// policyengine/controller.go
//
// CRD controller — watches Policy custom resources and rebuilds the
// engine's policy chain whenever CRs are added, updated, or deleted.
// Uses client-go dynamic informers (no code-gen required).
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var controllerHTTP = &http.Client{Timeout: 5 * time.Second}

var policyGVR = schema.GroupVersionResource{
	Group:    "policy.poc.io",
	Version:  "v1alpha1",
	Resource: "policies",
}

// Controller watches Policy CRs and hot-reloads the engine chain.
type Controller struct {
	engine    *Engine
	namespace string
	client    dynamic.Interface
}

// NewController creates a controller that uses in-cluster credentials.
func NewController(engine *Engine, namespace string) (*Controller, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	dc, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return &Controller{engine: engine, namespace: namespace, client: dc}, nil
}

// Run starts the informer and blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) {
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		c.client, 0, c.namespace, nil,
	)

	informer := factory.ForResource(policyGVR).Informer()
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ interface{}) { c.reconcile() },
		UpdateFunc: func(_, _ interface{}) { c.reconcile() },
		DeleteFunc: func(_ interface{}) { c.reconcile() },
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	log.Printf("controller: watching Policy CRs in namespace %q", c.namespace)

	// Do an initial reconcile to pick up any existing CRs.
	c.reconcile()

	<-ctx.Done()
}

// reconcile lists all Policy CRs, sorts by order, converts to concrete
// Policy instances, and swaps them into the engine atomically.
func (c *Controller) reconcile() {
	list, err := c.client.Resource(policyGVR).Namespace(c.namespace).List(
		context.Background(), metav1.ListOptions{},
	)
	if err != nil {
		log.Printf("controller: list policies: %v", err)
		return
	}

	type ordered struct {
		order  int
		policy Policy
	}

	var policies []ordered
	for _, item := range list.Items {
		spec, ok := item.Object["spec"].(map[string]interface{})
		if !ok {
			log.Printf("controller: %s has no spec — skipping", item.GetName())
			continue
		}

		p, order, err := policyFromSpec(item.GetName(), spec)
		if err != nil {
			log.Printf("controller: %s: %v — skipping", item.GetName(), err)
			continue
		}

		policies = append(policies, ordered{order: order, policy: p})
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].order < policies[j].order
	})

	chain := make([]Policy, len(policies))
	for i, p := range policies {
		chain[i] = p.policy
	}

	// Push inline Rego to OPA for any OPA policies that carry it.
	for _, p := range chain {
		opa, ok := p.(*OPAPolicy)
		if !ok || opa.Rego == "" {
			continue
		}
		if err := pushRegoToOPA(opa); err != nil {
			log.Printf("controller: failed to push rego for %s: %v", opa.PolicyID, err)
		} else {
			log.Printf("controller: pushed rego to OPA for policy %q", opa.PolicyID)
		}
	}

	c.engine.SetPolicies(chain)

	log.Printf("controller: rebuilt chain — %d policies", len(chain))
	for i, p := range chain {
		log.Printf("  [%d] %s  phases=%v", i, p.Name(), p.Phases())
	}
}

// pushRegoToOPA uploads inline Rego source to OPA's Policy API.
// PUT /v1/policies/<id>
func pushRegoToOPA(opa *OPAPolicy) error {
	// Derive the OPA server base from the Data API URL.
	// e.g. http://opa:8181/v1/data/envoy/authz → http://opa:8181
	u, err := url.Parse(opa.URL)
	if err != nil {
		return fmt.Errorf("parse OPA URL: %w", err)
	}
	base := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	policyURL := fmt.Sprintf("%s/v1/policies/%s", base, opa.PolicyID)

	req, err := http.NewRequest(http.MethodPut, policyURL, strings.NewReader(opa.Rego))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := controllerHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", policyURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("OPA returned %d: %s", resp.StatusCode, body)
	}
	return nil
}
