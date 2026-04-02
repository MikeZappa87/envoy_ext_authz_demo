// policyengine/main.go
//
// Unified policy engine that serves ext_authz, ext_proc, and the MITM
// TLS-interception proxy on a single binary.
//
// Two modes:
//
//	--crd              Watch Policy CRDs and build the chain dynamically.
//	(default)          Use the hardcoded chain below (for local dev).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_proc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	crdMode := flag.Bool("crd", false, "watch Policy CRDs to build the chain dynamically")
	namespace := flag.String("namespace", "", "namespace to watch for Policy CRs (default: POD_NAMESPACE env or 'poc')")
	mitmCACert := flag.String("mitm-ca-cert", "", "proxy CA certificate for MITM interception")
	mitmCAKey := flag.String("mitm-ca-key", "", "proxy CA private key for MITM interception")
	mitmAddr := flag.String("mitm-addr", ":9192", "MITM proxy listen address")
	flag.Parse()

	// Resolve namespace: flag > env > default.
	ns := *namespace
	if ns == "" {
		ns = os.Getenv("POD_NAMESPACE")
	}
	if ns == "" {
		ns = "poc"
	}

	engine := NewEngine()

	if *crdMode {
		ctrl, err := NewController(engine, ns)
		if err != nil {
			log.Fatalf("controller init: %v", err)
		}
		go ctrl.Run(context.Background())
		log.Printf("CRD mode — watching Policy CRs in namespace %q", ns)
	} else {
		// Fallback: hardcoded chain for local development.
		engine.SetPolicies([]Policy{
			&SPIFFEPolicy{
				AllowedIDs: map[string]bool{
					"spiffe://poc/go-client": true,
				},
			},
			&OPAPolicy{
				URL: "http://opa.poc.svc.cluster.local:8181/v1/data/envoy/authz",
				RegisteredPhases: []Phase{
					PhaseAuthz,
					PhaseRequestHeaders,
					PhaseRequestBody,
				},
			},
		})
	}

	// ---- Optionally start the MITM proxy --------------------------------
	if *mitmCACert != "" && *mitmCAKey != "" {
		proxy, err := newMITMProxy(*mitmCACert, *mitmCAKey, engine)
		if err != nil {
			log.Fatalf("mitm init: %v", err)
		}
		go func() {
			if err := proxy.listenAndServe(*mitmAddr); err != nil {
				log.Fatalf("mitm listen: %v", err)
			}
		}()
	}

	// ---- Start gRPC server with both services -------------------------
	lis, err := net.Listen("tcp", ":9191")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer()

	// Both ext_authz and ext_proc on the same port.
	auth.RegisterAuthorizationServer(grpcServer, &authzServer{engine: engine})
	ext_proc.RegisterExternalProcessorServer(grpcServer, &extProcServer{engine: engine})

	reflection.Register(grpcServer)

	fmt.Println("policyengine listening on :9191 (ext_authz + ext_proc + mitm)")
	policies := engine.Policies()
	log.Printf("policy chain: %d policies registered", len(policies))
	for i, p := range policies {
		log.Printf("  [%d] %s  phases=%v", i, p.Name(), p.Phases())
	}

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
