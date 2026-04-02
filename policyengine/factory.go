// policyengine/factory.go
//
// Converts a Policy CRD spec (unstructured) into a concrete Policy
// implementation. Used by the CRD controller on reconcile.
package main

import "fmt"

// policyFromSpec parses spec fields from an unstructured Policy CR and
// returns the concrete Policy, the ordering value, and any error.
func policyFromSpec(name string, spec map[string]interface{}) (Policy, int, error) {
	pType, _ := spec["type"].(string)

	// Kubernetes unstructured stores integers as int64, but JSON
	// round-tripped through encoding/json produces float64.
	var order int
	switch v := spec["order"].(type) {
	case int64:
		order = int(v)
	case float64:
		order = int(v)
	}

	config, _ := spec["config"].(map[string]interface{})

	switch pType {
	case "spiffe":
		return spiffeFromConfig(config), order, nil
	case "path-acl":
		return pathACLFromConfig(config), order, nil
	case "header-validate":
		return headerFromConfig(config), order, nil
	case "body-inspect":
		return bodyInspectFromConfig(config), order, nil
	case "header-inject":
		return headerInjectFromConfig(config), order, nil
	case "opa":
		p := opaFromConfig(config)
		p.PolicyID = name
		return p, order, nil
	default:
		return nil, 0, fmt.Errorf("unknown policy type: %q", pType)
	}
}

func spiffeFromConfig(cfg map[string]interface{}) *SPIFFEPolicy {
	ids := make(map[string]bool)
	if v, ok := cfg["allowedIDs"].([]interface{}); ok {
		for _, id := range v {
			if s, ok := id.(string); ok {
				ids[s] = true
			}
		}
	}
	return &SPIFFEPolicy{AllowedIDs: ids}
}

func pathACLFromConfig(cfg map[string]interface{}) *PathACLPolicy {
	acl := make(map[string][]PathRule)
	if aclMap, ok := cfg["acl"].(map[string]interface{}); ok {
		for identity, rulesRaw := range aclMap {
			if rules, ok := rulesRaw.([]interface{}); ok {
				for _, ruleRaw := range rules {
					if rule, ok := ruleRaw.(map[string]interface{}); ok {
						pr := PathRule{}
						if methods, ok := rule["methods"].([]interface{}); ok {
							for _, m := range methods {
								if s, ok := m.(string); ok {
									pr.Methods = append(pr.Methods, s)
								}
							}
						}
						if prefix, ok := rule["pathPrefix"].(string); ok {
							pr.PathPrefix = prefix
						}
						acl[identity] = append(acl[identity], pr)
					}
				}
			}
		}
	}
	return &PathACLPolicy{ACL: acl}
}

func headerFromConfig(cfg map[string]interface{}) *HeaderPolicy {
	p := &HeaderPolicy{}
	if v, ok := cfg["requiredHeaders"].([]interface{}); ok {
		for _, h := range v {
			if s, ok := h.(string); ok {
				p.RequiredHeaders = append(p.RequiredHeaders, s)
			}
		}
	}
	if v, ok := cfg["forbiddenHeaders"].([]interface{}); ok {
		for _, h := range v {
			if s, ok := h.(string); ok {
				p.ForbiddenHeaders = append(p.ForbiddenHeaders, s)
			}
		}
	}
	return p
}

func bodyInspectFromConfig(cfg map[string]interface{}) *BodyInspectPolicy {
	actions := make(map[string]bool)
	if v, ok := cfg["blockedActions"].([]interface{}); ok {
		for _, a := range v {
			if s, ok := a.(string); ok {
				actions[s] = true
			}
		}
	}
	return &BodyInspectPolicy{BlockedActions: actions}
}

func opaFromConfig(cfg map[string]interface{}) *OPAPolicy {
	p := &OPAPolicy{}
	if url, ok := cfg["url"].(string); ok {
		p.URL = url
	}
	if rego, ok := cfg["rego"].(string); ok {
		p.Rego = rego
	}
	if phases, ok := cfg["phases"].([]interface{}); ok {
		for _, ph := range phases {
			if s, ok := ph.(string); ok {
				switch s {
				case "authz":
					p.RegisteredPhases = append(p.RegisteredPhases, PhaseAuthz)
				case "request_headers":
					p.RegisteredPhases = append(p.RegisteredPhases, PhaseRequestHeaders)
				case "request_body":
					p.RegisteredPhases = append(p.RegisteredPhases, PhaseRequestBody)
				case "response_headers":
					p.RegisteredPhases = append(p.RegisteredPhases, PhaseResponseHeaders)
				case "mitm_url":
					p.RegisteredPhases = append(p.RegisteredPhases, PhaseMITMURL)
				}
			}
		}
	}
	return p
}

func headerInjectFromConfig(cfg map[string]interface{}) *HeaderInjectPolicy {
	set := make(map[string]string)
	if v, ok := cfg["set"].(map[string]interface{}); ok {
		for k, val := range v {
			if s, ok := val.(string); ok {
				set[k] = s
			}
		}
	}
	return &HeaderInjectPolicy{Set: set}
}
