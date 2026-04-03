// policyengine/authz.go
//
// ext_authz gRPC handler. Extracts identity from the client cert and
// runs the AuthZ-phase policies through the engine.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

type authzServer struct {
	auth.UnimplementedAuthorizationServer
	engine *Engine
}

func (s *authzServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	attrs := req.GetAttributes()
	httpReq := attrs.GetRequest().GetHttp()

	log.Printf("authz: method=%s path=%s host=%s",
		httpReq.GetMethod(), httpReq.GetPath(), httpReq.GetHost())

	// Parse client certificate
	rawCert := attrs.GetSource().GetCertificate()
	if rawCert == "" {
		log.Println("authz: no peer certificate — rejecting")
		return authzDeny(403, "mTLS required: no client certificate"), nil
	}

	spiffeIDs, subject, err := parseCert(rawCert)
	if err != nil {
		log.Printf("authz: cert parse error: %v", err)
		return authzDeny(403, "invalid client certificate"), nil
	}

	if len(spiffeIDs) == 0 {
		return authzDeny(403, "no SPIFFE URI SAN in client certificate"), nil
	}

	// Build request context for the policy chain
	rctx := &RequestContext{
		SpiffeID:      spiffeIDs[0],
		Subject:       subject,
		Method:        httpReq.GetMethod(),
		Path:          httpReq.GetPath(),
		Headers:       httpReq.GetHeaders(),
		RequestID:     httpReq.GetHeaders()["x-request-id"],
		Phase:         PhaseAuthz,
		SetHeaders:    make(map[string]string),
		RemoveHeaders: nil,
	}

	// For CONNECT requests the destination is in :authority / host.
	if rctx.Method == "CONNECT" {
		rctx.ConnectAuthority = httpReq.GetHost()
	}

	result := s.engine.Run(rctx)

	if result.Action == ActionDeny {
		log.Printf("authz: DENIED — %s", result.Message)
		return authzDeny(int32(result.StatusCode), result.Message), nil
	}

	// Inject identity headers so ext_proc can see them downstream.
	rctx.SetHeaders["x-spiffe-id"] = rctx.SpiffeID
	rctx.SetHeaders["x-cert-subject"] = rctx.Subject

	log.Printf("authz: ALLOWED — %s", result.Message)
	return authzAllow(rctx), nil
}

// --- helpers ----------------------------------------------------------------

func authzAllow(rctx *RequestContext) *auth.CheckResponse {
	var headers []*core.HeaderValueOption
	for k, v := range rctx.SetHeaders {
		headers = append(headers, &core.HeaderValueOption{
			Header: &core.HeaderValue{Key: k, Value: v},
		})
	}

	return &auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				Headers: headers,
			},
		},
	}
}

func authzDeny(httpCode int32, message string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode(httpCode)},
				Body:   message,
				Headers: []*core.HeaderValueOption{
					{Header: &core.HeaderValue{Key: "content-type", Value: "text/plain"}},
				},
			},
		},
	}
}

func parseCert(rawCert string) (spiffeIDs []string, subject string, err error) {
	decoded, err := url.QueryUnescape(rawCert)
	if err != nil {
		return nil, "", fmt.Errorf("url decode: %w", err)
	}

	block, _ := pem.Decode([]byte(decoded))
	if block == nil {
		return nil, "", fmt.Errorf("no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("x509 parse: %w", err)
	}

	for _, uri := range cert.URIs {
		spiffeIDs = append(spiffeIDs, uri.String())
	}

	return spiffeIDs, cert.Subject.String(), nil
}
