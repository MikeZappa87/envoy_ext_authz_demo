// ext_authz/main.go
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
)

// allowedSPIFFEIDs is the built-in authz policy (used when OPA is disabled).
var allowedSPIFFEIDs = map[string]bool{
	"spiffe://poc/go-client": true,
}

// allowedPathPrefixes restricts which paths the built-in policy permits.
var allowedPathPrefixes = []string{"/hello"}

// opaURL is set via -opa flag; when non-empty, policy decisions are delegated to OPA.
var opaURL string

type server struct {
	auth.UnimplementedAuthorizationServer
}

func (s *server) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	attrs := req.GetAttributes()

	// ---- 1. Log the full request for debugging -------------------------
	httpReq := attrs.GetRequest().GetHttp()
	log.Printf("ext_authz: method=%s path=%s host=%s",
		httpReq.GetMethod(), httpReq.GetPath(), httpReq.GetHost())

	// ---- 2. Extract the URL-encoded PEM cert --------------------------
	// Populated by Envoy when include_peer_certificate: true is set.
	// This is the full X.509 certificate of the downstream client.
	rawCert := attrs.GetSource().GetCertificate()
	if rawCert == "" {
		log.Println("ext_authz: no peer certificate — rejecting")
		return deny(403, "mTLS required: no client certificate presented"), nil
	}

	// ---- 3. Decode + parse the certificate ----------------------------
	spiffeIDs, subject, err := parseCert(rawCert)
	if err != nil {
		log.Printf("ext_authz: cert parse error: %v", err)
		return deny(403, "invalid client certificate"), nil
	}

	log.Printf("ext_authz: subject=%q spiffe_ids=%v", subject, spiffeIDs)

	if len(spiffeIDs) == 0 {
		return deny(403, "client certificate has no SPIFFE URI SAN"), nil
	}

	spiffeID := spiffeIDs[0] // primary identity

	// ---- 4. Authz check -----------------------------------------------
	method := httpReq.GetMethod()
	path := httpReq.GetPath()

	var allowed bool
	var reason string

	if opaURL != "" {
		// Delegate decision to OPA
		allowed, reason, err = queryOPA(spiffeID, method, path)
		if err != nil {
			log.Printf("ext_authz: OPA query error: %v", err)
			return deny(500, "policy engine unavailable"), nil
		}
	} else {
		// Built-in allowlist
		if !allowedSPIFFEIDs[spiffeID] {
			allowed = false
			reason = fmt.Sprintf("SPIFFE ID %q is not in the allowlist", spiffeID)
		} else if !matchesPathPrefix(path) {
			allowed = false
			reason = fmt.Sprintf("path %q is not allowed", path)
		} else {
			allowed = true
			reason = "allowed by built-in allowlist"
		}
	}

	if !allowed {
		log.Printf("ext_authz: DENIED spiffe_id=%q reason=%s", spiffeID, reason)
		return deny(403, reason), nil
	}

	log.Printf("ext_authz: ALLOWED spiffe_id=%q reason=%s", spiffeID, reason)
	return allow(spiffeID, subject), nil
}

// parseCert URL-decodes then parses the PEM cert Envoy sends.
// Returns all URI SANs (SPIFFE IDs) and the cert subject.
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

func matchesPathPrefix(path string) bool {
	for _, prefix := range allowedPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func allow(spiffeID, subject string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &auth.CheckResponse_OkResponse{
			OkResponse: &auth.OkHttpResponse{
				// Inject headers — upstream app can read these directly.
				// Envoy will forward them to the upstream cluster.
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "x-spiffe-id",
							Value: spiffeID,
						},
						KeepEmptyValue: false,
					},
					{
						Header: &core.HeaderValue{
							Key:   "x-cert-subject",
							Value: subject,
						},
					},
				},
			},
		},
	}
}

func deny(httpCode int32, message string) *auth.CheckResponse {
	return &auth.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &typev3.HttpStatus{
					Code: typev3.StatusCode(httpCode),
				},
				Body: message,
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "content-type",
							Value: "text/plain",
						},
					},
				},
			},
		},
	}
}

func main() {
	flag.StringVar(&opaURL, "opa", "", "OPA policy URL (e.g. http://localhost:8181/v1/data/envoy/authz). If empty, uses built-in allowlist.")
	flag.Parse()

	if opaURL != "" {
		log.Printf("ext_authz: using OPA at %s", opaURL)
	} else {
		log.Println("ext_authz: using built-in SPIFFE ID allowlist")
	}

	lis, err := net.Listen("tcp", ":9191")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	auth.RegisterAuthorizationServer(grpcServer, &server{})
	reflection.Register(grpcServer)

	fmt.Println("ext_authz listening on :9191")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// --- OPA integration -------------------------------------------------------

// opaInput is the JSON body sent to OPA's Data API.
type opaInput struct {
	Input opaInputData `json:"input"`
}

type opaInputData struct {
	SpiffeID string `json:"spiffe_id"`
	Method   string `json:"method"`
	Path     string `json:"path"`
}

// opaResponse is the JSON response from OPA's Data API.
type opaResponse struct {
	Result struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	} `json:"result"`
}

var opaClient = &http.Client{Timeout: 2 * time.Second}

// queryOPA sends an authorization query to OPA and returns the decision.
func queryOPA(spiffeID, method, path string) (allowed bool, reason string, err error) {
	body, err := json.Marshal(opaInput{
		Input: opaInputData{
			SpiffeID: spiffeID,
			Method:   method,
			Path:     path,
		},
	})
	if err != nil {
		return false, "", fmt.Errorf("marshal OPA input: %w", err)
	}

	resp, err := opaClient.Post(opaURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("OPA request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("read OPA response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("OPA returned %d: %s", resp.StatusCode, respBody)
	}

	var opaResp opaResponse
	if err := json.Unmarshal(respBody, &opaResp); err != nil {
		return false, "", fmt.Errorf("unmarshal OPA response: %w", err)
	}

	return opaResp.Result.Allow, opaResp.Result.Reason, nil
}
