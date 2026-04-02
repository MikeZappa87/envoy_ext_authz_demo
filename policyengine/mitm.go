// policyengine/mitm.go
//
// TLS-intercepting and plaintext-inspecting proxy that runs alongside
// ext_authz and ext_proc inside the policyengine binary.
//
// Envoy tunnels CONNECT traffic here. The proxy peeks at the first byte
// to auto-detect TLS vs plaintext HTTP:
//
//   - TLS (0x16): terminates TLS with a dynamically-generated cert signed
//     by the proxy CA, reads the decrypted HTTP request, runs policies,
//     and forwards to the real origin over TLS.
//
//   - Plaintext: reads the HTTP request directly, runs policies, and
//     forwards to the real origin over plain HTTP.
//
// Both paths run PhaseMITMURL through the engine before forwarding.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// mitmProxy performs TLS interception with on-the-fly cert generation
// and delegates policy decisions to the engine.
type mitmProxy struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	engine     *Engine
	certCache  sync.Map // domain → *tls.Certificate
	httpClient *http.Client
}

func newMITMProxy(caCertFile, caKeyFile string, engine *Engine) (*mitmProxy, error) {
	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in CA cert")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM block in CA key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse CA key: PKCS1: %w, PKCS8: %w", err, err2)
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA key is not RSA")
		}
	}

	return &mitmProxy{
		caCert: caCert,
		caKey:  caKey,
		engine: engine,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}, nil
}

// certForDomain generates (or returns cached) a TLS certificate for the
// given domain, signed by the proxy CA.
func (p *mitmProxy) certForDomain(domain string) (*tls.Certificate, error) {
	if cached, ok := p.certCache.Load(domain); ok {
		return cached.(*tls.Certificate), nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	p.certCache.Store(domain, cert)
	return cert, nil
}

// listenAndServe starts the MITM TCP listener.
func (p *mitmProxy) listenAndServe(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("MITM proxy listening on %s", addr)
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Printf("mitm: accept: %v", err)
			continue
		}
		go p.handleConn(conn)
	}
}

// peekedConn wraps a net.Conn and prepends already-read bytes.
type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// handleConn auto-detects TLS vs plaintext and dispatches accordingly.
func (p *mitmProxy) handleConn(conn net.Conn) {
	defer conn.Close()

	// Peek at the first byte to determine protocol.
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Printf("mitm: peek failed: %v", err)
		return
	}

	// Re-combine the peeked byte with the rest of the connection.
	pConn := &peekedConn{Conn: conn, r: io.MultiReader(bytes.NewReader(buf), conn)}

	if buf[0] == 0x16 {
		// TLS ClientHello — do full MITM interception.
		p.handleTLS(pConn)
	} else {
		// Plaintext HTTP — inspect and forward directly.
		p.handlePlaintext(pConn)
	}
}

// handleTLS performs TLS interception: generate cert, decrypt, inspect, re-encrypt to origin.
func (p *mitmProxy) handleTLS(conn net.Conn) {
	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				return nil, fmt.Errorf("no SNI in ClientHello")
			}
			log.Printf("mitm: TLS handshake for %s", hello.ServerName)
			return p.certForDomain(hello.ServerName)
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("mitm: TLS handshake failed: %v", err)
		return
	}
	defer tlsConn.Close()

	domain := tlsConn.ConnectionState().ServerName

	br := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("mitm: read request from %s: %v", domain, err)
		return
	}

	bodyBytes := readBody(req)

	log.Printf("mitm: %s https://%s%s", req.Method, domain, req.URL.Path)

	result, headers := p.runPolicy(domain, req, bodyBytes)
	if result.Action == ActionDeny {
		log.Printf("mitm: DENIED %s https://%s%s — %s", req.Method, domain, req.URL.Path, result.Message)
		mitmWriteResponse(tlsConn, result.StatusCode, result.Message)
		return
	}
	log.Printf("mitm: ALLOWED %s https://%s%s — %s", req.Method, domain, req.URL.Path, result.Message)

	// Forward to the real origin with TLS.
	prepareForward(req, "https", domain, bodyBytes, headers)

	originResp, err := p.httpClient.Do(req)
	if err != nil {
		log.Printf("mitm: origin request failed: %v", err)
		mitmWriteResponse(tlsConn, 502, fmt.Sprintf("origin error: %v", err))
		return
	}
	defer originResp.Body.Close()

	originResp.Header.Set("X-MITM-Proxy", "inspected")
	if err := originResp.Write(tlsConn); err != nil {
		log.Printf("mitm: write response: %v", err)
	}
}

// handlePlaintext reads a plaintext HTTP request from the tunnel,
// runs policies, and forwards to the origin over plain HTTP.
func (p *mitmProxy) handlePlaintext(conn net.Conn) {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("mitm: read plaintext request: %v", err)
		return
	}

	// Derive the domain from the Host header.
	domain := req.Host
	if host, _, err := net.SplitHostPort(domain); err == nil {
		_ = host // domain with port is fine, keep domain as-is for forwarding
	}

	bodyBytes := readBody(req)

	log.Printf("mitm: %s http://%s%s (plaintext tunnel)", req.Method, domain, req.URL.Path)

	result, headers := p.runPolicy(hostOnly(domain), req, bodyBytes)
	if result.Action == ActionDeny {
		log.Printf("mitm: DENIED %s http://%s%s — %s", req.Method, domain, req.URL.Path, result.Message)
		mitmWriteResponse(conn, result.StatusCode, result.Message)
		return
	}
	log.Printf("mitm: ALLOWED %s http://%s%s — %s", req.Method, domain, req.URL.Path, result.Message)

	// Forward to the real origin over plaintext HTTP.
	prepareForward(req, "http", domain, bodyBytes, headers)

	originResp, err := p.plaintextClient().Do(req)
	if err != nil {
		log.Printf("mitm: origin request failed: %v", err)
		mitmWriteResponse(conn, 502, fmt.Sprintf("origin error: %v", err))
		return
	}
	defer originResp.Body.Close()

	originResp.Header.Set("X-MITM-Proxy", "inspected")
	if err := originResp.Write(conn); err != nil {
		log.Printf("mitm: write response: %v", err)
	}
}

func (p *mitmProxy) plaintextClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

// runPolicy builds a RequestContext and runs PhaseMITMURL through the engine.
func (p *mitmProxy) runPolicy(domain string, req *http.Request, body []byte) (*PolicyResult, map[string]string) {
	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}

	ctx := &RequestContext{
		Phase:      PhaseMITMURL,
		Method:     req.Method,
		Path:       req.URL.Path,
		Host:       domain,
		Headers:    headers,
		Body:       body,
		SetHeaders: make(map[string]string),
	}

	return p.engine.Run(ctx), ctx.SetHeaders
}

func readBody(req *http.Request) []byte {
	if req.Body == nil {
		return nil
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		log.Printf("mitm: read body: %v", err)
		return nil
	}
	req.Body.Close()
	return bodyBytes
}

func prepareForward(req *http.Request, scheme, host string, body []byte, extraHeaders map[string]string) {
	req.URL.Scheme = scheme
	req.URL.Host = host
	req.RequestURI = ""
	req.Host = host
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if len(body) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	} else {
		req.Body = nil
		req.ContentLength = 0
	}
}

// hostOnly strips the port from a host:port string.
func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // no port present
	}
	return h
}

func mitmWriteResponse(w io.Writer, status int, message string) {
	body := message + "\n"
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}, "X-MITM-Proxy": {"inspected"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Write(w)
}
