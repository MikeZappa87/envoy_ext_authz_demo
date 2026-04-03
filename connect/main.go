// connect/main.go
//
// HTTP/2 CONNECT tunnel client. Establishes an mTLS connection to Envoy's
// CONNECT listener, sends CONNECT with the target in :authority, then
// tunnels a plain HTTP request over the established stream.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"golang.org/x/net/http2"
)

func main() {
	proxyAddr := flag.String("proxy", "localhost:8444", "Envoy CONNECT proxy address")
	target := flag.String("target", "upstream.poc.svc.cluster.local:8080", "Original destination (CONNECT authority)")
	reqPath := flag.String("path", "/hello", "HTTP path to request through the tunnel")
	certFile := flag.String("cert", "certs/client.crt", "Client cert")
	keyFile := flag.String("key", "certs/client.key", "Client key")
	caFile := flag.String("ca", "certs/ca.crt", "CA cert")
	flag.Parse()

	// Load mTLS credentials.
	clientCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load client cert/key: %v", err)
	}

	// Extract SPIFFE ID and subject from the client cert for tunnel headers.
	var spiffeID, subject string
	if len(clientCert.Certificate) > 0 {
		parsed, err := x509.ParseCertificate(clientCert.Certificate[0])
		if err == nil {
			subject = parsed.Subject.String()
			for _, uri := range parsed.URIs {
				if uri.Scheme == "spiffe" {
					spiffeID = uri.String()
					break
				}
			}
		}
	}
	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("read CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatal("failed to parse CA cert")
	}

	// Use the hostname from the proxy address for TLS verification.
	proxyHost, _, _ := net.SplitHostPort(*proxyAddr)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   proxyHost,
		NextProtos:   []string{"h2"},
	}

	// Dial TLS to Envoy's CONNECT listener.
	rawConn, err := tls.Dial("tcp", *proxyAddr, tlsCfg)
	if err != nil {
		log.Fatalf("tls dial %s: %v", *proxyAddr, err)
	}
	defer rawConn.Close()

	// Wrap in an HTTP/2 client transport.
	h2Transport := &http2.Transport{
		DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
			return rawConn, nil
		},
	}

	// For HTTP/2 CONNECT, the request body is the write side of the tunnel
	// and the response body is the read side.
	pr, pw := io.Pipe()

	connectReq, err := http.NewRequest(http.MethodConnect, "https://"+*proxyAddr, pr)
	if err != nil {
		log.Fatalf("new request: %v", err)
	}
	connectReq.Host = *target // Sets :authority to the original destination.

	log.Printf("CONNECT %s via %s", *target, *proxyAddr)

	// RoundTrip sends the CONNECT and returns once the 200 is received.
	// After that, pr/pw is the write side and resp.Body is the read side.
	resp, err := h2Transport.RoundTrip(connectReq)
	if err != nil {
		log.Fatalf("CONNECT request failed: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		log.Fatalf("CONNECT returned %d: %s", resp.StatusCode, body)
	}

	log.Printf("CONNECT tunnel established (status %d)", resp.StatusCode)

	// Send a plain HTTP/1.1 request through the tunnel's write side.
	tunnelReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nx-spiffe-id: %s\r\nx-cert-subject: %s\r\nConnection: close\r\n\r\n",
		*reqPath, *target, spiffeID, subject)
	go func() {
		_, _ = fmt.Fprint(pw, tunnelReq)
		// Don't close pw yet — that would send END_STREAM.
		// The upstream will close after responding because of Connection: close.
	}()

	// Read the HTTP response from the tunnel's read side.
	tunnelResp, err := http.ReadResponse(bufio.NewReader(resp.Body), nil)
	if err != nil {
		log.Fatalf("read tunnel response: %v", err)
	}
	defer tunnelResp.Body.Close()

	body, err := io.ReadAll(tunnelResp.Body)
	if err != nil {
		log.Fatalf("read body: %v", err)
	}

	fmt.Printf("Tunnel response: %s\n", tunnelResp.Status)
	fmt.Printf("Body:\n%s\n", body)

	pw.Close()
}
