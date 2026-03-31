// client/main.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "https://localhost:8443", "Envoy address")
	certFile := flag.String("cert", "certs/client.crt", "Client cert (with SPIFFE SAN)")
	keyFile := flag.String("key", "certs/client.key", "Client key")
	caFile := flag.String("ca", "certs/ca.crt", "CA cert to verify Envoy's server cert")
	path := flag.String("path", "/hello", "Request path")
	flag.Parse()

	// Load client cert+key (this is the SVID in a real SPIRE setup)
	clientCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load client cert/key: %v", err)
	}

	// Load CA to verify Envoy's server cert
	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("read CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatal("failed to parse CA cert")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		// Must match the SAN on Envoy's server cert, not the CN.
		// Our server.crt has SAN=spiffe://poc/envoy so we override
		// ServerName to bypass hostname check since we're using SPIFFE SANs.
		// In production, use a proper SPIFFE TLS dialer from go-spiffe.
		InsecureSkipVerify: false,
		ServerName:         "envoy", // matches CN; for SPIFFE use go-spiffe's dialer
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	url := *addr + *path
	log.Printf("client: GET %s", url)

	resp, err := httpClient.Get(url)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("read body: %v", err)
	}

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Body:\n%s\n", body)

	// Print TLS state for debugging
	// Re-dial just to show what cert Envoy presented (optional)
	conn, err := tls.Dial("tcp", "localhost:8443", tlsCfg)
	if err != nil {
		log.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	fmt.Println("\n--- TLS Handshake Info ---")
	fmt.Printf("Version:       %x\n", state.Version)
	fmt.Printf("CipherSuite:   %x\n", state.CipherSuite)
	for i, cert := range state.PeerCertificates {
		fmt.Printf("Server cert[%d]: Subject=%s\n", i, cert.Subject)
		for _, uri := range cert.URIs {
			fmt.Printf("  SPIFFE SAN: %s\n", uri)
		}
	}
}
