// upstream/main.go
package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	spiffeID := r.Header.Get("x-spiffe-id")
	subject := r.Header.Get("x-cert-subject")
	agent := r.Header.Get("agent")

	log.Printf("upstream: SPIFFE ID=%q subject=%q agent=%q", spiffeID, subject, agent)

	fmt.Fprintf(w, "Request authorized!\nSPIFFE ID:    %s\nCert Subject: %s\nAgent:        %s\n",
		spiffeID, subject, agent)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("upstream listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
