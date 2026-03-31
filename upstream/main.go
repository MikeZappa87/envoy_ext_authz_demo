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

	log.Printf("upstream: SPIFFE ID=%q subject=%q", spiffeID, subject)

	fmt.Fprintf(w, "Request authorized!\nSPIFFE ID:    %s\nCert Subject: %s\n",
		spiffeID, subject)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("upstream listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
