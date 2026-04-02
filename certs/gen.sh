#!/bin/bash
set -e
mkdir -p certs && cd certs

# CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=poc-ca"

# Server cert for Envoy — spiffe://poc/envoy
cat > server-ext.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = URI:spiffe://poc/envoy,DNS:envoy,DNS:localhost
EOF

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=envoy" -config server-ext.cnf
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -extensions v3_req -extfile server-ext.cnf

# Client cert — spiffe://poc/go-client
cat > client-ext.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = URI:spiffe://poc/go-client
EOF

openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=go-client" -config client-ext.cnf
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -extensions v3_req -extfile client-ext.cnf

# Proxy CA — separate CA for MITM TLS interception
openssl genrsa -out proxy-ca.key 4096
openssl req -new -x509 -days 365 -key proxy-ca.key -out proxy-ca.crt \
  -subj "/CN=poc-proxy-ca/O=POC MITM Proxy"

echo "Certs ready:"
ls -la *.crt *.key