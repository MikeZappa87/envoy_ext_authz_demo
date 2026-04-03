#!/usr/bin/env bash
# k8s/spire/register-entries.sh
#
# Registers SPIFFE identities in the SPIRE server for:
#   1. Envoy proxy     — spiffe://poc/envoy
#   2. Go client        — spiffe://poc/go-client
#   3. Policy engine    — spiffe://poc/policyengine
#
# Prerequisites: SPIRE server must be running.
# Usage: ./k8s/spire/register-entries.sh

set -euo pipefail

SPIRE_SERVER_POD=$(kubectl get pod -n spire-system -l app=spire-server -o jsonpath='{.items[0].metadata.name}')

echo "==> Using SPIRE server pod: $SPIRE_SERVER_POD"

# Dynamically resolve the agent's SPIFFE ID (includes node UUID for k8s_psat)
AGENT_ID=$(kubectl exec -n spire-system "$SPIRE_SERVER_POD" -- \
  /opt/spire/bin/spire-server agent list -output json 2>/dev/null \
  | grep -oP '"id":\s*\{"trust_domain":"poc","path":"[^"]*"' \
  | head -1 \
  | grep -oP '"path":"/[^"]*"' \
  | tr -d '"' \
  | sed 's/^path://')

if [[ -z "$AGENT_ID" ]]; then
  # Fallback: parse from text output
  AGENT_ID=$(kubectl exec -n spire-system "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server agent list 2>/dev/null \
    | grep 'SPIFFE ID' \
    | head -1 \
    | awk '{print $NF}')
fi

if [[ -z "$AGENT_ID" ]]; then
  echo "ERROR: No attested SPIRE agent found. Is the agent running?"
  exit 1
fi

echo "==> Using agent SPIFFE ID: $AGENT_ID"

register() {
  local spiffe_id=$1
  local namespace=$2
  local sa=$3
  shift 3
  local dns_args=(-dns "$sa.$namespace.svc.cluster.local")
  for extra_dns in "$@"; do
    dns_args+=(-dns "$extra_dns")
  done
  echo "  Registering $spiffe_id (ns=$namespace, sa=$sa, dns=${dns_args[*]})"
  kubectl exec -n spire-system "$SPIRE_SERVER_POD" -- \
    /opt/spire/bin/spire-server entry create \
    -spiffeID "$spiffe_id" \
    -parentID "$AGENT_ID" \
    -selector "k8s:ns:$namespace" \
    -selector "k8s:sa:$sa" \
    "${dns_args[@]}" \
    2>&1 || true
}

echo "==> Registering SPIFFE entries..."
register "spiffe://poc/envoy"         "poc" "default" "localhost"
register "spiffe://poc/policyengine"  "poc" "policyengine"
register "spiffe://poc/upstream"      "poc" "default"

echo ""
echo "==> Listing registered entries:"
kubectl exec -n spire-system "$SPIRE_SERVER_POD" -- \
  /opt/spire/bin/spire-server entry show

echo ""
echo "==> Done."
