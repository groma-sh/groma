#!/usr/bin/env bash
# Two-act demo. Act 1 uses kind's default CNI (kindnet), which accepts
# NetworkPolicy objects but does not enforce them, so Groma catches the
# enforcement gap. Install an enforcing CNI (Calico/Cilium) to see the
# same intent pass. Run from the repo root: examples/demo/run.sh
set -euo pipefail

CLUSTER=groma-demo
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

kind create cluster --name "$CLUSTER"
trap 'kind delete cluster --name "$CLUSTER"' EXIT

kubectl config use-context "kind-$CLUSTER"
kubectl apply -f "$ROOT/examples/demo/namespaces.yaml"
kubectl apply -f "$ROOT/examples/demo/policy.yaml"

echo
echo ">>> The cde-isolation NetworkPolicy is applied. kubectl accepted it, and a"
echo ">>> static analyzer confirms the config DENIES frontend -> cde. --mode both"
echo ">>> runs that static analysis AND probes reality, then reconciles the two:"
echo

set +e
go run "$ROOT/cmd/groma" --intent "$ROOT/examples/intent.yaml" --mode both
code=$?
set -e

echo
echo ">>> groma exit code: $code (non-zero means the reconciliation found a gap:"
echo ">>> config DENIED but runtime REACHABLE = ENFORCEMENT-GAP)"
