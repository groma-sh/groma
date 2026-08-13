package adapters

import "testing"

const ciliumSameNamespaceOnly = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: payments-ingress, namespace: cde }
spec:
  endpointSelector:
    matchLabels: { app: payments-db }
  ingress:
    - fromEndpoints:
        - matchLabels: { app: web }
      toPorts:
        - ports:
            - { port: "5432", protocol: TCP }
`

const ciliumCrossNamespaceAllow = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: payments-ingress, namespace: cde }
spec:
  endpointSelector:
    matchLabels: { app: payments-db }
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: web
            io.kubernetes.pod.namespace: frontend
      toPorts:
        - ports:
            - { port: "5432", protocol: TCP }
`

const ciliumClusterwideDeny = `
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata: { name: quarantine-out-of-scope }
spec:
  endpointSelector:
    matchLabels: { app: payments-db }
  ingressDeny:
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace.labels.pci-scope: out
  ingress:
    - fromEndpoints: [{}]
`

const ciliumFQDNEgress = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: web-egress, namespace: frontend }
spec:
  endpointSelector:
    matchLabels: { app: web }
  egress:
    - toFQDNs:
        - matchName: api.example.com
`

func TestCilium_SameNamespaceSelectorDoesNotReachAcrossNamespaces(t *testing.T) {
	a := loadAdapter(t, LoadCilium, ciliumSameNamespaceOnly)
	// fromEndpoints in a namespaced CNP is confined to the policy's own
	// namespace, so a source in "frontend" is not the "app: web" it names.
	assertVerdict(t, a.Evaluate(flow(), Allow), Deny)
}

func TestCilium_CrossNamespaceAllow(t *testing.T) {
	a := loadAdapter(t, LoadCilium, ciliumCrossNamespaceAllow)
	assertVerdict(t, a.Evaluate(flow(), Deny), Allow)
}

func TestCilium_WrongPortFallsToDefaultDeny(t *testing.T) {
	a := loadAdapter(t, LoadCilium, ciliumCrossNamespaceAllow)
	f := flow()
	f.Port = 6379
	assertVerdict(t, a.Evaluate(f, Allow), Deny)
}

func TestCilium_IngressDenyBeatsAllow(t *testing.T) {
	a := loadAdapter(t, LoadCilium, ciliumClusterwideDeny)
	got := a.Evaluate(flow(), Allow)
	assertVerdict(t, got, Deny)
	if len(got.Policies) == 0 {
		t.Error("a deny verdict must cite the policy that produced it")
	}
}

func TestCilium_UnmodeledConstructIsUnknownNotDeny(t *testing.T) {
	a := loadAdapter(t, LoadCilium, ciliumFQDNEgress)
	got := a.Evaluate(flow(), Allow)
	assertVerdict(t, got, Unknown)
	if got.Reason == "" {
		t.Error("an Unknown verdict must explain which construct forced it")
	}
}

func TestCilium_NoPoliciesMeansNoOpinion(t *testing.T) {
	a := loadAdapter(t, LoadCilium)
	assertVerdict(t, a.Evaluate(flow(), Allow), NoOpinion)
}

func TestCilium_EgressOnlyRuleDoesNotRestrictIngress(t *testing.T) {
	// A rule carrying only egress must not turn the destination's ingress
	// default-deny; that is the trap a naive reader of the spec falls into.
	const egressOnly = `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: db-egress, namespace: cde }
spec:
  endpointSelector:
    matchLabels: { app: payments-db }
  egress:
    - toEndpoints:
        - matchLabels: { app: payments-db }
`
	a := loadAdapter(t, LoadCilium, egressOnly)
	assertVerdict(t, a.Evaluate(flow(), Allow), NoOpinion)
}

func TestCilium_UnreadableDenyRuleIsUnknownEvenWhenAnAllowMatches(t *testing.T) {
	// Nothing later in Cilium's evaluation can override a deny, so a deny rule
	// Groma cannot read poisons the verdict rather than losing to an allow.
	const mixed = `
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata: { name: mixed }
spec:
  endpointSelector:
    matchLabels: { app: payments-db }
  ingressDeny:
    - fromCIDR: ["10.0.0.0/8"]
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: web
            io.kubernetes.pod.namespace: frontend
`
	a := loadAdapter(t, LoadCilium, mixed)
	got := a.Evaluate(flow(), Allow)
	assertVerdict(t, got, Unknown)
}
