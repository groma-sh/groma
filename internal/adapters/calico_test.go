package adapters

import "testing"

const calicoGlobalDeny = `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: { name: default.isolate-cde }
spec:
  order: 100
  selector: "app == 'payments-db'"
  namespaceSelector: "pci-scope == 'cde'"
  types: [Ingress]
  ingress:
    - action: Deny
      protocol: TCP
      source:
        namespaceSelector: "pci-scope == 'out'"
      destination:
        ports: [5432]
`

const calicoGlobalAllow = `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: { name: allow-frontend }
spec:
  order: 10
  selector: "app == 'payments-db'"
  types: [Ingress]
  ingress:
    - action: Allow
      protocol: 6
      source:
        selector: "app in {'web','worker'}"
        namespaceSelector: "projectcalico.org/name == 'frontend'"
      destination:
        ports: ["5000:6000"]
`

const calicoNonDefaultTier = `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: { name: security.lockdown }
spec:
  tier: security
  order: 1
  selector: "app == 'payments-db'"
  types: [Ingress]
  ingress:
    - action: Deny
      source: {}
`

const calicoPassAction = `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: { name: delegate }
spec:
  order: 1
  selector: "app == 'payments-db'"
  types: [Ingress]
  ingress:
    - action: Pass
      source: {}
`

func TestCalico_DenyBySelectorAndPort(t *testing.T) {
	a := loadAdapter(t, LoadCalico, calicoGlobalDeny)
	got := a.Evaluate(flow(), Allow)
	assertVerdict(t, got, Deny)
	if len(got.Policies) == 0 {
		t.Error("a deny verdict must cite the policy that produced it")
	}
}

func TestCalico_DenyRuleMissesOnAnotherPort(t *testing.T) {
	a := loadAdapter(t, LoadCalico, calicoGlobalDeny)
	f := flow()
	f.Port = 6379
	// The policy still applies, but no rule matched, so Calico continues into
	// the converted upstream NetworkPolicy set and the adapter abstains.
	assertVerdict(t, a.Evaluate(f, Allow), NoOpinion)
}

func TestCalico_AllowAcrossNamespacesWithNumericProtocolAndPortRange(t *testing.T) {
	a := loadAdapter(t, LoadCalico, calicoGlobalAllow)
	assertVerdict(t, a.Evaluate(flow(), Deny), Allow)
}

func TestCalico_LowerOrderWins(t *testing.T) {
	// The allow is order 10 and the deny order 100, so the allow decides.
	a := loadAdapter(t, LoadCalico, calicoGlobalDeny, calicoGlobalAllow)
	assertVerdict(t, a.Evaluate(flow(), Deny), Allow)
}

func TestCalico_NonDefaultTierIsUnknown(t *testing.T) {
	a := loadAdapter(t, LoadCalico, calicoNonDefaultTier)
	got := a.Evaluate(flow(), Allow)
	assertVerdict(t, got, Unknown)
	if got.Reason == "" {
		t.Error("an Unknown verdict must explain itself")
	}
}

func TestCalico_PassActionIsUnknown(t *testing.T) {
	a := loadAdapter(t, LoadCalico, calicoPassAction)
	assertVerdict(t, a.Evaluate(flow(), Allow), Unknown)
}

func TestCalico_NamespacedPolicyStaysInItsNamespace(t *testing.T) {
	const other = `
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata: { name: deny-all, namespace: staging }
spec:
  selector: all()
  types: [Ingress]
  ingress:
    - action: Deny
      source: {}
`
	a := loadAdapter(t, LoadCalico, other)
	assertVerdict(t, a.Evaluate(flow(), Allow), NoOpinion)
}

func TestCalico_NetsForceUnknown(t *testing.T) {
	const cidr = `
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata: { name: cidr-deny }
spec:
  selector: "app == 'payments-db'"
  types: [Ingress]
  ingress:
    - action: Deny
      source:
        nets: ["10.0.0.0/8"]
`
	a := loadAdapter(t, LoadCalico, cidr)
	assertVerdict(t, a.Evaluate(flow(), Allow), Unknown)
}
