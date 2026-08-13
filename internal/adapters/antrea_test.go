package adapters

import "testing"

const antreaClusterDrop = `
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata: { name: isolate-cde }
spec:
  tier: securityops
  priority: 5
  appliedTo:
    - namespaceSelector: { matchLabels: { pci-scope: cde } }
      podSelector: { matchLabels: { app: payments-db } }
  ingress:
    - action: Drop
      from:
        - namespaceSelector: { matchLabels: { pci-scope: out } }
      ports:
        - { protocol: TCP, port: 5432 }
`

const antreaClusterAllowHigherTier = `
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata: { name: break-glass }
spec:
  tier: emergency
  priority: 1
  appliedTo:
    - podSelector: { matchLabels: { app: payments-db } }
  ingress:
    - action: Allow
      from:
        - podSelector: { matchLabels: { app: web } }
          namespaceSelector: { matchLabels: { pci-scope: out } }
`

const antreaPass = `
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata: { name: delegate }
spec:
  tier: platform
  priority: 1
  appliedTo:
    - podSelector: { matchLabels: { app: payments-db } }
  ingress:
    - action: Pass
      from:
        - namespaceSelector: {}
`

const antreaBaseline = `
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata: { name: default-deny }
spec:
  tier: baseline
  priority: 250
  appliedTo:
    - namespaceSelector: { matchLabels: { pci-scope: cde } }
  ingress:
    - action: Drop
      from:
        - namespaceSelector: {}
`

const antreaCustomTier = `
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata: { name: house-rules }
spec:
  tier: house
  priority: 1
  appliedTo:
    - podSelector: { matchLabels: { app: payments-db } }
  ingress:
    - action: Drop
      from:
        - namespaceSelector: {}
`

func TestAntrea_ClusterPolicyDrops(t *testing.T) {
	a := loadAdapter(t, LoadAntrea, antreaClusterDrop)
	got := a.Evaluate(flow(), Allow)
	assertVerdict(t, got, Deny)
	if len(got.Policies) == 0 {
		t.Error("a deny verdict must cite the policy that produced it")
	}
}

func TestAntrea_LowerTierPriorityWins(t *testing.T) {
	// emergency (50) is evaluated before securityops (100), so the allow wins
	// even though the drop is also a match.
	a := loadAdapter(t, LoadAntrea, antreaClusterDrop, antreaClusterAllowHigherTier)
	assertVerdict(t, a.Evaluate(flow(), Deny), Allow)
}

func TestAntrea_PassDelegatesToUpstream(t *testing.T) {
	a := loadAdapter(t, LoadAntrea, antreaPass)
	assertVerdict(t, a.Evaluate(flow(), Allow), NoOpinion)
}

func TestAntrea_BaselineIsUnknownWhenUpstreamAllows(t *testing.T) {
	// The Baseline tier only sees traffic no upstream NetworkPolicy selected,
	// and an allow verdict cannot tell "explicitly allowed" from "unselected".
	a := loadAdapter(t, LoadAntrea, antreaBaseline)
	assertVerdict(t, a.Evaluate(flow(), Allow), Unknown)
}

func TestAntrea_BaselineIsIrrelevantWhenUpstreamDenies(t *testing.T) {
	a := loadAdapter(t, LoadAntrea, antreaBaseline)
	assertVerdict(t, a.Evaluate(flow(), Deny), NoOpinion)
}

func TestAntrea_CustomTierIsUnknown(t *testing.T) {
	a := loadAdapter(t, LoadAntrea, antreaCustomTier)
	assertVerdict(t, a.Evaluate(flow(), Allow), Unknown)
}

func TestAntrea_NamespacedPolicyStaysInItsNamespace(t *testing.T) {
	const annp = `
apiVersion: crd.antrea.io/v1beta1
kind: NetworkPolicy
metadata: { name: deny-all, namespace: staging }
spec:
  tier: application
  priority: 1
  appliedTo:
    - podSelector: {}
  ingress:
    - action: Drop
      from:
        - podSelector: {}
`
	a := loadAdapter(t, LoadAntrea, annp)
	assertVerdict(t, a.Evaluate(flow(), Allow), NoOpinion)
}

func TestAntrea_FQDNPeerIsUnknown(t *testing.T) {
	const fqdn = `
apiVersion: crd.antrea.io/v1beta1
kind: ClusterNetworkPolicy
metadata: { name: egress-fqdn }
spec:
  tier: application
  priority: 1
  appliedTo:
    - podSelector: { matchLabels: { app: web } }
  egress:
    - action: Allow
      to:
        - fqdn: "*.example.com"
`
	a := loadAdapter(t, LoadAntrea, fqdn)
	assertVerdict(t, a.Evaluate(flow(), Allow), Unknown)
}
