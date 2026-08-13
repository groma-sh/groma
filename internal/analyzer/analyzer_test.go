package analyzer

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/groma-sh/groma/internal/adapters"
	"github.com/groma-sh/groma/internal/intent"
	"github.com/groma-sh/groma/internal/prober"
)

func ns(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func denyIngressExceptCDE() *netv1.NetworkPolicy {
	port := intstr.FromInt(5432)
	return &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "cde", Name: "isolate-payments"},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{{
				From:  []netv1.NetworkPolicyPeer{{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"pci": "cde"}}}},
				Ports: []netv1.NetworkPolicyPort{{Port: &port}},
			}},
		},
	}
}

func ep(zone, namespace string, labels map[string]string) prober.Endpoint {
	return prober.Endpoint{Zone: zone, Namespace: namespace, Labels: labels}
}

func check(from, to prober.Endpoint, port int32) prober.Check {
	return prober.Check{From: from, To: to, Assertion: "MustNotReach", Port: intent.Port{Protocol: intent.TCP, Port: port}}
}

func newAnalyzer(t *testing.T, objs ...runtime.Object) *Analyzer {
	t.Helper()
	a, err := New(context.Background(), fake.NewSimpleClientset(objs...), nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAnalyze_DeniesOutOfScope(t *testing.T) {
	a := newAnalyzer(t,
		ns("cde", map[string]string{"pci": "cde"}),
		ns("out", map[string]string{"pci": "out"}),
		denyIngressExceptCDE(),
	)
	out := ep("out-of-scope", "out", map[string]string{"app": "web"})
	cde := ep("cde", "cde", map[string]string{"app": "payments"})
	res := a.Analyze([]prober.Check{check(out, cde, 5432)})
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	if res[0].Allows {
		t.Errorf("out-of-scope -> cde:5432 should be DENIED by config")
	}
}

func TestAnalyze_AllowsInScope(t *testing.T) {
	a := newAnalyzer(t,
		ns("cde", map[string]string{"pci": "cde"}),
		ns("out", map[string]string{"pci": "out"}),
		denyIngressExceptCDE(),
	)
	inCde := ep("cde-peer", "cde", map[string]string{"app": "web"})
	cde := ep("cde", "cde", map[string]string{"app": "payments"})
	res := a.Analyze([]prober.Check{check(inCde, cde, 5432)})
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	if !res[0].Allows {
		t.Errorf("in-cde -> cde:5432 should be ALLOWED by config (namespaceSelector pci=cde)")
	}
}

func TestAnalyze_NoPolicyAllowsAll(t *testing.T) {

	a := newAnalyzer(t, ns("cde", nil), ns("out", nil))
	out := ep("out-of-scope", "out", map[string]string{"app": "web"})
	cde := ep("cde", "cde", map[string]string{"app": "payments"})
	res := a.Analyze([]prober.Check{check(out, cde, 5432)})
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	if !res[0].Allows {
		t.Errorf("with no policy, all traffic is allowed by config")
	}
}

func TestAnalyze_WrongPortDenied(t *testing.T) {

	a := newAnalyzer(t,
		ns("cde", map[string]string{"pci": "cde"}),
		denyIngressExceptCDE(),
	)
	inCde := ep("cde-peer", "cde", map[string]string{"app": "web"})
	cde := ep("cde", "cde", map[string]string{"app": "payments"})
	res := a.Analyze([]prober.Check{check(inCde, cde, 6379)})
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	if res[0].Allows {
		t.Errorf("in-cde -> cde:6379 should be DENIED (only 5432 is allowlisted)")
	}
}

// stubAdapter stands in for a CNI adapter so the analyzer's folding logic can be
// tested without a live cluster's CRDs.
type stubAdapter struct {
	name     string
	decision adapters.Decision
}

func (s stubAdapter) Name() string { return s.name }

func (s stubAdapter) Evaluate(adapters.Flow, adapters.Verdict) adapters.Decision { return s.decision }

func TestAnalyze_AdapterOverridesUpstreamAllow(t *testing.T) {
	// No NetworkPolicy at all, so upstream analysis says ALLOWED; the CNI's own
	// policy is what actually denies the path.
	deny := stubAdapter{name: "cilium", decision: adapters.Decision{
		Verdict: adapters.Deny, Adapter: "cilium",
		Reason:   "CiliumClusterwideNetworkPolicy quarantine denies this path",
		Policies: []string{"CiliumClusterwideNetworkPolicy quarantine"},
	}}
	a, err := New(context.Background(), fake.NewSimpleClientset(ns("cde", nil), ns("out", nil)), nil, deny)
	if err != nil {
		t.Fatal(err)
	}
	res := a.Analyze([]prober.Check{check(
		ep("out-of-scope", "out", map[string]string{"app": "web"}),
		ep("cde", "cde", map[string]string{"app": "payments"}), 5432)})[0]
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.Allows {
		t.Error("the CNI adapter denies this path, so the config verdict must be DENIED")
	}
	if res.Source != "cilium" || len(res.Policies) != 1 {
		t.Errorf("verdict must be attributed to the adapter, got source=%q policies=%v", res.Source, res.Policies)
	}
}

func TestAnalyze_AdapterUnknownIsNotAVerdict(t *testing.T) {
	unknown := stubAdapter{name: "antrea", decision: adapters.Decision{
		Verdict: adapters.Unknown, Adapter: "antrea", Reason: "baseline-tier policy applies",
	}}
	a, err := New(context.Background(), fake.NewSimpleClientset(ns("cde", nil), ns("out", nil)), nil, unknown)
	if err != nil {
		t.Fatal(err)
	}
	res := a.Analyze([]prober.Check{check(
		ep("out-of-scope", "out", nil), ep("cde", "cde", nil), 5432)})[0]
	if !res.Unknown {
		t.Fatal("an adapter that cannot decide must produce an undecidable ConfigResult")
	}
	if res.Reason == "" {
		t.Error("an undecidable result must carry the reason into evidence")
	}
}

func TestAnalyze_AbstainingAdapterLeavesUpstreamVerdict(t *testing.T) {
	abstain := stubAdapter{name: "calico", decision: adapters.Decision{Verdict: adapters.NoOpinion, Adapter: "calico"}}
	a, err := New(context.Background(),
		fake.NewSimpleClientset(ns("cde", map[string]string{"pci": "cde"}), ns("out", map[string]string{"pci": "out"}), denyIngressExceptCDE()),
		nil, abstain)
	if err != nil {
		t.Fatal(err)
	}
	res := a.Analyze([]prober.Check{check(
		ep("out-of-scope", "out", map[string]string{"app": "web"}),
		ep("cde", "cde", map[string]string{"app": "payments"}), 5432)})[0]
	if res.Allows || res.Unknown {
		t.Error("with the adapter abstaining, the upstream NetworkPolicy deny must stand")
	}
	if res.Source != upstreamSource {
		t.Errorf("source = %q, want %q", res.Source, upstreamSource)
	}
	if got := a.Adapters(); len(got) != 1 || got[0] != "calico" {
		t.Errorf("Adapters() = %v, want [calico]", got)
	}
}
