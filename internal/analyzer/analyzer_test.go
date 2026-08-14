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
