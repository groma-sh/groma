package adapters

import (
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestCombine(t *testing.T) {
	cilium := func(v Verdict) Decision { return Decision{Verdict: v, Adapter: "cilium"} }
	calico := func(v Verdict) Decision { return Decision{Verdict: v, Adapter: "calico"} }

	cases := []struct {
		name      string
		k8s       Verdict
		decisions []Decision
		want      Verdict
	}{
		{"no adapters leaves the upstream verdict", Allow, nil, Allow},
		{"abstaining adapters leave the upstream verdict", Deny, []Decision{cilium(NoOpinion)}, Deny},
		{"a CNI deny overrides an upstream allow", Allow, []Decision{cilium(Deny)}, Deny},
		{"a CNI allow overrides an upstream deny", Deny, []Decision{cilium(Allow)}, Allow},
		{"unknown poisons the result", Allow, []Decision{cilium(Unknown), calico(Allow)}, Unknown},
		{"disagreement poisons the result", Allow, []Decision{cilium(Allow), calico(Deny)}, Unknown},
		{"agreement is kept", Allow, []Decision{cilium(Deny), calico(Deny)}, Deny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Combine(tc.k8s, tc.decisions); got.Verdict != tc.want {
				t.Errorf("verdict = %s, want %s", got.Verdict, tc.want)
			}
		})
	}
}

func TestParseSelection(t *testing.T) {
	names, auto, err := parseSelection("auto")
	if err != nil || !auto || len(names) != len(Names()) {
		t.Errorf(`"auto" = (%v, %v, %v), want every adapter with auto set`, names, auto, err)
	}
	if names, _, err := parseSelection("none"); err != nil || len(names) != 0 {
		t.Errorf(`"none" = (%v, %v), want no adapters`, names, err)
	}
	names, auto, err = parseSelection("cilium, calico")
	if err != nil || auto || len(names) != 2 {
		t.Errorf(`"cilium, calico" = (%v, %v, %v), want both named adapters`, names, auto, err)
	}
	if _, _, err := parseSelection("weave"); err == nil {
		t.Error("an unknown adapter name must be rejected rather than silently ignored")
	}
}

func TestIsAbsent(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}
	absent := []error{
		apierrors.NewNotFound(gvr.GroupResource(), "x"),
		apierrors.NewForbidden(gvr.GroupResource(), "x", nil),
		&meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "cilium.io", Kind: "CiliumNetworkPolicy"}},
	}
	for _, err := range absent {
		if !isAbsent(err) {
			t.Errorf("%v should count as an uninstalled CNI, not a failure", err)
		}
	}
	if isAbsent(apierrors.NewInternalError(errors.New("etcd is down"))) {
		t.Error("a real API failure must not be mistaken for an uninstalled CNI")
	}
}
