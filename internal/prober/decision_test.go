package prober

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/intent"
)

func proberWithPolicy(reach func(ns string, labels map[string]string) bool) *Prober {
	cs := fake.NewSimpleClientset(ns("cde", nil), ns("frontend", nil))
	var n int64
	cs.PrependReactor("create", "pods", func(a clienttesting.Action) (bool, runtime.Object, error) {
		pod := a.(clienttesting.CreateAction).GetObject().(*corev1.Pod)
		if pod.Name == "" && pod.GenerateName != "" {
			pod.Name = fmt.Sprintf("%s%d", pod.GenerateName, atomic.AddInt64(&n, 1))
		}
		if pod.Labels[roleKey] == "receiver" {
			pod.Status.Phase = corev1.PodRunning
			pod.Status.PodIP = "10.244.0.1"
		} else if reach(pod.Namespace, pod.Labels) {
			pod.Status.Phase = corev1.PodSucceeded
		} else {
			pod.Status.Phase = corev1.PodFailed
		}
		return false, nil, nil
	})
	return New(cs, Options{MaxConcurrentProbes: 1, Retries: 1})
}

func runAll(t *testing.T, p *Prober, a intent.Assertion) []evidence.Probe {
	t.Helper()
	si := &intent.SegmentationIntent{
		Zones: []intent.Zone{
			{Name: "frontend", Namespace: "frontend", PodLabels: map[string]string{"app": "web"}},
			{Name: "cde", Namespace: "cde", PodLabels: map[string]string{"app": "payments-db"}},
		},
		Assertions: []intent.Assertion{a},
	}
	probes, _, err := p.Run(context.Background(), si)
	if err != nil {
		t.Fatal(err)
	}
	return probes
}

func runOne(t *testing.T, p *Prober, a intent.Assertion) evidence.Probe {
	t.Helper()
	probes := runAll(t, p, a)
	if len(probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(probes))
	}
	return probes[0]
}

func byPort(probes []evidence.Probe) map[int32]evidence.Probe {
	m := map[int32]evidence.Probe{}
	for _, p := range probes {
		m[p.Port] = p
	}
	return m
}

var mayReachOnly443 = intent.Assertion{From: "frontend", To: "cde", Type: intent.MayReachOnly, Ports: []intent.Port{{Protocol: intent.TCP, Port: 443}}}

func TestMayReachOnly_ExpandsToAllowlistPlusCanary(t *testing.T) {

	p := proberWithPolicy(func(string, map[string]string) bool { return true })
	probes := runAll(t, p, mayReachOnly443)
	if len(probes) != 2 {
		t.Fatalf("MayReachOnly [443] should expand to allowlisted + canary = 2 checks, got %d", len(probes))
	}
	m := byPort(probes)
	if m[443].Result != evidence.Pass {
		t.Errorf("allowlisted 443 reachable: got %s, want PASS", m[443].Result)
	}
	if m[9999].Result != evidence.Fail {
		t.Errorf("canary 9999 reachable: got %s, want FAIL", m[9999].Result)
	}
}

func TestMayReachOnly_EnforcedAllowlistPortBlocked(t *testing.T) {

	p := proberWithPolicy(func(ns string, _ map[string]string) bool { return ns == "cde" })
	m := byPort(runAll(t, p, mayReachOnly443))
	if m[443].Result != evidence.Fail {
		t.Errorf("allowlisted 443 blocked: got %s, want FAIL", m[443].Result)
	}
	if m[9999].Result != evidence.Pass || m[9999].PositiveControl != "REACHABLE" {
		t.Errorf("canary 9999: got %s/%s, want PASS/REACHABLE", m[9999].Result, m[9999].PositiveControl)
	}
}

var mustNotReach = intent.Assertion{From: "frontend", To: "cde", Type: intent.MustNotReach, Ports: []intent.Port{{Protocol: intent.TCP, Port: 5432}}}

func TestMustNotReach_BlockedWithPositiveControl_Passes(t *testing.T) {

	p := proberWithPolicy(func(ns string, _ map[string]string) bool { return ns == "cde" })
	got := runOne(t, p, mustNotReach)
	if got.Result != evidence.Pass {
		t.Fatalf("result = %s, want PASS (%+v)", got.Result, got)
	}
	if got.Observed != "BLOCKED" || got.PositiveControl != "REACHABLE" {
		t.Errorf("observed=%s positiveControl=%s", got.Observed, got.PositiveControl)
	}
}

func TestMustNotReach_Reachable_Fails(t *testing.T) {

	p := proberWithPolicy(func(string, map[string]string) bool { return true })
	got := runOne(t, p, mustNotReach)
	if got.Result != evidence.Fail || got.Observed != "REACHABLE" {
		t.Fatalf("result=%s observed=%s, want FAIL/REACHABLE", got.Result, got.Observed)
	}
}

func TestMustNotReach_PositiveControlFails_Indeterminate(t *testing.T) {

	p := proberWithPolicy(func(string, map[string]string) bool { return false })
	got := runOne(t, p, mustNotReach)
	if got.Result != evidence.Indeterminate || got.PositiveControl != "BLOCKED" {
		t.Fatalf("result=%s positiveControl=%s, want INDETERMINATE/BLOCKED", got.Result, got.PositiveControl)
	}
}

func TestMustReach_RequiredPathBlockedByPolicy_Fails(t *testing.T) {

	p := proberWithPolicy(func(ns string, _ map[string]string) bool { return ns == "cde" })
	a := mustNotReach
	a.Type = intent.MustReach
	got := runOne(t, p, a)
	if got.Result != evidence.Fail || got.PositiveControl != "REACHABLE" {
		t.Fatalf("result=%s positiveControl=%s, want FAIL/REACHABLE", got.Result, got.PositiveControl)
	}
}
