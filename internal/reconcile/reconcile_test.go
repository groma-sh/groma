package reconcile

import (
	"testing"

	"github.com/groma-sh/groma/internal/analyzer"
	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/intent"
	"github.com/groma-sh/groma/internal/prober"
)

func mustNotReachCheck() prober.Check {
	return prober.Check{
		From:      prober.Endpoint{Zone: "out", Namespace: "out"},
		To:        prober.Endpoint{Zone: "cde", Namespace: "cde"},
		Assertion: string(intent.MustNotReach), Port: intent.Port{Protocol: intent.TCP, Port: 5432},
		ExpectReachable: false,
	}
}

func mustReachCheck() prober.Check {
	c := mustNotReachCheck()
	c.Assertion = string(intent.MustReach)
	c.ExpectReachable = true
	return c
}

func runtimeProbe(observed string, result evidence.Result) evidence.Probe {
	return evidence.Probe{Observed: observed, Result: result, Port: 5432}
}

func TestReconcile_EnforcementGap(t *testing.T) {
	checks := []prober.Check{mustNotReachCheck()}
	rt := []evidence.Probe{runtimeProbe("REACHABLE", evidence.Fail)}
	cfg := []analyzer.ConfigResult{{Allows: false}}
	got := Reconcile(checks, rt, cfg)[0]
	if got.Reconciliation != CellEnforcementGap {
		t.Fatalf("cell = %q, want %q", got.Reconciliation, CellEnforcementGap)
	}
	if got.Result != evidence.Fail || got.Config != "DENIED" {
		t.Errorf("result=%s config=%s, want FAIL/DENIED", got.Result, got.Config)
	}
}

func TestReconcile_ConsistentDeniedAndBlocked(t *testing.T) {
	checks := []prober.Check{mustNotReachCheck()}
	rt := []evidence.Probe{runtimeProbe("BLOCKED", evidence.Pass)}
	cfg := []analyzer.ConfigResult{{Allows: false}}
	got := Reconcile(checks, rt, cfg)[0]
	if got.Reconciliation != CellConsistent || got.Result != evidence.Pass {
		t.Fatalf("cell=%q result=%s, want CONSISTENT/PASS", got.Reconciliation, got.Result)
	}
}

func TestReconcile_ConfigDriftKeepsPass(t *testing.T) {
	checks := []prober.Check{mustNotReachCheck()}
	rt := []evidence.Probe{runtimeProbe("BLOCKED", evidence.Pass)}
	cfg := []analyzer.ConfigResult{{Allows: true}}
	got := Reconcile(checks, rt, cfg)[0]
	if got.Reconciliation != CellConfigDrift {
		t.Fatalf("cell = %q, want %q", got.Reconciliation, CellConfigDrift)
	}
	if got.Result != evidence.Pass {
		t.Errorf("config drift on a satisfied MustNotReach should stay PASS, got %s", got.Result)
	}
}

func TestReconcile_MustReachGapFails(t *testing.T) {
	checks := []prober.Check{mustReachCheck()}
	rt := []evidence.Probe{runtimeProbe("REACHABLE", evidence.Pass)}
	cfg := []analyzer.ConfigResult{{Allows: false}}
	got := Reconcile(checks, rt, cfg)[0]
	if got.Reconciliation != CellEnforcementGap || got.Result != evidence.Fail {
		t.Fatalf("cell=%q result=%s, want ENFORCEMENT-GAP/FAIL", got.Reconciliation, got.Result)
	}
}

func TestReconcile_IndeterminateNotReconciled(t *testing.T) {
	checks := []prober.Check{mustNotReachCheck()}
	rt := []evidence.Probe{runtimeProbe("BLOCKED", evidence.Indeterminate)}
	cfg := []analyzer.ConfigResult{{Allows: false}}
	got := Reconcile(checks, rt, cfg)[0]
	if got.Reconciliation != "" {
		t.Errorf("indeterminate runtime must not get a reconciliation cell, got %q", got.Reconciliation)
	}
	if got.Result != evidence.Indeterminate || got.Config != "DENIED" {
		t.Errorf("result=%s config=%s, want INDETERMINATE/DENIED", got.Result, got.Config)
	}
}

func TestSetEnforcement(t *testing.T) {
	report := &evidence.Report{Probes: []evidence.Probe{
		{Reconciliation: CellConsistent},
		{Reconciliation: CellEnforcementGap},
	}}
	SetEnforcement(report)
	if report.EnforcementMatchesConfig == nil || *report.EnforcementMatchesConfig {
		t.Fatalf("expected EnforcementMatchesConfig=false with a gap present")
	}
	if report.EnforcementDetail == "" {
		t.Errorf("expected a detail message")
	}

	clean := &evidence.Report{Probes: []evidence.Probe{{Reconciliation: CellConsistent}}}
	SetEnforcement(clean)
	if clean.EnforcementMatchesConfig == nil || !*clean.EnforcementMatchesConfig {
		t.Errorf("all-consistent run should report EnforcementMatchesConfig=true")
	}

	activeOnly := &evidence.Report{Probes: []evidence.Probe{{Result: evidence.Pass}}}
	SetEnforcement(activeOnly)
	if activeOnly.EnforcementMatchesConfig != nil {
		t.Errorf("a run with no reconciled paths must leave the field nil")
	}
}

func TestStaticProbes(t *testing.T) {
	checks := []prober.Check{mustNotReachCheck(), mustNotReachCheck()}
	cfg := []analyzer.ConfigResult{{Allows: false}, {Allows: true}}
	got := StaticProbes(checks, cfg)
	if got[0].Result != evidence.Pass || got[0].Config != "DENIED" {
		t.Errorf("denied MustNotReach: got %s/%s, want PASS/DENIED", got[0].Result, got[0].Config)
	}
	if got[1].Result != evidence.Fail || got[1].Config != "ALLOWED" {
		t.Errorf("allowed MustNotReach: got %s/%s, want FAIL/ALLOWED", got[1].Result, got[1].Config)
	}
	if got[0].Observed != "" {
		t.Errorf("static-only probe must have no runtime Observed, got %q", got[0].Observed)
	}
}
