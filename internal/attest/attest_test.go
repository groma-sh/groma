package attest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/intent"
	"github.com/groma-sh/groma/internal/reconcile"
)

func fixtureReport() (*evidence.Report, *intent.SegmentationIntent) {
	f := false
	start := time.Date(2026, 8, 3, 3, 0, 0, 0, time.UTC)
	report := &evidence.Report{
		Intent:                   "pci-cde-isolation",
		Framework:                "PCI-DSS-4.0",
		Controls:                 []string{"11.4.5", "1.3.4"},
		Mode:                     "active+static",
		StartedAt:                start,
		FinishedAt:               start.Add(12 * time.Second),
		Result:                   evidence.Fail,
		EnforcementMatchesConfig: &f,
		EnforcementDetail:        "runtime allows one or more paths your policy config denies (enforcement gap)",
		Zones: []evidence.ResolvedZone{
			{Name: "out-of-scope", Namespace: "frontend"},
			{Name: "cde", Namespace: "payments", IdentityLabels: map[string]string{"app": "payments-db"}},
		},
		Probes: []evidence.Probe{
			{
				From: "out-of-scope", To: "cde", FromNamespace: "frontend", ToNamespace: "payments",
				Protocol: "TCP", Port: 5432, Assertion: string(intent.MustNotReach),
				Config: "DENIED", Observed: "REACHABLE", PositiveControl: "REACHABLE",
				Reconciliation: reconcile.CellEnforcementGap, Result: evidence.Fail,
				Detail: "enforcement gap: policy config DENIES this path but it is REACHABLE at runtime on tcp/5432",
			},
			{
				From: "dmz", To: "cde", FromNamespace: "dmz", ToNamespace: "payments",
				Protocol: "TCP", Port: 443, Assertion: string(intent.MayReachOnly),
				Config: "ALLOWED", Observed: "REACHABLE",
				Reconciliation: reconcile.CellConsistent, Result: evidence.Pass,
			},
		},
	}
	si := &intent.SegmentationIntent{
		APIVersion: "groma.dev/v1alpha1", Kind: "SegmentationIntent",
		Metadata: intent.Meta{Name: "pci-cde-isolation"},
		Zones: []intent.Zone{
			{Name: "out-of-scope", NamespaceSelector: &intent.LabelSelector{MatchLabels: map[string]string{"pci-scope": "out"}}},
			{Name: "cde", NamespaceSelector: &intent.LabelSelector{MatchLabels: map[string]string{"pci-scope": "cde"}}, PodLabels: map[string]string{"app": "payments-db"}},
			{Name: "dmz", NamespaceSelector: &intent.LabelSelector{MatchLabels: map[string]string{"tier": "dmz"}}},
		},
		Assertions: []intent.Assertion{
			{From: "out-of-scope", To: "cde", Type: intent.MustNotReach, Ports: []intent.Port{{Protocol: intent.TCP, Port: 5432}}},
			{From: "dmz", To: "cde", Type: intent.MayReachOnly, Ports: []intent.Port{{Protocol: intent.TCP, Port: 443}}},
		},
	}
	return report, si
}

func TestBuildStatementGolden(t *testing.T) {
	report, si := fixtureReport()
	stmt, err := BuildStatement(report, si, Meta{GromaVersion: "v0.4.0-test", ClusterID: "kind-groma", CNI: "kindnet/unknown"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := stmt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	golden := filepath.Join("testdata", "statement.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with UPDATE_GOLDEN=1 to regenerate): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("statement mismatch with %s (run UPDATE_GOLDEN=1 to update)\n--- got ---\n%s", golden, got)
	}
}

func TestEnforcementGapMapping(t *testing.T) {
	report, si := fixtureReport()
	stmt, err := BuildStatement(report, si, Meta{GromaVersion: "v0.4.0-test"})
	if err != nil {
		t.Fatal(err)
	}
	gap := stmt.Predicate.Assertions[0]
	if gap.ConfigAllows == nil || *gap.ConfigAllows {
		t.Errorf("enforcement-gap path: configAllows should be false, got %v", gap.ConfigAllows)
	}
	if gap.RuntimeReachable != "REACHABLE" {
		t.Errorf("enforcement-gap path: runtimeReachable = %q, want REACHABLE", gap.RuntimeReachable)
	}
	if len(gap.MappedControls) == 0 {
		t.Errorf("enforcement-gap path: expected mapped PCI controls, got none")
	}
	if stmt.Subject[0].Digest["sha256"] == "" {
		t.Errorf("subject digest not set")
	}
}
