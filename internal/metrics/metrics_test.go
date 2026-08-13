package metrics

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/reconcile"
)

func gapReport() *evidence.Report {
	start := time.Date(2026, 8, 3, 3, 0, 0, 0, time.UTC)
	return &evidence.Report{
		Intent: "pci-cde", Mode: "active+static", Result: evidence.Fail,
		StartedAt: start, FinishedAt: start.Add(30 * time.Second),
		Probes: []evidence.Probe{
			{Result: evidence.Fail, Reconciliation: reconcile.CellEnforcementGap},
			{Result: evidence.Pass, Reconciliation: reconcile.CellConsistent},
			{Result: evidence.Pass, Reconciliation: reconcile.CellConfigDrift},
			{Result: evidence.Indeterminate, Config: reconcile.ConfigUnknown},
		},
	}
}

func TestObserveRun(t *testing.T) {
	Forget("pci-cde")
	ObserveRun("pci-cde", gapReport())

	if got := testutil.ToFloat64(LastRunEnforcementGaps.WithLabelValues("pci-cde")); got != 1 {
		t.Errorf("enforcement gaps = %v, want 1", got)
	}
	if got := testutil.ToFloat64(LastRunConfigDrift.WithLabelValues("pci-cde")); got != 1 {
		t.Errorf("config drift = %v, want 1", got)
	}
	if got := testutil.ToFloat64(LastRunUndecidedConfig.WithLabelValues("pci-cde")); got != 1 {
		t.Errorf("undecided config = %v, want 1", got)
	}
	if got := testutil.ToFloat64(LastRunResult.WithLabelValues("pci-cde", "FAIL")); got != 1 {
		t.Errorf("last run result FAIL = %v, want 1", got)
	}
	if got := testutil.ToFloat64(LastRunAssertions.WithLabelValues("pci-cde", "PASS")); got != 2 {
		t.Errorf("passing assertions = %v, want 2", got)
	}
}

func TestObserveRun_ClearsThePreviousResult(t *testing.T) {
	Forget("pci-cde")
	ObserveRun("pci-cde", gapReport())

	fixed := gapReport()
	fixed.Result = evidence.Pass
	fixed.Probes = []evidence.Probe{{Result: evidence.Pass, Reconciliation: reconcile.CellConsistent}}
	ObserveRun("pci-cde", fixed)

	// A gauge left at 1 after the gap is closed would keep an alert firing for
	// a problem that no longer exists.
	if got := testutil.ToFloat64(LastRunResult.WithLabelValues("pci-cde", "FAIL")); got != 0 {
		t.Errorf("FAIL gauge = %v after a passing run, want 0", got)
	}
	if got := testutil.ToFloat64(LastRunResult.WithLabelValues("pci-cde", "PASS")); got != 1 {
		t.Errorf("PASS gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(LastRunEnforcementGaps.WithLabelValues("pci-cde")); got != 0 {
		t.Errorf("enforcement gaps = %v after a clean run, want 0", got)
	}
}

func TestForget(t *testing.T) {
	// Other tests share these package-level collectors, so count series rather
	// than asserting the whole family is empty.
	before := testutil.CollectAndCount(LastRunEnforcementGaps)
	resultsBefore := testutil.CollectAndCount(LastRunResult)

	ObserveRun("doomed", gapReport())
	if got := testutil.CollectAndCount(LastRunEnforcementGaps); got != before+1 {
		t.Fatalf("observing a run added %d series, want 1", got-before)
	}

	Forget("doomed")
	if got := testutil.CollectAndCount(LastRunEnforcementGaps); got != before {
		t.Errorf("gauge series survived Forget: %d, want %d", got, before)
	}
	if got := testutil.CollectAndCount(LastRunResult); got != resultsBefore {
		t.Errorf("per-result series survived Forget: %d, want %d", got, resultsBefore)
	}
}

func TestObserveOutcomes(t *testing.T) {
	before := testutil.ToFloat64(EvidencePublishTotal.WithLabelValues("oci", OutcomeFailure))
	ObservePublish("oci", errors.New("registry is unreachable"))
	if got := testutil.ToFloat64(EvidencePublishTotal.WithLabelValues("oci", OutcomeFailure)); got != before+1 {
		t.Errorf("failed publish not counted: %v -> %v", before, got)
	}

	before = testutil.ToFloat64(AttestationsTotal.WithLabelValues(OutcomeSuccess))
	ObserveAttestation(nil)
	if got := testutil.ToFloat64(AttestationsTotal.WithLabelValues(OutcomeSuccess)); got != before+1 {
		t.Errorf("successful signing not counted: %v -> %v", before, got)
	}
}
