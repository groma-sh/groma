// Package metrics exposes Groma's conformance results to Prometheus.
//
// The point of a continuous segmentation verifier is that someone finds out
// when segmentation breaks, and nobody reads a ConfigMap on a schedule. These
// metrics turn a failed run into something Alertmanager can page on, and turn
// the enforcement gap - the finding no static or runtime tool can produce alone
// - into a first-class series worth alerting on by itself.
//
// Label cardinality is deliberately bounded by the number of SegmentationIntent
// objects, never by the number of probes: a hundred-namespace cluster produces
// thousands of probes per run, and a per-probe series would cost more to store
// than the evidence itself. Per-probe detail lives in the evidence artifact.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/reconcile"
)

// allResults is every value a run or assertion can take. Gauges are written for
// all of them on each run so a series that stops applying drops to 0 instead of
// going stale at 1, which would otherwise leave an alert firing forever after a
// failure is fixed.
var allResults = []evidence.Result{
	evidence.Pass, evidence.Fail, evidence.Indeterminate, evidence.Error, evidence.Skipped,
}

var (
	RunsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "groma_conformance_runs_total",
		Help: "Conformance runs completed, by intent and overall result.",
	}, []string{"intent", "result"})

	RunDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "groma_conformance_run_duration_seconds",
		Help: "Wall-clock duration of a conformance run, by intent and mode.",
		// Active probing creates and waits on pods, so a run is measured in
		// seconds to minutes, not milliseconds.
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600, 1800},
	}, []string{"intent", "mode"})

	LastRunResult = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "groma_last_run_result",
		Help: "1 for the most recent run's result for an intent, 0 for every other result value.",
	}, []string{"intent", "result"})

	LastRunTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "groma_last_run_timestamp_seconds",
		Help: "Unix time the most recent run for an intent finished. Alert on this going stale to catch a controller that stopped running.",
	}, []string{"intent"})

	LastRunAssertions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "groma_last_run_assertions",
		Help: "Assertions in the most recent run for an intent, by result.",
	}, []string{"intent", "result"})

	LastRunEnforcementGaps = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "groma_last_run_enforcement_gaps",
		Help: "Paths in the most recent run that policy config denies but that are reachable at runtime. Any value above 0 means the cluster believes it is segmented and is not.",
	}, []string{"intent"})

	LastRunConfigDrift = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "groma_last_run_config_drift",
		Help: "Paths in the most recent run that policy config allows but that are blocked at runtime.",
	}, []string{"intent"})

	LastRunUndecidedConfig = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "groma_last_run_undecided_config",
		Help: "Paths in the most recent run whose policy config could not be decided, because a selecting policy uses a construct Groma does not model.",
	}, []string{"intent"})

	AttestationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "groma_attestations_total",
		Help: "Attestation signing attempts, by outcome.",
	}, []string{"outcome"})

	EvidencePublishTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "groma_evidence_publish_total",
		Help: "Evidence publish attempts, by sink type and outcome.",
	}, []string{"sink", "outcome"})
)

const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

func init() {
	// Registering on controller-runtime's registry means the manager's existing
	// metrics endpoint serves these alongside the standard controller metrics,
	// with no second listener to secure.
	ctrlmetrics.Registry.MustRegister(
		RunsTotal, RunDuration,
		LastRunResult, LastRunTimestamp, LastRunAssertions,
		LastRunEnforcementGaps, LastRunConfigDrift, LastRunUndecidedConfig,
		AttestationsTotal, EvidencePublishTotal,
	)
}

// ObserveRun records one finished run. Call it once, after the report is
// summarized and reconciled.
func ObserveRun(intent string, report *evidence.Report) {
	result := string(report.Result)
	RunsTotal.WithLabelValues(intent, result).Inc()
	if d := report.FinishedAt.Sub(report.StartedAt); d > 0 {
		RunDuration.WithLabelValues(intent, report.Mode).Observe(d.Seconds())
	}
	LastRunTimestamp.WithLabelValues(intent).Set(float64(report.FinishedAt.Unix()))

	counts := map[evidence.Result]int{}
	var gaps, drift, undecided int
	for _, p := range report.Probes {
		counts[p.Result]++
		switch p.Reconciliation {
		case reconcile.CellEnforcementGap:
			gaps++
		case reconcile.CellConfigDrift:
			drift++
		}
		if p.Config == reconcile.ConfigUnknown {
			undecided++
		}
	}
	for _, r := range allResults {
		LastRunAssertions.WithLabelValues(intent, string(r)).Set(float64(counts[r]))
		LastRunResult.WithLabelValues(intent, string(r)).Set(boolToFloat(report.Result == r))
	}
	LastRunEnforcementGaps.WithLabelValues(intent).Set(float64(gaps))
	LastRunConfigDrift.WithLabelValues(intent).Set(float64(drift))
	LastRunUndecidedConfig.WithLabelValues(intent).Set(float64(undecided))
}

// ObserveAttestation records one signing attempt.
func ObserveAttestation(err error) {
	AttestationsTotal.WithLabelValues(outcome(err)).Inc()
}

// ObservePublish records one publish attempt against a sink type.
func ObservePublish(sinkType string, err error) {
	EvidencePublishTotal.WithLabelValues(sinkType, outcome(err)).Inc()
}

// Forget drops every series for an intent, so deleting a SegmentationIntent
// does not leave a permanently failing gauge behind.
func Forget(intent string) {
	labels := prometheus.Labels{"intent": intent}
	LastRunTimestamp.Delete(labels)
	LastRunEnforcementGaps.Delete(labels)
	LastRunConfigDrift.Delete(labels)
	LastRunUndecidedConfig.Delete(labels)
	LastRunResult.DeletePartialMatch(labels)
	LastRunAssertions.DeletePartialMatch(labels)
}

func outcome(err error) string {
	if err != nil {
		return OutcomeFailure
	}
	return OutcomeSuccess
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
