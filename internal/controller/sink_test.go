package controller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	groma "github.com/groma-sh/groma/api/v1alpha1"
	"github.com/groma-sh/groma/internal/sink"
)

type failingSink struct{ err error }

func (failingSink) Name() string { return "failing" }

func (f failingSink) Write(context.Context, sink.Artifact) (string, error) { return "", f.err }

func sinkRun(name string, es *groma.EvidenceSink) *groma.ConformanceRun {
	return &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: groma.ConformanceRunSpec{
			IntentRef: groma.IntentRef{Name: "pci-cde"},
			Evidence:  &groma.EvidencePolicy{Sink: es},
		},
	}
}

func TestEvidencePublishedToSink(t *testing.T) {
	dir := t.TempDir()
	si := testIntent("pci-cde")
	run := sinkRun("run-sinked", &groma.EvidenceSink{Type: sink.TypeFile, Path: dir})
	r, fc := newRunReconciler(t, si, run)

	got, cm := runEvidenceCM(t, r, fc, run)
	if got.Status.EvidenceSinkRef == "" {
		t.Fatal("status.evidenceSinkRef not set after a successful publish")
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionEvidencePublished)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("EvidencePublished condition = %+v, want True", cond)
	}

	// The published bytes must be identical to the in-cluster ConfigMap, or a
	// signature that verifies against one will not verify against the other.
	for _, name := range []string{evidenceDataKey, statementDataKey, htmlDataKey} {
		published, err := os.ReadFile(filepath.Join(dir, run.Name, name))
		if err != nil {
			t.Fatalf("read published %s: %v", name, err)
		}
		if string(published) != cm.Data[name] {
			t.Errorf("published %s differs from the evidence ConfigMap", name)
		}
	}
}

func TestEvidenceSinkFailureDoesNotFailTheRun(t *testing.T) {
	si := testIntent("pci-cde")
	run := sinkRun("run-sink-down", &groma.EvidenceSink{Type: sink.TypeOCI, Repo: "registry.invalid/groma/evidence"})
	r, fc := newRunReconciler(t, si, run)
	r.NewSink = func(context.Context, *groma.EvidenceSink) (sink.Sink, error) {
		return failingSink{err: errors.New("registry is unreachable")}, nil
	}

	// The conformance verdict is already decided by publish time; losing it to a
	// registry outage would discard the very evidence the sink exists to keep.
	got, cm := runEvidenceCM(t, r, fc, run)
	if cm.Data[evidenceDataKey] == "" {
		t.Error("evidence must still be stored in-cluster when the sink is unreachable")
	}
	if got.Status.EvidenceSinkRef != "" {
		t.Errorf("evidenceSinkRef = %q, want empty after a failed publish", got.Status.EvidenceSinkRef)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionEvidencePublished)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("EvidencePublished condition = %+v, want False", cond)
	}
	if !strings.Contains(cond.Message, "registry is unreachable") {
		t.Errorf("condition message %q should carry the publish error", cond.Message)
	}
}

func TestNoSinkConfiguredLeavesNoCondition(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-no-sink"},
		Spec:       groma.ConformanceRunSpec{IntentRef: groma.IntentRef{Name: si.Name}},
	}
	r, fc := newRunReconciler(t, si, run)
	got, _ := runEvidenceCM(t, r, fc, run)
	if meta.FindStatusCondition(got.Status.Conditions, conditionEvidencePublished) != nil {
		t.Error("EvidencePublished condition set on a run with no sink configured")
	}
}

func TestEvidenceSinkConfigErrorIsReported(t *testing.T) {
	si := testIntent("pci-cde")
	run := sinkRun("run-bad-sink", &groma.EvidenceSink{Type: "dropbox"})
	r, fc := newRunReconciler(t, si, run)

	got, _ := runEvidenceCM(t, r, fc, run)
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionEvidencePublished)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "SinkConfigError" {
		t.Fatalf("EvidencePublished condition = %+v, want False/SinkConfigError", cond)
	}
}
