package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	groma "github.com/groma-sh/groma/api/v1alpha1"
)

func newScheduleReconciler(t *testing.T, objs ...client.Object) (*ConformanceScheduleReconciler, client.Client) {
	t.Helper()
	scheme := testScheme(t)
	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&groma.ConformanceRun{}, &groma.ConformanceSchedule{}).
		WithObjects(objs...).
		Build()
	return &ConformanceScheduleReconciler{Client: fc, Scheme: scheme}, fc
}

func TestConformanceScheduleCreatesRunWhenDue(t *testing.T) {
	sched := &groma.ConformanceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "hourly", CreationTimestamp: metav1.NewTime(time.Now().Add(-2 * time.Hour))},
		Spec: groma.ConformanceScheduleSpec{
			IntentRef: groma.IntentRef{Name: "pci-cde"},
			Schedule:  "* * * * *",
			Mode:      []groma.Mode{groma.ModeActive},
		},
	}
	r, fc := newScheduleReconciler(t, sched)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sched)}

	res, err := r.Reconcile(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter <= 0 || res.RequeueAfter > 61*time.Second {
		t.Errorf("RequeueAfter = %v, want a positive duration within the next minute", res.RequeueAfter)
	}

	var runs groma.ConformanceRunList
	if err := fc.List(ctx, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 1 {
		t.Fatalf("got %d runs, want 1", len(runs.Items))
	}
	run := runs.Items[0]
	if run.Spec.IntentRef.Name != "pci-cde" {
		t.Errorf("run intentRef = %+v", run.Spec.IntentRef)
	}
	if run.Labels[scheduleLabel] != "hourly" {
		t.Errorf("run missing schedule label: %+v", run.Labels)
	}

	var got groma.ConformanceSchedule
	if err := fc.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.LastRunRef != run.Name {
		t.Errorf("lastRunRef = %q, want %q", got.Status.LastRunRef, run.Name)
	}
	if got.Status.LastScheduleTime == nil {
		t.Error("lastScheduleTime not set")
	}
}

func TestConformanceScheduleNotYetDue(t *testing.T) {
	sched := &groma.ConformanceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "monthly", CreationTimestamp: metav1.Now()},
		Spec: groma.ConformanceScheduleSpec{
			IntentRef: groma.IntentRef{Name: "pci-cde"},
			Schedule:  "0 3 1 * *",
		},
	}
	r, fc := newScheduleReconciler(t, sched)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sched)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var runs groma.ConformanceRunList
	if err := fc.List(ctx, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 0 {
		t.Fatalf("got %d runs, want 0 (not due yet)", len(runs.Items))
	}
}

func TestConformanceScheduleRejectsUnknownMode(t *testing.T) {
	sched := &groma.ConformanceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-mode"},
		Spec: groma.ConformanceScheduleSpec{
			IntentRef: groma.IntentRef{Name: "pci-cde"},
			Schedule:  "* * * * *",
			Mode:      []groma.Mode{"bogus"},
		},
	}
	r, fc := newScheduleReconciler(t, sched)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sched)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var runs groma.ConformanceRunList
	if err := fc.List(ctx, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 0 {
		t.Fatalf("got %d runs, want 0 (invalid mode)", len(runs.Items))
	}

	var got groma.ConformanceSchedule
	if err := fc.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, conditionValid, metav1.ConditionFalse, "InvalidMode") {
		t.Errorf("expected Valid=False/InvalidMode condition, got %+v", got.Status.Conditions)
	}
}

func TestConformanceScheduleRejectsBadCron(t *testing.T) {
	sched := &groma.ConformanceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-cron"},
		Spec: groma.ConformanceScheduleSpec{
			IntentRef: groma.IntentRef{Name: "pci-cde"},
			Schedule:  "not a cron expression",
		},
	}
	r, fc := newScheduleReconciler(t, sched)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(sched)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var got groma.ConformanceSchedule
	if err := fc.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, conditionValid, metav1.ConditionFalse, "InvalidSchedule") {
		t.Errorf("expected Valid=False/InvalidSchedule condition, got %+v", got.Status.Conditions)
	}
}

func TestPruneOldRuns(t *testing.T) {
	sched := &groma.ConformanceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "hourly"},
		Spec: groma.ConformanceScheduleSpec{
			IntentRef: groma.IntentRef{Name: "pci-cde"},
			Schedule:  "* * * * *",
			Evidence:  &groma.EvidencePolicy{Retain: "1h"},
		},
	}
	old := metav1.NewTime(time.Now().Add(-48 * time.Hour))
	recent := metav1.NewTime(time.Now().Add(-1 * time.Minute))
	oldRun := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "old-run", Labels: map[string]string{scheduleLabel: "hourly"}},
		Status:     groma.ConformanceRunStatus{Phase: groma.PhaseCompleted, CompletionTime: &old},
	}
	recentRun := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "recent-run", Labels: map[string]string{scheduleLabel: "hourly"}},
		Status:     groma.ConformanceRunStatus{Phase: groma.PhaseCompleted, CompletionTime: &recent},
	}
	r, fc := newScheduleReconciler(t, sched, oldRun, recentRun)
	ctx := context.Background()

	if err := r.pruneOldRuns(ctx, sched, time.Now()); err != nil {
		t.Fatal(err)
	}

	var runs groma.ConformanceRunList
	if err := fc.List(ctx, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs.Items) != 1 || runs.Items[0].Name != "recent-run" {
		t.Fatalf("got %v, want only recent-run to survive", runs.Items)
	}
}

func hasCondition(conds []metav1.Condition, typ string, status metav1.ConditionStatus, reason string) bool {
	for _, c := range conds {
		if c.Type == typ && c.Status == status && c.Reason == reason {
			return true
		}
	}
	return false
}
