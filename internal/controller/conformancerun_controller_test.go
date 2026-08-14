package controller

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	groma "github.com/groma-sh/groma/api/v1alpha1"
)

const probeRoleLabel = "groma.dev/role"

func alwaysReachableClientset() *fakeclientset.Clientset {
	cs := fakeclientset.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cde"}})
	var n int64
	cs.PrependReactor("create", "pods", func(a clienttesting.Action) (bool, runtime.Object, error) {
		pod := a.(clienttesting.CreateAction).GetObject().(*corev1.Pod)
		if pod.Name == "" && pod.GenerateName != "" {
			pod.Name = fmt.Sprintf("%s%d", pod.GenerateName, atomic.AddInt64(&n, 1))
		}
		if pod.Labels[probeRoleLabel] == "receiver" {
			pod.Status.Phase = corev1.PodRunning
			pod.Status.PodIP = "10.244.0.1"
		} else {
			pod.Status.Phase = corev1.PodSucceeded
		}
		return false, nil, nil
	})
	return cs
}

func newRunReconciler(t *testing.T, objs ...client.Object) (*ConformanceRunReconciler, client.Client) {
	t.Helper()
	scheme := testScheme(t)
	fc := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&groma.ConformanceRun{}, &groma.ConformanceSchedule{}).
		WithObjects(objs...).
		Build()
	r := &ConformanceRunReconciler{
		Client: fc,

		APIReader:         fc,
		Scheme:            scheme,
		Clientset:         alwaysReachableClientset(),
		EvidenceNamespace: "groma-system",
	}
	return r, fc
}

func TestConformanceRunReconcilePass(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-1"},
		Spec:       groma.ConformanceRunSpec{IntentRef: groma.IntentRef{Name: si.Name}},
	}
	r, fc := newRunReconciler(t, si, run)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(run)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}

	var got groma.ConformanceRun
	if err := fc.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != groma.PhaseCompleted {
		t.Fatalf("phase = %s, want Completed", got.Status.Phase)
	}
	if got.Status.Result != groma.ResultPass {
		t.Fatalf("result = %s, want PASS", got.Status.Result)
	}
	if got.Status.AssertionsPassed != 1 {
		t.Fatalf("assertionsPassed = %d, want 1", got.Status.AssertionsPassed)
	}
	if got.Status.EvidenceRef == "" {
		t.Fatal("evidenceRef not set")
	}

	var cm corev1.ConfigMap
	if err := fc.Get(ctx, client.ObjectKey{Name: got.Status.EvidenceRef, Namespace: "groma-system"}, &cm); err != nil {
		t.Fatalf("evidence configmap missing: %v", err)
	}
	if cm.Data[evidenceDataKey] == "" {
		t.Fatal("evidence configmap has no evidence.json data")
	}
}

func TestConformanceRunReconcileIdempotent(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-1"},
		Spec:       groma.ConformanceRunSpec{IntentRef: groma.IntentRef{Name: si.Name}},
	}
	r, fc := newRunReconciler(t, si, run)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(run)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var first groma.ConformanceRun
	if err := fc.Get(ctx, req.NamespacedName, &first); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var second groma.ConformanceRun
	if err := fc.Get(ctx, req.NamespacedName, &second); err != nil {
		t.Fatal(err)
	}
	if !second.Status.CompletionTime.Time.Equal(first.Status.CompletionTime.Time) {
		t.Fatal("second reconcile re-ran the probe on an already-Completed run")
	}
}

func TestConformanceRunStaticMode(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-static"},
		Spec: groma.ConformanceRunSpec{
			IntentRef: groma.IntentRef{Name: si.Name},
			Mode:      []groma.Mode{groma.ModeStatic},
		},
	}
	r, fc := newRunReconciler(t, si, run)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(run)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var got groma.ConformanceRun
	if err := fc.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != groma.PhaseCompleted || got.Status.Result != groma.ResultPass {
		t.Fatalf("phase=%s result=%s, want Completed/PASS", got.Status.Phase, got.Status.Result)
	}

	if meta.FindStatusCondition(got.Status.Conditions, conditionEnforcementMatchesConfig) != nil {
		t.Errorf("static-only run should not set the %s condition", conditionEnforcementMatchesConfig)
	}
}

func TestConformanceRunReconciledConsistent(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-both"},
		Spec: groma.ConformanceRunSpec{
			IntentRef: groma.IntentRef{Name: si.Name},
			Mode:      []groma.Mode{groma.ModeActive, groma.ModeStatic},
		},
	}
	r, fc := newRunReconciler(t, si, run)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(run)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var got groma.ConformanceRun
	if err := fc.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != groma.PhaseCompleted || got.Status.Result != groma.ResultPass {
		t.Fatalf("phase=%s result=%s, want Completed/PASS", got.Status.Phase, got.Status.Result)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionEnforcementMatchesConfig)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("EnforcementMatchesConfig = %+v, want present and True", cond)
	}
}

func TestConformanceRunMissingIntent(t *testing.T) {
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-missing"},
		Spec:       groma.ConformanceRunSpec{IntentRef: groma.IntentRef{Name: "does-not-exist"}},
	}
	r, fc := newRunReconciler(t, run)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(run)}

	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	var got groma.ConformanceRun
	if err := fc.Get(ctx, req.NamespacedName, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != groma.PhaseFailed {
		t.Fatalf("phase = %s, want Failed", got.Status.Phase)
	}
}
