package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	groma "github.com/groma-sh/groma/api/v1alpha1"
	"github.com/groma-sh/groma/internal/attest"
)

type fakeSigner struct {
	res *attest.SignResult
	err error
}

func (f fakeSigner) Sign(_ context.Context, _ []byte) (*attest.SignResult, error) {
	return f.res, f.err
}

func runEvidenceCM(t *testing.T, r *ConformanceRunReconciler, fc client.Client, run *groma.ConformanceRun) (groma.ConformanceRun, corev1.ConfigMap) {
	t.Helper()
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
	var cm corev1.ConfigMap
	if err := fc.Get(ctx, client.ObjectKey{Name: got.Status.EvidenceRef, Namespace: "groma-system"}, &cm); err != nil {
		t.Fatalf("evidence configmap missing: %v", err)
	}
	return got, cm
}

func TestEvidenceStatementAndHTMLAlwaysStored(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-unsigned"},
		Spec:       groma.ConformanceRunSpec{IntentRef: groma.IntentRef{Name: si.Name}},
	}
	r, fc := newRunReconciler(t, si, run)
	got, cm := runEvidenceCM(t, r, fc, run)

	if cm.Data[statementDataKey] == "" {
		t.Error("statement.json not stored")
	}
	if cm.Data[htmlDataKey] == "" {
		t.Error("report.html not stored")
	}
	if cm.Data[attestationDataKey] != "" {
		t.Error("attestation.json stored for an unsigned run")
	}
	if meta.FindStatusCondition(got.Status.Conditions, conditionAttestationSigned) != nil {
		t.Error("AttestationSigned condition set on an unsigned run")
	}
}

func TestEvidenceSignedStoresAttestation(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-signed"},
		Spec: groma.ConformanceRunSpec{
			IntentRef: groma.IntentRef{Name: si.Name},
			Evidence:  &groma.EvidencePolicy{Sign: true, Keyless: true},
		},
	}
	r, fc := newRunReconciler(t, si, run)
	r.NewSigner = func(context.Context, *groma.EvidencePolicy) (attest.Signer, error) {
		return fakeSigner{res: &attest.SignResult{Envelope: []byte(`{"payloadType":"application/vnd.in-toto+json"}`), CertChainPEM: []byte("-----BEGIN CERTIFICATE-----\n"), RekorLogIndex: 42}}, nil
	}
	got, cm := runEvidenceCM(t, r, fc, run)

	if cm.Data[attestationDataKey] == "" {
		t.Error("attestation.json not stored for a signed run")
	}
	if cm.Data[certDataKey] == "" {
		t.Error("attestation.pem (cert chain) not stored for keyless signing")
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionAttestationSigned)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("AttestationSigned = %+v, want True", cond)
	}
}

func TestEvidenceSignFailureIsNonFatal(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-signfail"},
		Spec: groma.ConformanceRunSpec{
			IntentRef: groma.IntentRef{Name: si.Name},
			Evidence:  &groma.EvidencePolicy{Sign: true, Keyless: true},
		},
	}
	r, fc := newRunReconciler(t, si, run)
	r.NewSigner = func(context.Context, *groma.EvidencePolicy) (attest.Signer, error) {
		return fakeSigner{err: errors.New("fulcio unreachable")}, nil
	}
	got, cm := runEvidenceCM(t, r, fc, run)

	if got.Status.Result != groma.ResultPass {
		t.Errorf("result = %s, want PASS (signing failure must not change the verdict)", got.Status.Result)
	}
	if cm.Data[statementDataKey] == "" {
		t.Error("statement.json dropped after a signing failure")
	}
	if cm.Data[attestationDataKey] != "" {
		t.Error("attestation.json stored despite a signing failure")
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, conditionAttestationSigned)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "SignError" {
		t.Fatalf("AttestationSigned = %+v, want False/SignError", cond)
	}
}

func TestEvidenceSignWithoutMethod(t *testing.T) {
	si := testIntent("pci-cde")
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{Name: "run-nomethod"},
		Spec: groma.ConformanceRunSpec{
			IntentRef: groma.IntentRef{Name: si.Name},
			Evidence:  &groma.EvidencePolicy{Sign: true},
		},
	}
	r, fc := newRunReconciler(t, si, run)
	got, _ := runEvidenceCM(t, r, fc, run)

	cond := meta.FindStatusCondition(got.Status.Conditions, conditionAttestationSigned)
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("AttestationSigned = %+v, want False", cond)
	}
}
