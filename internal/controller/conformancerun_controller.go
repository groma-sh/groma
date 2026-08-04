package controller

import (
	"bytes"
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	policyapi "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	groma "github.com/groma-sh/groma/api/v1alpha1"
	"github.com/groma-sh/groma/internal/analyzer"
	"github.com/groma-sh/groma/internal/attest"
	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/intent"
	"github.com/groma-sh/groma/internal/prober"
	"github.com/groma-sh/groma/internal/reconcile"
	reportpkg "github.com/groma-sh/groma/internal/report"
	"github.com/groma-sh/groma/internal/version"
)

const (
	conditionComplete                 = "Complete"
	conditionSound                    = "Sound"
	conditionEnforcementMatchesConfig = "EnforcementMatchesConfig"
	conditionAttestationSigned        = "AttestationSigned"
)

type ConformanceRunReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	APIReader client.Reader

	Clientset kubernetes.Interface

	PolicyClient      policyapi.Interface
	EvidenceNamespace string

	ClusterID string

	NewSigner func(ctx context.Context, ep *groma.EvidencePolicy) (attest.Signer, error)
}

func (r *ConformanceRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var run groma.ConformanceRun
	if err := r.APIReader.Get(ctx, req.NamespacedName, &run); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if run.Status.Phase == groma.PhaseCompleted || run.Status.Phase == groma.PhaseFailed {
		return ctrl.Result{}, nil
	}

	active, static, err := resolveModes(run.Spec.Mode)
	if err != nil {
		return r.fail(ctx, &run, "InvalidMode", err.Error())
	}

	if run.Status.Phase == "" {
		now := metav1.Now()
		run.Status.Phase = groma.PhaseRunning
		run.Status.StartTime = &now
		if err := r.Status().Update(ctx, &run); err != nil {
			return ctrl.Result{}, err
		}
	}

	var si groma.SegmentationIntent
	if err := r.Get(ctx, client.ObjectKey{Name: run.Spec.IntentRef.Name}, &si); err != nil {
		if apierrors.IsNotFound(err) {
			return r.fail(ctx, &run, "IntentNotFound", fmt.Sprintf("SegmentationIntent %q not found", run.Spec.IntentRef.Name))
		}
		return ctrl.Result{}, err
	}

	engineIntent, err := intent.FromCRD(&si)
	if err != nil {
		return r.fail(ctx, &run, "InvalidIntent", err.Error())
	}

	report := &evidence.Report{
		Intent:    engineIntent.Metadata.Name,
		Framework: engineIntent.Compliance.Framework,
		Controls:  engineIntent.Compliance.Controls,
		Mode:      modeLabel(active, static),
		StartedAt: time.Now().UTC(),
	}
	pr := prober.New(r.Clientset, proberOptions(run.Spec.ProbeStrategy))
	checks, zones, err := pr.Plan(ctx, engineIntent)
	if err != nil {
		return r.fail(ctx, &run, "PlanError", err.Error())
	}
	report.Zones = zones
	report.Probes, err = r.collect(ctx, active, static, pr, checks)
	if err != nil {
		return r.fail(ctx, &run, "AnalyzeError", err.Error())
	}
	report.FinishedAt = time.Now().UTC()
	report.Summarize()
	reconcile.SetEnforcement(report)

	files, attestCond, err := r.buildEvidence(ctx, engineIntent, &run, report)
	if err != nil {
		return r.fail(ctx, &run, "AttestError", err.Error())
	}

	evidenceRef, err := writeEvidenceConfigMap(ctx, r.Client, r.Scheme, r.EvidenceNamespace, &run, report, files)
	if err != nil {
		logger.Error(err, "failed to write evidence configmap", "run", run.Name)
		return ctrl.Result{}, err
	}

	completion := metav1.Now()
	run.Status.Phase = groma.PhaseCompleted
	run.Status.Result = groma.Result(report.Result)
	run.Status.EvidenceRef = evidenceRef
	run.Status.CompletionTime = &completion
	countResults(&run.Status, report.Probes)
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: conditionComplete, Status: metav1.ConditionTrue,
		Reason: "RunFinished", Message: "conformance run finished",
	})
	setSoundCondition(&run.Status, report)
	setEnforcementCondition(&run.Status, report)
	if attestCond != nil {
		meta.SetStatusCondition(&run.Status.Conditions, *attestCond)
	}

	if err := ignoreConflict(r.Status().Update(ctx, &run)); err != nil {
		return ctrl.Result{}, err
	}
	logger.Info("conformance run completed", "run", run.Name, "result", run.Status.Result)
	return ctrl.Result{}, nil
}

func (r *ConformanceRunReconciler) fail(ctx context.Context, run *groma.ConformanceRun, reason, msg string) (ctrl.Result, error) {
	now := metav1.Now()
	if run.Status.StartTime == nil {
		run.Status.StartTime = &now
	}
	run.Status.Phase = groma.PhaseFailed
	run.Status.CompletionTime = &now
	meta.SetStatusCondition(&run.Status.Conditions, metav1.Condition{
		Type: conditionComplete, Status: metav1.ConditionFalse,
		Reason: reason, Message: msg,
	})
	if err := ignoreConflict(r.Status().Update(ctx, run)); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func ignoreConflict(err error) error {
	if apierrors.IsConflict(err) {
		return nil
	}
	return err
}

func resolveModes(modes []groma.Mode) (active, static bool, err error) {
	for _, m := range modes {
		switch m {
		case groma.ModeActive:
			active = true
		case groma.ModeStatic:
			static = true
		default:
			return false, false, fmt.Errorf("unknown mode %q", m)
		}
	}
	if !active && !static {
		active = true
	}
	return active, static, nil
}

func (r *ConformanceRunReconciler) collect(ctx context.Context, active, static bool, pr *prober.Prober, checks []prober.Check) ([]evidence.Probe, error) {
	if !static {
		return pr.ProbeChecks(ctx, checks), nil
	}
	an, err := analyzer.New(ctx, r.Clientset, r.PolicyClient)
	if err != nil {
		return nil, err
	}
	cfg := an.Analyze(checks)
	if !active {
		return reconcile.StaticProbes(checks, cfg), nil
	}
	runtimeProbes := pr.ProbeChecks(ctx, checks)
	return reconcile.Reconcile(checks, runtimeProbes, cfg), nil
}

func (r *ConformanceRunReconciler) buildEvidence(ctx context.Context, si *intent.SegmentationIntent, run *groma.ConformanceRun, report *evidence.Report) (map[string]string, *metav1.Condition, error) {
	stmt, err := attest.BuildStatement(report, si, attest.Meta{GromaVersion: version.Version, ClusterID: r.ClusterID})
	if err != nil {
		return nil, nil, err
	}
	stmtBytes, err := stmt.Marshal()
	if err != nil {
		return nil, nil, err
	}
	var html bytes.Buffer
	if err := reportpkg.RenderHTML(&html, stmt); err != nil {
		return nil, nil, err
	}
	files := map[string]string{
		statementDataKey: string(stmtBytes),
		htmlDataKey:      html.String(),
	}

	ep := run.Spec.Evidence
	if ep == nil || !ep.Sign {
		return files, nil, nil
	}

	res, err := r.sign(ctx, ep, stmtBytes)
	if err != nil {
		return files, &metav1.Condition{
			Type: conditionAttestationSigned, Status: metav1.ConditionFalse,
			Reason: "SignError", Message: err.Error(),
		}, nil
	}
	files[attestationDataKey] = string(res.Envelope)
	if len(res.CertChainPEM) > 0 {
		files[certDataKey] = string(res.CertChainPEM)
	}
	msg := "attestation signed and stored"
	if res.RekorLogIndex != 0 {
		msg = fmt.Sprintf("attestation signed and recorded in Rekor at log index %d", res.RekorLogIndex)
	}
	return files, &metav1.Condition{
		Type: conditionAttestationSigned, Status: metav1.ConditionTrue,
		Reason: "Signed", Message: msg,
	}, nil
}

func (r *ConformanceRunReconciler) sign(ctx context.Context, ep *groma.EvidencePolicy, statement []byte) (*attest.SignResult, error) {
	newSigner := r.NewSigner
	if newSigner == nil {
		newSigner = defaultSigner
	}
	signer, err := newSigner(ctx, ep)
	if err != nil {
		return nil, err
	}
	return signer.Sign(ctx, statement)
}

func defaultSigner(ctx context.Context, ep *groma.EvidencePolicy) (attest.Signer, error) {
	switch {
	case ep.Keyless:
		return attest.NewKeylessSigner(attest.KeylessOptions{UploadTLog: true}), nil
	case ep.KeyRef != "":
		return attest.NewKeySigner(ctx, ep.KeyRef)
	default:
		return nil, fmt.Errorf("evidence.sign is set but neither keyless nor keyRef is configured")
	}
}

func modeLabel(active, static bool) string {
	switch {
	case active && static:
		return "active+static"
	case static:
		return "static"
	default:
		return "active"
	}
}

func proberOptions(ps *groma.ProbeStrategy) prober.Options {
	if ps == nil {
		return prober.Options{}
	}
	return prober.Options{
		MaxConcurrentProbes: int(ps.MaxConcurrentProbes),
		Image:               ps.Image,
		Retries:             int(ps.Retries),
	}
}

func countResults(status *groma.ConformanceRunStatus, probes []evidence.Probe) {
	for _, p := range probes {
		switch p.Result {
		case evidence.Pass:
			status.AssertionsPassed++
		case evidence.Fail:
			status.AssertionsFailed++
		case evidence.Indeterminate, evidence.Error:
			status.AssertionsIndeterminate++
		}
	}
}

func setSoundCondition(status *groma.ConformanceRunStatus, report *evidence.Report) {
	unsound := false
	for _, p := range report.Probes {
		if p.Result == evidence.Indeterminate || p.Result == evidence.Error {
			unsound = true
			break
		}
	}
	cond := metav1.Condition{Type: conditionSound, Status: metav1.ConditionTrue,
		Reason: "AllAttributable", Message: "every non-pass result was attributable to policy"}
	if unsound {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "Indeterminate"
		cond.Message = "one or more probes could not be attributed to policy; see the evidence configmap for detail"
	}
	meta.SetStatusCondition(&status.Conditions, cond)
}

func setEnforcementCondition(status *groma.ConformanceRunStatus, report *evidence.Report) {
	if report.EnforcementMatchesConfig == nil {
		return
	}
	cond := metav1.Condition{Type: conditionEnforcementMatchesConfig, Status: metav1.ConditionTrue,
		Reason: "Consistent", Message: "runtime enforcement matched the policy configuration on every reconciled path"}
	if !*report.EnforcementMatchesConfig {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "ConfigDrift"
		for _, p := range report.Probes {
			if p.Reconciliation == reconcile.CellEnforcementGap {
				cond.Reason = "EnforcementGap"
				break
			}
		}
		cond.Message = report.EnforcementDetail
	}
	meta.SetStatusCondition(&status.Conditions, cond)
}

func (r *ConformanceRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&groma.ConformanceRun{}).
		WithOptions(ctrlcontroller.Options{MaxConcurrentReconciles: 4}).
		Complete(r)
}
