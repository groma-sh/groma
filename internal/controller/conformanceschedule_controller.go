package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	groma "github.com/groma-sh/groma/api/v1alpha1"
)

const (
	scheduleLabel  = "groma.dev/schedule"
	conditionValid = "Valid"
)

type ConformanceScheduleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *ConformanceScheduleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var sched groma.ConformanceSchedule
	if err := r.Get(ctx, req.NamespacedName, &sched); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if invalid := r.invalidate(ctx, &sched); invalid {
		return ctrl.Result{}, nil
	}

	cronSchedule, err := cron.ParseStandard(sched.Spec.Schedule)
	if err != nil {
		return ctrl.Result{}, r.setInvalid(ctx, &sched, "InvalidSchedule", err.Error())
	}

	now := time.Now()
	from := sched.CreationTimestamp.Time
	if sched.Status.LastScheduleTime != nil {
		from = sched.Status.LastScheduleTime.Time
	}
	next := cronSchedule.Next(from)

	if !next.After(now) {
		runName, err := r.createRun(ctx, &sched)
		if err != nil {
			return ctrl.Result{}, err
		}
		scheduled := metav1.NewTime(now)
		sched.Status.LastScheduleTime = &scheduled
		sched.Status.LastRunRef = runName
		meta.SetStatusCondition(&sched.Status.Conditions, metav1.Condition{
			Type: conditionValid, Status: metav1.ConditionTrue,
			Reason: "Scheduled", Message: fmt.Sprintf("created run %s", runName),
		})
		if err := ignoreConflict(r.Status().Update(ctx, &sched)); err != nil {
			return ctrl.Result{}, err
		}
		logger.Info("created conformance run", "schedule", sched.Name, "run", runName)
		next = cronSchedule.Next(now)
	}

	if err := r.pruneOldRuns(ctx, &sched, now); err != nil {

		logger.Error(err, "failed to prune old runs", "schedule", sched.Name)
	}

	return ctrl.Result{RequeueAfter: next.Sub(now)}, nil
}

func (r *ConformanceScheduleReconciler) invalidate(ctx context.Context, sched *groma.ConformanceSchedule) bool {
	if _, _, err := resolveModes(sched.Spec.Mode); err != nil {
		_ = r.setInvalid(ctx, sched, "InvalidMode", err.Error())
		return true
	}
	return false
}

func (r *ConformanceScheduleReconciler) setInvalid(ctx context.Context, sched *groma.ConformanceSchedule, reason, msg string) error {
	meta.SetStatusCondition(&sched.Status.Conditions, metav1.Condition{
		Type: conditionValid, Status: metav1.ConditionFalse, Reason: reason, Message: msg,
	})
	return r.Status().Update(ctx, sched)
}

func (r *ConformanceScheduleReconciler) createRun(ctx context.Context, sched *groma.ConformanceSchedule) (string, error) {
	run := &groma.ConformanceRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: sched.Name + "-",
			Labels: map[string]string{
				managedByLabel: managedByValue,
				scheduleLabel:  sched.Name,
			},
		},
		Spec: groma.ConformanceRunSpec{
			IntentRef:     sched.Spec.IntentRef,
			Mode:          sched.Spec.Mode,
			ProbeStrategy: sched.Spec.ProbeStrategy,
			Evidence:      sched.Spec.Evidence,
		},
	}
	if err := controllerutil.SetControllerReference(sched, run, r.Scheme); err != nil {
		return "", fmt.Errorf("set owner reference: %w", err)
	}
	if err := r.Create(ctx, run); err != nil {
		return "", fmt.Errorf("create run: %w", err)
	}
	return run.Name, nil
}

func (r *ConformanceScheduleReconciler) pruneOldRuns(ctx context.Context, sched *groma.ConformanceSchedule, now time.Time) error {
	if sched.Spec.Evidence == nil || sched.Spec.Evidence.Retain == "" {
		return nil
	}
	retain, err := parseRetain(sched.Spec.Evidence.Retain)
	if err != nil {
		return err
	}
	var runs groma.ConformanceRunList
	if err := r.List(ctx, &runs, client.MatchingLabels{scheduleLabel: sched.Name}); err != nil {
		return err
	}
	for _, name := range runsToPrune(runs.Items, retain, now) {
		run := &groma.ConformanceRun{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if err := r.Delete(ctx, run); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (r *ConformanceScheduleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&groma.ConformanceSchedule{}).
		Owns(&groma.ConformanceRun{}).
		Complete(r)
}
