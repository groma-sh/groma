package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	groma "github.com/groma-sh/groma/api/v1alpha1"
	"github.com/groma-sh/groma/internal/evidence"
)

const (
	managedByLabel     = "app.kubernetes.io/managed-by"
	managedByValue     = "groma"
	runLabel           = "groma.dev/run"
	evidenceDataKey    = "evidence.json"
	summaryDataKey     = "summary.txt"
	statementDataKey   = "statement.json"
	htmlDataKey        = "report.html"
	attestationDataKey = "attestation.json"
	certDataKey        = "attestation.pem"
)

func evidenceConfigMapName(runName string) string {
	return runName + "-evidence"
}

// evidenceFiles assembles the run's evidence bundle. The ConfigMap and every
// sink publish this exact map, so an artifact fetched from a registry verifies
// against the same signature as the copy in the cluster.
func evidenceFiles(report *evidence.Report, extra map[string]string) (map[string]string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal evidence: %w", err)
	}
	var summary strings.Builder
	report.RenderText(&summary)

	files := map[string]string{
		evidenceDataKey: string(data),
		summaryDataKey:  summary.String(),
	}
	for k, v := range extra {
		files[k] = v
	}
	return files, nil
}

func writeEvidenceConfigMap(ctx context.Context, c client.Client, scheme *runtime.Scheme, ns string, run *groma.ConformanceRun, cmData map[string]string) (string, error) {
	name := evidenceConfigMapName(run.Name)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				managedByLabel: managedByValue,
				runLabel:       run.Name,
			},
		},
		Data: cmData,
	}
	if err := controllerutil.SetControllerReference(run, cm, scheme); err != nil {
		return "", fmt.Errorf("set owner reference: %w", err)
	}

	if err := c.Create(ctx, cm); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", fmt.Errorf("create evidence configmap: %w", err)
	}
	return name, nil
}
