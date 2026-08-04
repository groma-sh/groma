// Package v1alpha1 contains the groma.dev/v1alpha1 API: SegmentationIntent,
// ConformanceSchedule, and ConformanceRun.
// +kubebuilder:object:generate=true
// +groupName=groma.dev
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion = schema.GroupVersion{Group: "groma.dev", Version: "v1alpha1"}

	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	AddToScheme = SchemeBuilder.AddToScheme
)
