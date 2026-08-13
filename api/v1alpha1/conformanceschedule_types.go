package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Mode: "active" (probe), "static" (analyze), or both (reconcile). Empty defaults to ["active"].
type Mode string

const (
	ModeActive Mode = "active"
	ModeStatic Mode = "static"
)

type IntentRef struct {
	Name string `json:"name"`
}

// ProbeStrategy mirrors internal/prober.Options.
type ProbeStrategy struct {
	MaxConcurrentProbes int32  `json:"maxConcurrentProbes,omitempty"`
	Image               string `json:"image,omitempty"`
	Retries             int32  `json:"retries,omitempty"`
}

// EvidenceSink publishes a run's evidence outside the cluster it audits, so the
// artifact survives the namespace and cannot be rewritten by the cluster under
// test. The bytes published are the same ones stored in the evidence ConfigMap,
// so a signature verifies identically from either.
type EvidenceSink struct {
	// Type selects the backend.
	// +kubebuilder:validation:Enum=oci;s3;gcs;file
	Type string `json:"type"`
	// Repo is the OCI repository, without a tag, for type "oci"
	// (for example "registry.example.com/groma/evidence").
	Repo string `json:"repo,omitempty"`
	// Bucket is the object-storage bucket for types "s3" and "gcs".
	Bucket string `json:"bucket,omitempty"`
	// Prefix is the key prefix objects are written under; each run gets its own
	// directory beneath it.
	Prefix string `json:"prefix,omitempty"`
	// Region is the AWS region for type "s3"; when empty the ambient AWS
	// configuration supplies it.
	Region string `json:"region,omitempty"`
	// Path is the directory for type "file", typically a mounted volume.
	Path string `json:"path,omitempty"`
}

type EvidencePolicy struct {
	// How long to keep runs and evidence; empty keeps forever.
	Retain string `json:"retain,omitempty"`
	// Where to publish evidence in addition to the in-cluster ConfigMap. A
	// failed publish never fails the run: the conformance result is already
	// determined by then, and losing it to a registry outage would be worse
	// than an unpublished artifact.
	Sink *EvidenceSink `json:"sink,omitempty"`
	// Enable in-toto attestation signing; when false, only statement and HTML are stored.
	Sign bool `json:"sign,omitempty"`
	// Sign via Sigstore (Fulcio + Rekor); when false, KeyRef must be set.
	Keyless bool `json:"keyless,omitempty"`
	// Cosign key reference (KMS URI or in-cluster secret) when not Keyless.
	KeyRef string `json:"keyRef,omitempty"`
}

type ConformanceScheduleSpec struct {
	IntentRef IntentRef `json:"intentRef"`
	// Standard 5-field cron expression.
	Schedule string `json:"schedule"`
	// Mode defaults to ["active"] when empty. List both to reconcile config vs runtime.
	Mode          []Mode          `json:"mode,omitempty"`
	ProbeStrategy *ProbeStrategy  `json:"probeStrategy,omitempty"`
	Evidence      *EvidencePolicy `json:"evidence,omitempty"`
}

type ConformanceScheduleStatus struct {
	LastScheduleTime *metav1.Time       `json:"lastScheduleTime,omitempty"`
	LastRunRef       string             `json:"lastRunRef,omitempty"`
	Conditions       []metav1.Condition `json:"conditions,omitempty"`
}

// Runs a SegmentationIntent on a cron schedule, creating a ConformanceRun per tick.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cs
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`
// +kubebuilder:printcolumn:name="Last Run",type=string,JSONPath=`.status.lastRunRef`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ConformanceSchedule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConformanceScheduleSpec   `json:"spec,omitempty"`
	Status ConformanceScheduleStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ConformanceScheduleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConformanceSchedule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConformanceSchedule{}, &ConformanceScheduleList{})
}
