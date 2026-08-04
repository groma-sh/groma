package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RunPhase string

const (
	PhasePending   RunPhase = "Pending"
	PhaseRunning   RunPhase = "Running"
	PhaseCompleted RunPhase = "Completed"
	PhaseFailed    RunPhase = "Failed"
)

// Result mirrors internal/evidence.Result.
type Result string

const (
	ResultPass          Result = "PASS"
	ResultFail          Result = "FAIL"
	ResultIndeterminate Result = "INDETERMINATE"
	ResultError         Result = "ERROR"
	ResultSkipped       Result = "SKIPPED"
)

type ConformanceRunSpec struct {
	IntentRef IntentRef `json:"intentRef"`
	// Mode defaults to ["active"] when empty. List both to reconcile config vs runtime.
	Mode []Mode `json:"mode,omitempty"`
	// Carries the schedule's strategy down to the run so it is self-contained.
	ProbeStrategy *ProbeStrategy `json:"probeStrategy,omitempty"`
	// Attestation signing; copied from the schedule, Retain ignored here.
	Evidence *EvidencePolicy `json:"evidence,omitempty"`
}

type ConformanceRunStatus struct {
	Phase                   RunPhase `json:"phase,omitempty"`
	Result                  Result   `json:"result,omitempty"`
	AssertionsPassed        int32    `json:"assertionsPassed,omitempty"`
	AssertionsFailed        int32    `json:"assertionsFailed,omitempty"`
	AssertionsIndeterminate int32    `json:"assertionsIndeterminate,omitempty"`
	// ConfigMap (in the manager's namespace) holding the full JSON evidence report.
	EvidenceRef    string       `json:"evidenceRef,omitempty"`
	StartTime      *metav1.Time `json:"startTime,omitempty"`
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
	// "Complete", "Sound", and "EnforcementMatchesConfig" (False = enforcement gap).
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// A single execution of an intent's assertions, run once.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=cr
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Result",type=string,JSONPath=`.status.result`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type ConformanceRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConformanceRunSpec   `json:"spec,omitempty"`
	Status ConformanceRunStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ConformanceRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConformanceRun `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConformanceRun{}, &ConformanceRunList{})
}
