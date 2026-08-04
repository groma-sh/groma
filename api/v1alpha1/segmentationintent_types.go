package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Protocol string

const (
	ProtocolTCP Protocol = "TCP"
	ProtocolUDP Protocol = "UDP"
)

type Port struct {
	Protocol Protocol `json:"protocol"`
	Port     int32    `json:"port"`
}

// Workload set located by namespace name or namespaceSelector, with an optional
// podSelector (matchLabels only) giving the identity labels a prober must stamp.
type Zone struct {
	Name              string                `json:"name"`
	Namespace         string                `json:"namespace,omitempty"`
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	PodSelector       *metav1.LabelSelector `json:"podSelector,omitempty"`
}

type AssertionType string

const (
	MustNotReach AssertionType = "MustNotReach"
	MustReach    AssertionType = "MustReach"
	MayReachOnly AssertionType = "MayReachOnly"
)

type Assertion struct {
	From  string        `json:"from"`
	To    string        `json:"to"`
	Type  AssertionType `json:"type"`
	Ports []Port        `json:"ports"`
}

type Compliance struct {
	Framework string   `json:"framework,omitempty"`
	Controls  []string `json:"controls,omitempty"`
}

type SegmentationIntentSpec struct {
	Zones      []Zone      `json:"zones"`
	Assertions []Assertion `json:"assertions"`
	Compliance Compliance  `json:"compliance,omitempty"`
}

// Declares zones and connectivity assertions; cluster-scoped.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=si
type SegmentationIntent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec SegmentationIntentSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true
type SegmentationIntentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SegmentationIntent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SegmentationIntent{}, &SegmentationIntentList{})
}
