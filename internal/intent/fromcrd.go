package intent

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	groma "github.com/groma-sh/groma/api/v1alpha1"
)

func FromCRD(crd *groma.SegmentationIntent) (*SegmentationIntent, error) {
	zones := make([]Zone, len(crd.Spec.Zones))
	for i, z := range crd.Spec.Zones {
		nsSel, err := convertSelector(z.NamespaceSelector)
		if err != nil {
			return nil, fmt.Errorf("zone %q: namespaceSelector: %w", z.Name, err)
		}
		podSel, err := convertSelector(z.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("zone %q: podSelector: %w", z.Name, err)
		}
		zones[i] = Zone{
			Name:              z.Name,
			Namespace:         z.Namespace,
			NamespaceSelector: nsSel,
			PodSelector:       podSel,
		}
	}

	assertions := make([]Assertion, len(crd.Spec.Assertions))
	for i, a := range crd.Spec.Assertions {
		ports := make([]Port, len(a.Ports))
		for j, p := range a.Ports {
			ports[j] = Port{Protocol: Protocol(p.Protocol), Port: p.Port}
		}
		assertions[i] = Assertion{
			From:  a.From,
			To:    a.To,
			Type:  AssertionType(a.Type),
			Ports: ports,
		}
	}

	si := &SegmentationIntent{
		APIVersion: groma.GroupVersion.String(),
		Kind:       "SegmentationIntent",
		Metadata:   Meta{Name: crd.Name},
		Zones:      zones,
		Assertions: assertions,
		Compliance: Compliance{
			Framework: crd.Spec.Compliance.Framework,
			Controls:  crd.Spec.Compliance.Controls,
		},
	}
	if err := si.validate(); err != nil {
		return nil, err
	}
	return si, nil
}

func convertSelector(sel *metav1.LabelSelector) (*LabelSelector, error) {
	if sel == nil {
		return nil, nil
	}
	if len(sel.MatchExpressions) > 0 {
		return nil, fmt.Errorf("matchExpressions not supported yet, use matchLabels")
	}
	return &LabelSelector{MatchLabels: sel.MatchLabels}, nil
}
