package intent

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	groma "github.com/groma-sh/groma/api/v1alpha1"
)

func TestFromCRD(t *testing.T) {
	crd := &groma.SegmentationIntent{
		ObjectMeta: metav1.ObjectMeta{Name: "pci-cde"},
		Spec: groma.SegmentationIntentSpec{
			Zones: []groma.Zone{
				{Name: "frontend", Namespace: "frontend", PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
				{Name: "cde", NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"pci-scope": "cde"}}},
			},
			Assertions: []groma.Assertion{
				{From: "frontend", To: "cde", Type: groma.MustNotReach, Ports: []groma.Port{{Protocol: groma.ProtocolTCP, Port: 5432}}},
			},
			Compliance: groma.Compliance{Framework: "PCI-DSS-4.0", Controls: []string{"11.4.5"}},
		},
	}

	si, err := FromCRD(crd)
	if err != nil {
		t.Fatal(err)
	}
	if si.Kind != "SegmentationIntent" || si.Metadata.Name != "pci-cde" {
		t.Fatalf("got %+v", si)
	}
	if len(si.Zones) != 2 || si.Zones[0].PodSelector == nil || si.Zones[0].PodSelector.MatchLabels["app"] != "web" {
		t.Fatalf("podSelector conversion wrong: %+v", si.Zones)
	}
	if si.Zones[1].NamespaceSelector == nil || si.Zones[1].NamespaceSelector.MatchLabels["pci-scope"] != "cde" {
		t.Fatalf("namespaceSelector conversion wrong: %+v", si.Zones[1])
	}
	if len(si.Assertions) != 1 || si.Assertions[0].Type != MustNotReach {
		t.Fatalf("assertion conversion wrong: %+v", si.Assertions)
	}
	if si.Compliance.Framework != "PCI-DSS-4.0" {
		t.Fatalf("compliance conversion wrong: %+v", si.Compliance)
	}
}

func TestFromCRDRejectsMatchExpressions(t *testing.T) {
	crd := &groma.SegmentationIntent{
		ObjectMeta: metav1.ObjectMeta{Name: "x"},
		Spec: groma.SegmentationIntentSpec{
			Zones: []groma.Zone{
				{Name: "a", NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "env", Operator: metav1.LabelSelectorOpExists}},
				}},
				{Name: "b", Namespace: "b"},
			},
			Assertions: []groma.Assertion{
				{From: "a", To: "b", Type: groma.MustReach, Ports: []groma.Port{{Protocol: groma.ProtocolTCP, Port: 80}}},
			},
		},
	}
	if _, err := FromCRD(crd); err == nil {
		t.Fatal("expected error for matchExpressions")
	}
}

func TestFromCRDInvalidPropagatesFromValidate(t *testing.T) {
	crd := &groma.SegmentationIntent{
		ObjectMeta: metav1.ObjectMeta{Name: "x"},
		Spec: groma.SegmentationIntentSpec{
			Zones: []groma.Zone{{Name: "a", Namespace: "a"}},
			Assertions: []groma.Assertion{
				{From: "a", To: "missing", Type: groma.MustReach, Ports: []groma.Port{{Protocol: groma.ProtocolTCP, Port: 80}}},
			},
		},
	}
	if _, err := FromCRD(crd); err == nil {
		t.Fatal("expected validation error for unknown to-zone")
	}
}
