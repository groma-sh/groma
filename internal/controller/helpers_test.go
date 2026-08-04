package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	groma "github.com/groma-sh/groma/api/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := groma.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func testIntent(name string) *groma.SegmentationIntent {
	return &groma.SegmentationIntent{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: groma.SegmentationIntentSpec{
			Zones: []groma.Zone{
				{Name: "cde", Namespace: "cde", PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments-db"}}},
			},
			Assertions: []groma.Assertion{
				{From: "cde", To: "cde", Type: groma.MustReach, Ports: []groma.Port{{Protocol: groma.ProtocolTCP, Port: 5432}}},
			},
		},
	}
}
