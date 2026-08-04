package prober

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/groma-sh/groma/internal/intent"
)

func ns(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

func TestResolveZoneExactNamespace(t *testing.T) {
	p := New(fake.NewSimpleClientset(ns("cde", nil)), Options{})
	rz, err := p.resolveZone(context.Background(), &intent.Zone{Name: "cde", Namespace: "cde"})
	if err != nil {
		t.Fatal(err)
	}
	if rz.namespace != "cde" || len(rz.namespaces) != 1 {
		t.Fatalf("got %+v", rz)
	}
}

func TestResolveZoneMissingNamespace(t *testing.T) {
	p := New(fake.NewSimpleClientset(), Options{})
	if _, err := p.resolveZone(context.Background(), &intent.Zone{Name: "cde", Namespace: "cde"}); err == nil {
		t.Fatal("expected error for missing namespace")
	}
}

func TestResolveZoneSelectorRepresentativeIsSorted(t *testing.T) {
	p := New(fake.NewSimpleClientset(
		ns("team-b-cde", map[string]string{"zone": "cde"}),
		ns("team-a-cde", map[string]string{"zone": "cde"}),
		ns("other", map[string]string{"zone": "frontend"}),
	), Options{})
	z := &intent.Zone{Name: "cde", NamespaceSelector: &intent.LabelSelector{MatchLabels: map[string]string{"zone": "cde"}}}
	rz, err := p.resolveZone(context.Background(), z)
	if err != nil {
		t.Fatal(err)
	}
	if rz.namespace != "team-a-cde" {
		t.Errorf("representative should be lexically first match, got %q", rz.namespace)
	}
	if len(rz.namespaces) != 2 {
		t.Errorf("selector should match exactly 2 namespaces, got %v", rz.namespaces)
	}
}

func TestResolveZoneSelectorNoMatch(t *testing.T) {
	p := New(fake.NewSimpleClientset(ns("x", map[string]string{"zone": "frontend"})), Options{})
	z := &intent.Zone{Name: "cde", NamespaceSelector: &intent.LabelSelector{MatchLabels: map[string]string{"zone": "cde"}}}
	if _, err := p.resolveZone(context.Background(), z); err == nil {
		t.Fatal("expected error when selector matches no namespace")
	}
}
