package intent

import "testing"

func base() *SegmentationIntent {
	return &SegmentationIntent{
		Kind: "SegmentationIntent",
		Zones: []Zone{
			{Name: "a", Namespace: "ns-a"},
			{Name: "b", Namespace: "ns-b"},
		},
		Assertions: []Assertion{
			{From: "a", To: "b", Type: MustNotReach, Ports: []Port{{Protocol: TCP, Port: 5432}}},
		},
	}
}

func TestValidateOK(t *testing.T) {
	if err := base().validate(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func TestValidateZoneNamespaceExclusivity(t *testing.T) {
	cases := map[string]Zone{
		"neither namespace nor selector": {Name: "a"},
		"both namespace and selector": {
			Name: "a", Namespace: "ns-a",
			NamespaceSelector: &LabelSelector{MatchLabels: map[string]string{"k": "v"}},
		},
		"selector with empty matchLabels": {
			Name: "a", NamespaceSelector: &LabelSelector{},
		},
		"both podLabels and podSelector": {
			Name: "a", Namespace: "ns-a",
			PodLabels:   map[string]string{"app": "x"},
			PodSelector: &LabelSelector{MatchLabels: map[string]string{"app": "x"}},
		},
	}
	for name, z := range cases {
		si := base()
		si.Zones[0] = z
		if err := si.validate(); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestValidateDuplicateZone(t *testing.T) {
	si := base()
	si.Zones[1].Name = "a"
	if err := si.validate(); err == nil {
		t.Fatal("expected duplicate-zone error")
	}
}

func TestValidateMayReachOnly(t *testing.T) {
	si := base()
	si.Assertions[0].Type = MayReachOnly
	if err := si.validate(); err != nil {
		t.Fatalf("MayReachOnly should be valid, got %v", err)
	}
}

func TestValidateSelectorZoneAccepted(t *testing.T) {
	si := base()
	si.Zones[0] = Zone{
		Name:              "a",
		NamespaceSelector: &LabelSelector{MatchLabels: map[string]string{"zone": "a"}},
		PodSelector:       &LabelSelector{MatchLabels: map[string]string{"app": "web"}},
	}
	if err := si.validate(); err != nil {
		t.Fatalf("selector zone should be valid, got %v", err)
	}
}

func TestIdentityLabels(t *testing.T) {
	z := Zone{PodLabels: map[string]string{"app": "db"}}
	if z.IdentityLabels()["app"] != "db" {
		t.Error("PodLabels should be identity")
	}
	z = Zone{PodSelector: &LabelSelector{MatchLabels: map[string]string{"app": "web"}}}
	if z.IdentityLabels()["app"] != "web" {
		t.Error("PodSelector should back identity when PodLabels absent")
	}
	empty := Zone{}
	if empty.IdentityLabels() != nil {
		t.Error("empty zone should have nil identity")
	}
}
