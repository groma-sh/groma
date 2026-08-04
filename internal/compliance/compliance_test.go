package compliance

import "testing"

func TestMap(t *testing.T) {
	cases := []struct {
		framework string
		assertion string
		wantIDs   []string
	}{
		{"PCI-DSS-4.0", "MustNotReach", []string{"11.4.5", "1.3.1"}},
		{"PCI-DSS-4.0", "MayReachOnly", []string{"11.4.5", "1.3.1"}},
		{"pci-dss-4.0", "MustNotReach", []string{"11.4.5", "1.3.1"}},
		{"PCI-DSS-4.0", "MustReach", nil},
		{"HIPAA", "MustNotReach", nil},
		{"", "MustNotReach", nil},
	}
	for _, c := range cases {
		got := Map(c.framework, c.assertion)
		if len(got) != len(c.wantIDs) {
			t.Errorf("Map(%q,%q): got %d controls, want %d", c.framework, c.assertion, len(got), len(c.wantIDs))
			continue
		}
		for i, ctrl := range got {
			if ctrl.ID != c.wantIDs[i] {
				t.Errorf("Map(%q,%q)[%d]: got id %q, want %q", c.framework, c.assertion, i, ctrl.ID, c.wantIDs[i])
			}
			if ctrl.Title == "" || ctrl.Rationale == "" {
				t.Errorf("Map(%q,%q)[%d]: empty title or rationale", c.framework, c.assertion, i)
			}
		}
	}
}

func TestControls(t *testing.T) {
	got := Controls("PCI-DSS-4.0")
	want := []string{"1.3.1", "11.4.5"}
	if len(got) != len(want) {
		t.Fatalf("Controls: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Controls: got %v, want %v", got, want)
		}
	}
	if Controls("nope") != nil {
		t.Errorf("Controls(unknown): expected nil")
	}
}
