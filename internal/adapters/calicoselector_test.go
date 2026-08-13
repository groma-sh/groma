package adapters

import (
	"testing"

	"k8s.io/apimachinery/pkg/labels"
)

func TestParseCalicoSelector(t *testing.T) {
	set := labels.Set{"app": "web", "tier": "frontend", "projectcalico.org/namespace": "cde"}
	cases := []struct {
		selector string
		want     bool
	}{
		{"", true},
		{"all()", true},
		{"global()", false},
		{"app == 'web'", true},
		{`app == "web"`, true},
		{"app == 'db'", false},
		{"app != 'db'", true},
		{"has(app)", true},
		{"has(missing)", false},
		{"!has(missing)", true},
		{"app in {'web','worker'}", true},
		{"app in {'db'}", false},
		{"app not in {'db'}", true},
		{"app == 'web' && tier == 'frontend'", true},
		{"app == 'db' && tier == 'frontend'", false},
		{"app == 'db' || tier == 'frontend'", true},
		{"(app == 'db' || tier == 'frontend') && has(app)", true},
		{"projectcalico.org/namespace == 'cde'", true},
		{"!(app == 'db')", true},
	}
	for _, tc := range cases {
		got, err := evalCalicoSelector(tc.selector, set)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.selector, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q = %v, want %v", tc.selector, got, tc.want)
		}
	}
}

func TestParseCalicoSelector_UnsupportedIsAnError(t *testing.T) {
	// Anything outside the modeled subset must fail loudly, because the caller
	// turns the error into Unknown rather than a guessed match.
	for _, selector := range []string{
		"app contains 'we'",
		"app starts with 'we'",
		"app == ",
		"app in {'web'",
		"(app == 'web'",
		"app == 'web' &&",
	} {
		if _, err := parseCalicoSelector(selector); err == nil {
			t.Errorf("%q parsed without error, but it is outside the modeled subset", selector)
		}
	}
}

func TestParseCalicoSelector_KeywordPrefixesAreNotOperators(t *testing.T) {
	// "notch" and "install" begin with "not" and "in"; neither is an operator.
	set := labels.Set{"notch": "a", "install": "b"}
	for _, selector := range []string{"notch == 'a'", "install == 'b'"} {
		got, err := evalCalicoSelector(selector, set)
		if err != nil {
			t.Fatalf("%q: %v", selector, err)
		}
		if !got {
			t.Errorf("%q should match", selector)
		}
	}
}
