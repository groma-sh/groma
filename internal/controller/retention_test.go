package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	groma "github.com/groma-sh/groma/api/v1alpha1"
)

func TestParseRetain(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{in: "", want: 0},
		{in: "400d", want: 400 * 24 * time.Hour},
		{in: "720h", want: 720 * time.Hour},
		{in: "0d", wantErr: true},
		{in: "-5d", wantErr: true},
		{in: "not-a-duration", wantErr: true},
	}
	for _, c := range cases {
		got, err := parseRetain(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseRetain(%q): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRetain(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseRetain(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRunsToPrune(t *testing.T) {
	now := time.Now()
	completedAt := func(ago time.Duration) *metav1.Time {
		t := metav1.NewTime(now.Add(-ago))
		return &t
	}
	runs := []groma.ConformanceRun{
		{ObjectMeta: metav1.ObjectMeta{Name: "old"}, Status: groma.ConformanceRunStatus{CompletionTime: completedAt(48 * time.Hour)}},
		{ObjectMeta: metav1.ObjectMeta{Name: "recent"}, Status: groma.ConformanceRunStatus{CompletionTime: completedAt(1 * time.Hour)}},
		{ObjectMeta: metav1.ObjectMeta{Name: "in-progress"}},
	}

	got := runsToPrune(runs, 24*time.Hour, now)
	if len(got) != 1 || got[0] != "old" {
		t.Fatalf("runsToPrune = %v, want [old]", got)
	}

	if got := runsToPrune(runs, 0, now); got != nil {
		t.Fatalf("zero retain should prune nothing, got %v", got)
	}
}
