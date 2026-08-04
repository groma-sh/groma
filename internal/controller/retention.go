package controller

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	groma "github.com/groma-sh/groma/api/v1alpha1"
)

func parseRetain(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid retention %q: expected a positive day count before 'd'", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid retention %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid retention %q: must be positive", s)
	}
	return d, nil
}

func runsToPrune(runs []groma.ConformanceRun, retain time.Duration, now time.Time) []string {
	if retain <= 0 {
		return nil
	}
	cutoff := now.Add(-retain)
	var names []string
	for _, r := range runs {
		if r.Status.CompletionTime == nil {
			continue
		}
		if r.Status.CompletionTime.Time.Before(cutoff) {
			names = append(names, r.Name)
		}
	}
	return names
}
