package evidence

import "testing"

func TestSummarize(t *testing.T) {
	cases := []struct {
		name   string
		in     []Result
		expect Result
	}{
		{"all pass", []Result{Pass, Pass}, Pass},
		{"fail dominates", []Result{Pass, Indeterminate, Fail}, Fail},
		{"indeterminate over pass", []Result{Pass, Indeterminate}, Indeterminate},
		{"error counts as indeterminate", []Result{Pass, Error}, Indeterminate},
		{"skipped ignored", []Result{Skipped, Pass}, Pass},
		{"all skipped", []Result{Skipped, Skipped}, Skipped},
		{"empty", nil, Skipped},
	}
	for _, c := range cases {
		r := &Report{}
		for _, res := range c.in {
			r.Probes = append(r.Probes, Probe{Result: res})
		}
		r.Summarize()
		if r.Result != c.expect {
			t.Errorf("%s: got %s, want %s", c.name, r.Result, c.expect)
		}
	}
}
