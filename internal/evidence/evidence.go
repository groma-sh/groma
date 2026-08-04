package evidence

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

type Result string

const (
	Pass          Result = "PASS"
	Fail          Result = "FAIL"
	Indeterminate Result = "INDETERMINATE"
	Error         Result = "ERROR"
	Skipped       Result = "SKIPPED"
)

type Probe struct {
	From            string `json:"from"`
	To              string `json:"to"`
	FromNamespace   string `json:"fromNamespace,omitempty"`
	ToNamespace     string `json:"toNamespace,omitempty"`
	Protocol        string `json:"protocol"`
	Port            int32  `json:"port"`
	Assertion       string `json:"assertion"`
	Observed        string `json:"observed,omitempty"`
	PositiveControl string `json:"positiveControl,omitempty"`
	Config          string `json:"config,omitempty"`
	Reconciliation  string `json:"reconciliation,omitempty"`
	Result          Result `json:"result"`
	Detail          string `json:"detail,omitempty"`
}

type ResolvedZone struct {
	Name           string            `json:"name"`
	Namespace      string            `json:"namespace"`
	Namespaces     []string          `json:"namespaces,omitempty"`
	IdentityLabels map[string]string `json:"identityLabels,omitempty"`
}

type Report struct {
	Intent    string   `json:"intent"`
	Framework string   `json:"framework,omitempty"`
	Controls  []string `json:"controls,omitempty"`

	Mode       string    `json:"mode,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Result     Result    `json:"result"`

	EnforcementMatchesConfig *bool          `json:"enforcementMatchesConfig,omitempty"`
	EnforcementDetail        string         `json:"enforcementDetail,omitempty"`
	Zones                    []ResolvedZone `json:"zones,omitempty"`
	Probes                   []Probe        `json:"probes"`
}

func (r *Report) Summarize() {
	var hasReal, hasFail, hasIndet bool
	for _, p := range r.Probes {
		if p.Result == Skipped {
			continue
		}
		hasReal = true
		switch p.Result {
		case Fail:
			hasFail = true
		case Indeterminate, Error:
			hasIndet = true
		}
	}
	switch {
	case !hasReal:
		r.Result = Skipped
	case hasFail:
		r.Result = Fail
	case hasIndet:
		r.Result = Indeterminate
	default:
		r.Result = Pass
	}
}

func (r *Report) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func (r *Report) RenderText(w io.Writer) {
	fmt.Fprintf(w, "\nGroma segmentation conformance: %s\n", r.Result)
	line := "intent: " + r.Intent
	if r.Mode != "" {
		line += "   mode: " + r.Mode
	}
	if r.Framework != "" {
		line += "   framework: " + r.Framework
		if len(r.Controls) > 0 {
			line += " (" + strings.Join(r.Controls, ", ") + ")"
		}
	}
	fmt.Fprintln(w, line)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  RESULT\tPATH\tASSERTION\tPORT\tCONFIG\tOBSERVED\tRECONCILE")
	counts := map[Result]int{}
	for _, p := range r.Probes {
		counts[p.Result]++
		fmt.Fprintf(tw, "  %s\t%s -> %s\t%s\ttcp/%d\t%s\t%s\t%s\n",
			p.Result, p.From, p.To, p.Assertion, p.Port, dash(p.Config), dash(p.Observed), dash(p.Reconciliation))
	}
	tw.Flush()

	fmt.Fprintf(w, "  %d passed, %d failed, %d indeterminate, %d error",
		counts[Pass], counts[Fail], counts[Indeterminate], counts[Error])
	if counts[Skipped] > 0 {
		fmt.Fprintf(w, ", %d planned", counts[Skipped])
	}
	fmt.Fprintln(w)

	if r.EnforcementMatchesConfig != nil {
		status := "yes"
		if !*r.EnforcementMatchesConfig {
			status = "NO - " + r.EnforcementDetail
		}
		fmt.Fprintf(w, "  runtime enforcement matches policy config: %s\n", status)
	}

	for _, p := range r.Probes {
		if p.Result != Pass && p.Result != Skipped && p.Detail != "" {
			fmt.Fprintf(w, "  ! %s -> %s tcp/%d: %s\n", p.From, p.To, p.Port, p.Detail)
		}
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
