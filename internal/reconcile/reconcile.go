package reconcile

import (
	"fmt"

	"github.com/groma-sh/groma/internal/analyzer"
	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/prober"
)

const (
	CellConsistent     = "CONSISTENT"
	CellEnforcementGap = "ENFORCEMENT-GAP"
	CellConfigDrift    = "CONFIG-DRIFT"

	// ConfigUnknown is the Config value for a path no analysis engine could
	// decide, because a policy selecting one of the endpoints uses a construct
	// Groma does not model. It never reconciles, and it never passes.
	ConfigUnknown = "UNKNOWN"
)

func StaticProbes(checks []prober.Check, cfg []analyzer.ConfigResult) []evidence.Probe {
	out := make([]evidence.Probe, len(checks))
	for i, c := range checks {
		p := c.BaseProbe()
		r := cfg[i]
		if r.Err != nil {
			p.Result = evidence.Error
			p.Detail = "static analysis error: " + r.Err.Error()
			out[i] = p
			continue
		}
		annotateConfig(&p, r)
		if r.Unknown {
			// Static-only mode has no runtime signal to fall back on, so an
			// undecidable path is reported as exactly that rather than guessed
			// in either direction.
			p.Result = evidence.Indeterminate
			p.Detail = "policy config could not be decided: " + r.Reason
			out[i] = p
			continue
		}
		p.Config = configString(r.Allows)
		if r.Allows == c.ExpectReachable {
			p.Result = evidence.Pass
		} else {
			p.Result = evidence.Fail
			if c.ExpectReachable {
				p.Detail = "required path is DENIED by policy config"
			} else {
				p.Detail = "path that must be blocked is ALLOWED by policy config"
			}
		}
		out[i] = p
	}
	return out
}

func Reconcile(checks []prober.Check, runtime []evidence.Probe, cfg []analyzer.ConfigResult) []evidence.Probe {
	out := make([]evidence.Probe, len(runtime))
	for i := range runtime {
		p := runtime[i]
		r := cfg[i]
		if r.Err != nil {

			p.Detail = appendDetail(p.Detail, "static analysis error: "+r.Err.Error())
			out[i] = p
			continue
		}
		annotateConfig(&p, r)
		if r.Unknown {
			// The runtime half still stands on its own; only the config half is
			// missing, so the probe keeps its result and loses its 2x2 cell.
			p.Detail = appendDetail(p.Detail, "policy config could not be decided, so this path is not reconciled: "+r.Reason)
			out[i] = p
			continue
		}
		p.Config = configString(r.Allows)

		switch p.Result {
		case evidence.Error, evidence.Skipped, evidence.Indeterminate:
			out[i] = p
			continue
		}

		reachable := p.Observed == "REACHABLE"
		switch {
		case reachable == r.Allows:
			p.Reconciliation = CellConsistent
		case reachable && !r.Allows:
			p.Reconciliation = CellEnforcementGap
		default:
			p.Reconciliation = CellConfigDrift
		}

		switch p.Reconciliation {
		case CellEnforcementGap:
			p.Result = evidence.Fail
			p.Detail = fmt.Sprintf("enforcement gap: policy config DENIES this path but it is REACHABLE at runtime on tcp/%d", p.Port)
		case CellConfigDrift:
			if p.Result == evidence.Pass {
				p.Detail = "config drift: policy config ALLOWS this path; it is blocked only at runtime, so the block is not backed by your policy"
			}
		}
		out[i] = p
	}
	return out
}

// annotateConfig records which engine produced the config verdict and which
// policy rule it cited, whether or not the verdict itself is decidable.
func annotateConfig(p *evidence.Probe, r analyzer.ConfigResult) {
	p.ConfigSource = r.Source
	p.ConfigReason = r.Reason
	p.ConfigPolicies = r.Policies
	if r.Unknown {
		p.Config = ConfigUnknown
	}
}

func SetEnforcement(report *evidence.Report) {
	var reconciled, gap, drift bool
	for _, p := range report.Probes {
		switch p.Reconciliation {
		case CellConsistent:
			reconciled = true
		case CellEnforcementGap:
			reconciled, gap = true, true
		case CellConfigDrift:
			reconciled, drift = true, true
		}
	}
	if !reconciled {
		return
	}
	matches := !gap && !drift
	report.EnforcementMatchesConfig = &matches
	switch {
	case gap:
		report.EnforcementDetail = "runtime allows one or more paths your policy config denies (enforcement gap)"
	case drift:
		report.EnforcementDetail = "runtime blocks one or more paths your policy config allows (config drift / CNI over-block)"
	}
}

func configString(allows bool) string {
	if allows {
		return "ALLOWED"
	}
	return "DENIED"
}

func appendDetail(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}
