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
