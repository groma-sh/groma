package report

import (
	"html/template"
	"io"
	"time"

	"github.com/groma-sh/groma/internal/attest"
)

type view struct {
	Intent             string
	SubjectName        string
	SubjectDigest      string
	Predicate          attest.Predicate
	Duration           string
	EnforcementChecked bool
	EnforcementMatches bool
}

func RenderHTML(w io.Writer, stmt *attest.Statement) error {
	v := view{
		Intent:    stmt.Predicate.Intent,
		Predicate: stmt.Predicate,
		Duration:  stmt.Predicate.FinishedAt.Sub(stmt.Predicate.StartedAt).Round(time.Millisecond).String(),
	}
	if e := stmt.Predicate.EnforcementMatchesConfig; e != nil {
		v.EnforcementChecked = true
		v.EnforcementMatches = *e
	}
	if len(stmt.Subject) > 0 {
		v.SubjectName = stmt.Subject[0].Name
		v.SubjectDigest = stmt.Subject[0].Digest["sha256"]
	}
	return htmlTemplate.Execute(w, v)
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"utc":       func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 MST") },
	"badge":     badgeClass,
	"tristate":  tristate,
	"reconcile": reconcileBadge,
}).Parse(htmlSource))

func badgeClass(result string) string {
	switch result {
	case "PASS":
		return "pass"
	case "FAIL":
		return "fail"
	case "INDETERMINATE", "ERROR":
		return "warn"
	default:
		return "muted"
	}
}

func tristate(b *bool) string {
	switch {
	case b == nil:
		return "-"
	case *b:
		return "ALLOWED"
	default:
		return "DENIED"
	}
}

func reconcileBadge(cell string) string {
	switch cell {
	case "ENFORCEMENT-GAP":
		return "fail"
	case "CONFIG-DRIFT":
		return "warn"
	case "CONSISTENT":
		return "pass"
	default:
		return "muted"
	}
}

const htmlSource = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Groma Segmentation Conformance - {{.Intent}}</title>
<style>
  :root { --pass:#1a7f37; --fail:#cf222e; --warn:#9a6700; --muted:#57606a; --line:#d0d7de; --bg:#ffffff; --ink:#1f2328; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: var(--ink); background: var(--bg); margin: 0; padding: 2rem; line-height: 1.5; }
  .wrap { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.05rem; margin: 2rem 0 .5rem; border-bottom: 1px solid var(--line); padding-bottom: .3rem; }
  .sub { color: var(--muted); margin: 0 0 1.25rem; }
  .badge { display: inline-block; padding: .1rem .55rem; border-radius: 999px; font-size: .78rem; font-weight: 600; color: #fff; vertical-align: middle; }
  .badge.pass { background: var(--pass); } .badge.fail { background: var(--fail); }
  .badge.warn { background: var(--warn); } .badge.muted { background: var(--muted); }
  .meta { display: grid; grid-template-columns: max-content 1fr; gap: .3rem 1rem; font-size: .9rem; }
  .meta dt { color: var(--muted); } .meta dd { margin: 0; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; word-break: break-all; }
  table { border-collapse: collapse; width: 100%; font-size: .85rem; margin-top: .5rem; }
  th, td { border: 1px solid var(--line); padding: .4rem .5rem; text-align: left; vertical-align: top; }
  th { background: #f6f8fa; }
  .enf { padding: .6rem .8rem; border-radius: 6px; border: 1px solid var(--line); margin: .5rem 0 0; }
  .enf.gap { border-color: var(--fail); background: #fff5f5; }
  .enf.ok { border-color: var(--pass); background: #f2fbf4; }
  ul.controls { margin: .2rem 0; padding-left: 1.1rem; } ul.controls li { margin-bottom: .15rem; }
  .rationale { color: var(--muted); }
  footer { color: var(--muted); font-size: .78rem; margin-top: 2rem; border-top: 1px solid var(--line); padding-top: .6rem; }
  @media print { body { padding: 0; } h2 { page-break-after: avoid; } tr { page-break-inside: avoid; } }
</style>
</head>
<body>
<div class="wrap">
  <h1>Segmentation Conformance <span class="badge {{badge .Predicate.Result}}">{{.Predicate.Result}}</span></h1>
  <p class="sub">Intent <strong>{{.Intent}}</strong>{{if .Predicate.Framework}} &middot; {{.Predicate.Framework}}{{end}} &middot; verified by Groma {{.Predicate.GromaVersion}}</p>

  <dl class="meta">
    <dt>Modes</dt><dd>{{.Predicate.Mode}}</dd>
    <dt>Started</dt><dd>{{utc .Predicate.StartedAt}}</dd>
    <dt>Finished</dt><dd>{{utc .Predicate.FinishedAt}} ({{.Duration}})</dd>
    {{if .Predicate.Cluster}}<dt>Cluster</dt><dd>{{.Predicate.Cluster}}</dd>{{end}}
    {{if .Predicate.CNI}}<dt>CNI</dt><dd>{{.Predicate.CNI}}</dd>{{end}}
    <dt>Subject</dt><dd>{{.SubjectName}}</dd>
    <dt>Digest</dt><dd class="mono">sha256:{{.SubjectDigest}}</dd>
    {{if .Predicate.EvidencedControls}}<dt>Controls evidenced</dt><dd>{{range $i, $c := .Predicate.EvidencedControls}}{{if $i}}, {{end}}{{$c}}{{end}}</dd>{{end}}
  </dl>

  {{if .EnforcementChecked}}
  <div class="enf {{if .EnforcementMatches}}ok{{else}}gap{{end}}">
    Runtime enforcement matches policy configuration: <strong>{{if .EnforcementMatches}}yes{{else}}NO{{end}}</strong>
    {{if not .EnforcementMatches}}<br>{{.Predicate.EnforcementDetail}}{{end}}
  </div>
  {{end}}

  <h2>Assertions</h2>
  <table>
    <thead><tr><th>Path</th><th>Assertion</th><th>Port</th><th>Config</th><th>Runtime</th><th>Reconcile</th><th>Result</th></tr></thead>
    <tbody>
    {{range .Predicate.Assertions}}
      <tr>
        <td>{{.From}} &rarr; {{.To}}</td>
        <td>{{.Assertion}}</td>
        <td>{{.Protocol}}/{{.Port}}</td>
        <td>{{tristate .ConfigAllows}}</td>
        <td>{{if .RuntimeReachable}}{{.RuntimeReachable}}{{else}}-{{end}}</td>
        <td>{{if .Reconciliation}}<span class="badge {{reconcile .Reconciliation}}">{{.Reconciliation}}</span>{{else}}-{{end}}</td>
        <td><span class="badge {{badge .Result}}">{{.Result}}</span></td>
      </tr>
      {{if .Detail}}<tr><td colspan="7" class="rationale">{{.Detail}}</td></tr>{{end}}
    {{end}}
    </tbody>
  </table>

  {{if .Predicate.Framework}}
  <h2>Control coverage ({{.Predicate.Framework}})</h2>
  <table>
    <thead><tr><th>Path</th><th>Control</th><th>Requirement</th><th>Why this path evidences it</th></tr></thead>
    <tbody>
    {{range .Predicate.Assertions}}{{$from := .From}}{{$to := .To}}{{range .MappedControls}}
      <tr>
        <td>{{$from}} &rarr; {{$to}}</td>
        <td class="mono">{{.ID}}</td>
        <td>{{.Title}}</td>
        <td class="rationale">{{.Rationale}}</td>
      </tr>
    {{end}}{{end}}
    </tbody>
  </table>
  {{end}}

  <footer>
    Rendered deterministically from the signed in-toto attestation
    (<span class="mono">{{.Predicate.GromaVersion}}</span>). Verify the attestation with
    <span class="mono">cosign verify-blob-attestation</span>. Active probing samples specific
    source/target pairs; static analysis is exhaustive over the modeled policy set.
  </footer>
</div>
</body>
</html>
`
