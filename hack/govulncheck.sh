#!/usr/bin/env bash
# Fails only on reachable vulnerabilities not listed in .github/govulncheck-allow.txt.
# Also fails if an allowlist entry stops being reported (stale exception).
set -euo pipefail

ALLOWFILE="${ALLOWFILE:-.github/govulncheck-allow.txt}"
REPORT="${REPORT:-govulncheck.json}"

echo "==> running govulncheck"
go run golang.org/x/vuln/cmd/govulncheck@latest -format json ./... > "$REPORT" || true

python3 - "$REPORT" "$ALLOWFILE" <<'PY'
import json, sys, os

report, allowfile = sys.argv[1], sys.argv[2]

raw = open(report).read()
dec, i, objs = json.JSONDecoder(), 0, []
while i < len(raw):
    while i < len(raw) and raw[i].isspace():
        i += 1
    if i >= len(raw):
        break
    obj, i = dec.raw_decode(raw, i)
    objs.append(obj)

osvs = {o["osv"]["id"]: o["osv"] for o in objs if "osv" in o}
findings = [o["finding"] for o in objs if "finding" in o]

# A finding with a function in the first trace frame is a *called* symbol, not
# merely an imported or required module.
called = {f["osv"] for f in findings if f.get("trace") and f["trace"][0].get("function")}

allowed = {}
if os.path.exists(allowfile):
    for line in open(allowfile):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        oid, _, reason = line.partition(":")
        allowed[oid.strip()] = reason.strip()

unexpected = sorted(called - set(allowed))
stale = sorted(set(allowed) - called)

def summary(oid):
    return osvs.get(oid, {}).get("summary", "")[:100]

if unexpected:
    print(f"\n::error::{len(unexpected)} reachable vulnerability(ies) not in {allowfile}:")
    for oid in unexpected:
        print(f"  {oid}  {summary(oid)}")
        print(f"    https://pkg.go.dev/vuln/{oid}")

if stale:
    print(f"\n::error::{len(stale)} stale allowlist entry(ies) in {allowfile};")
    print("          these are no longer reported and must be removed:")
    for oid in stale:
        print(f"  {oid}")

if allowed and not stale:
    print(f"\n{len(allowed)} accepted advisory(ies):")
    for oid, reason in sorted(allowed.items()):
        print(f"  {oid}  {reason}")

if unexpected or stale:
    sys.exit(1)

print(f"\nOK: {len(called)} reachable vulnerability(ies), all accepted.")
PY
