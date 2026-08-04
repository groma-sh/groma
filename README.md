<p align="center">
  <img src="docs/banner.svg" alt="Groma - prove your Kubernetes network segmentation actually holds" width="840">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-alpha-E0A94A" alt="status: alpha">
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26">
  <img src="https://img.shields.io/badge/license-Apache--2.0-3DA639" alt="License: Apache-2.0">
</p>

<p align="center">
  <b>Groma proves your Kubernetes network segmentation enforces what you intended</b><br>
  and emits audit-ready evidence mapped to compliance controls (starting with PCI-DSS 11.4.5).
</p>

---

The same intent and the same policy on a CNI that accepts `NetworkPolicy` but
does not enforce it: `kubectl` is happy, and Groma goes red on the path that is
supposed to be blocked.

<p align="center">
  <img src="docs/demo.gif" alt="Groma catching an enforcement gap on a kind cluster" width="820">
</p>

## Why Groma?

- **Accepted is not enforced.** On a non-enforcing or misconfigured CNI, a
  `NetworkPolicy` object is accepted and ignored, and nothing warns you.
- **Policies are easy to get wrong.** Selector AND/OR semantics, default-deny
  activation, and ingress/egress interaction routinely produce YAML that does
  not isolate what its author believed.
- **PCI-DSS 4.0 requirement 11.4.5 mandates segmentation testing** at least
  annually, and a manual pen-test is stale the moment a policy changes.

## Quickstart

```sh
go build -o groma ./cmd/groma

# against the current kubeconfig context:
./groma --intent examples/intent.yaml

# preview the plan without touching the cluster:
./groma --intent examples/intent-selector.yaml --dry-run
```

| Flag | Purpose |
|---|---|
| `--intent` | Path to a `SegmentationIntent` YAML (required). |
| `--output` | Write JSON evidence to a file instead of stdout. |
| `--dry-run` | Resolve zones and print the probe plan without creating pods. |

See `./groma --help` for all flags.

Full self-contained demo (creates a kind cluster, applies a policy that a
non-enforcing CNI ignores, catches the gap, tears down):

```sh
examples/demo/run.sh
```

A more in-depth tutorial is coming to the [website](https://groma-sh.github.io).

## One policy, two CNIs: enforcement is not universal

`examples/demo/run.sh` runs the same intent and the same policy against two different CNIs:

| CNI | `frontend -> cde` (MustNotReach) | Overall | Exit |
|---|---|---|:---:|
| kindnet (does not enforce) | REACHABLE -> FAIL (enforcement gap) | **FAIL** | 1 |
| Calico (enforces)          | BLOCKED -> PASS                    | **PASS** | 0 |

## How Groma avoids false positives

A blocked connection alone does not prove segmentation; the target might just
be down. Before reporting a `MustNotReach` as `PASS`, Groma runs a positive
control: it probes the same destination from an allowed source, and only if
that source *can* reach it is the block attributable to policy. Otherwise the
result is `INDETERMINATE`, never a false `PASS`.

## Links

- [Website and docs](https://groma-sh.github.io)
- [Examples](examples/)
- Contributing: issues and PRs welcome
- [License: Apache-2.0](LICENSE)
