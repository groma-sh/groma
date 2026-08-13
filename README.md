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
| `--mode` | `active`, `static`, or `both` (reconcile config against runtime). |
| `--cni-adapter` | CNI-native policy to include in static analysis: `auto`, `none`, or a list. |
| `--sink` | Publish the evidence bundle: `oci://`, `s3://`, `gs://`, or a directory. |
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

## Beyond upstream NetworkPolicy

`--mode static` and `--mode both` analyze `NetworkPolicy` and the
network-policy-api types with the embedded np-guard engine. On a cluster that
also carries CNI-native policy, that model is incomplete, so Groma reads those
resources too:

| CNI | Resources modeled |
|---|---|
| Cilium | `CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy` (allow and deny rules, entities, per-direction default-deny) |
| Calico | `NetworkPolicy`, `GlobalNetworkPolicy` in the `default` tier (selector expressions, rule order, Allow/Deny/Log) |
| Antrea | `NetworkPolicy`, `ClusterNetworkPolicy` (built-in tier ordering, Allow/Drop/Reject/Pass) |

Adapters are detected automatically (`--cni-adapter auto`); a cluster without
those CRDs, or without permission to read them, simply analyzes upstream
NetworkPolicy as before. Every verdict records which engine produced it and
which rule it cited.

**Adapters never guess.** When a policy selects one of the endpoints but uses a
construct Groma does not model - an L7 rule, an FQDN or CIDR peer, a
service-account selector, a custom tier - the config verdict is `UNKNOWN` with
the reason attached, and the assertion reports `INDETERMINATE`. A segmentation
claim an auditor can disprove is worth less than an honest gap in coverage.

## Evidence that outlives the cluster

Evidence stored only in the cluster it audits can be rewritten by that cluster.
`--sink` publishes the same bytes somewhere durable:

```sh
./groma --intent examples/intent.yaml --mode both \
  --attest evidence.att.json --keyless \
  --sink oci://registry.example.com/groma/evidence
```

| Sink | Spec | Notes |
|---|---|---|
| OCI registry | `oci://registry.example.com/groma/evidence` | One layer per file, titled; returns a digest-pinned reference |
| Amazon S3 | `s3://bucket/prefix?region=eu-west-1` | Ambient AWS credentials; IRSA or Pod Identity in-cluster |
| Google Cloud Storage | `gs://bucket/prefix` | Application Default Credentials; Workload Identity in-cluster |
| Local directory | `/var/lib/groma/evidence` | Air-gapped clusters and mounted volumes |

In the controller, set `spec.evidence.sink` on a `ConformanceSchedule`. A failed
publish never fails the run; it surfaces as an `EvidencePublished` status
condition, because losing a determined verdict to a registry outage would
discard the very evidence the sink exists to preserve.

## Metrics and alerting

The controller-manager serves Prometheus metrics on `:8080`. Apply
`deploy/metrics.yaml` for a Service, a ServiceMonitor, and the alert rules; import
`deploy/grafana/groma-dashboard.json` for the dashboard.

The series that matters most is `groma_last_run_enforcement_gaps`: above zero,
the cluster believes it is segmented and is not.

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
