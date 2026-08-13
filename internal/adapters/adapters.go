// Package adapters extends Groma's static analysis with the CNI-native policy
// resources that upstream NetworkPolicy analysis cannot see.
//
// The embedded np-guard engine models `networking.k8s.io/NetworkPolicy` and the
// network-policy-api types. On a cluster that also carries CiliumNetworkPolicy,
// Calico GlobalNetworkPolicy, or Antrea ClusterNetworkPolicy objects, that model
// is incomplete: a path the upstream analysis calls ALLOWED may be denied by a
// CNI-native rule, and vice versa. An adapter reads one CNI's own resources and
// returns its verdict for a single flow, which the analyzer folds over the
// upstream verdict before reconciliation.
//
// Soundness rule for every adapter in this package: when a policy selects one of
// the endpoints but uses a construct the adapter does not model (an L7 rule, an
// FQDN peer, a service-account selector, a custom tier), the adapter returns
// Unknown rather than guessing. Unknown propagates to an INDETERMINATE result
// with the reason attached, never to a PASS. Groma would rather say "I cannot
// tell you" than emit evidence an auditor can disprove.
package adapters

import (
	"context"
	"fmt"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Verdict is one adapter's answer for a single flow.
type Verdict string

const (
	// NoOpinion means no CNI-native policy selects either endpoint for the
	// direction under test, so the upstream NetworkPolicy verdict stands.
	NoOpinion Verdict = "NO-OPINION"
	// Allow means CNI-native policy permits the flow.
	Allow Verdict = "ALLOW"
	// Deny means CNI-native policy blocks the flow.
	Deny Verdict = "DENY"
	// Unknown means a selecting policy uses a construct the adapter does not
	// model, so no honest verdict can be given.
	Unknown Verdict = "UNKNOWN"
)

// Target is one end of a flow, carrying everything a CNI selector can match on.
type Target struct {
	Namespace       string
	NamespaceLabels map[string]string
	PodLabels       map[string]string
}

// Flow is a single source/destination/port tuple under evaluation.
type Flow struct {
	Source      Target
	Destination Target
	Protocol    string
	Port        int32
}

// Decision is an adapter's verdict plus the evidence for it. Policies holds
// human-readable identities ("CiliumNetworkPolicy cde/deny-all") so the
// attestation can cite the exact rule that decided the path.
type Decision struct {
	Verdict  Verdict
	Adapter  string
	Reason   string
	Policies []string
}

// Adapter evaluates one CNI's native policy resources.
type Adapter interface {
	// Name is the lowercase CNI name ("cilium", "calico", "antrea").
	Name() string
	// Evaluate returns the CNI-native verdict for flow. k8s carries the
	// upstream NetworkPolicy verdict, because some CNIs (Antrea's Pass action,
	// Calico's fall-through to the converted knp.default.* policies) delegate
	// to it rather than deciding themselves.
	Evaluate(flow Flow, k8s Verdict) Decision
}

// Loader builds one adapter by listing its CRDs. It returns (nil, nil) when the
// CNI's resources are not served by this cluster.
type Loader func(ctx context.Context, dc dynamic.Interface) (Adapter, error)

var loaders = map[string]Loader{
	"cilium": LoadCilium,
	"calico": LoadCalico,
	"antrea": LoadAntrea,
}

// Names lists every adapter this build knows about, sorted.
func Names() []string {
	out := make([]string, 0, len(loaders))
	for name := range loaders {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Load builds the requested adapters. The selection is a comma-separated list:
// "auto" (the default) probes every known CNI and keeps the ones whose CRDs the
// cluster serves, "none" disables the feature, and an explicit list fails if a
// named CNI's resources are absent, so a misconfigured --cni-adapter is loud
// rather than silently analyzing less than the operator asked for.
func Load(ctx context.Context, dc dynamic.Interface, selection string) ([]Adapter, error) {
	names, auto, err := parseSelection(selection)
	if err != nil {
		return nil, err
	}
	var out []Adapter
	for _, name := range names {
		adapter, err := loaders[name](ctx, dc)
		if err != nil {
			return nil, fmt.Errorf("cni adapter %q: %w", name, err)
		}
		if adapter == nil {
			if auto {
				continue
			}
			return nil, fmt.Errorf("cni adapter %q: this cluster does not serve its policy CRDs", name)
		}
		out = append(out, adapter)
	}
	return out, nil
}

func parseSelection(selection string) (names []string, auto bool, err error) {
	selection = strings.TrimSpace(selection)
	if selection == "" || selection == "auto" {
		return Names(), true, nil
	}
	if selection == "none" {
		return nil, false, nil
	}
	for _, raw := range strings.Split(selection, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if _, ok := loaders[name]; !ok {
			return nil, false, fmt.Errorf("unknown cni adapter %q: known adapters are %s, auto, none",
				name, strings.Join(Names(), ", "))
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, false, nil
}

// Combine folds every adapter's decision over the upstream NetworkPolicy
// verdict. Adapters that abstain leave k8s in charge; a single Unknown, or two
// adapters that disagree, poisons the result to Unknown, because a segmentation
// claim backed by a contradiction is worth less than no claim at all.
func Combine(k8s Verdict, decisions []Decision) Decision {
	combined := Decision{Verdict: k8s}
	var opinionated []Decision
	for _, d := range decisions {
		switch d.Verdict {
		case NoOpinion:
			continue
		case Unknown:
			return d
		}
		opinionated = append(opinionated, d)
	}
	if len(opinionated) == 0 {
		return combined
	}
	first := opinionated[0]
	for _, d := range opinionated[1:] {
		if d.Verdict != first.Verdict {
			return Decision{
				Verdict: Unknown,
				Adapter: first.Adapter + "+" + d.Adapter,
				Reason: fmt.Sprintf("adapters disagree: %s says %s, %s says %s",
					first.Adapter, first.Verdict, d.Adapter, d.Verdict),
				Policies: append(append([]string{}, first.Policies...), d.Policies...),
			}
		}
		first.Policies = append(first.Policies, d.Policies...)
		first.Adapter += "+" + d.Adapter
	}
	return first
}

// listAll fetches every object across the given GVRs, tolerating a cluster that
// does not serve some of them. It reports whether any GVR was actually served,
// which is how "auto" detection decides a CNI is installed.
func listAll(ctx context.Context, dc dynamic.Interface, gvrs []schema.GroupVersionResource) (objs []unstructuredObject, served bool, err error) {
	for _, gvr := range gvrs {
		list, err := dc.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			if isAbsent(err) {
				continue
			}
			return nil, false, fmt.Errorf("list %s: %w", gvr.Resource+"."+gvr.Group, err)
		}
		served = true
		for i := range list.Items {
			objs = append(objs, unstructuredObject{gvr: gvr, item: list.Items[i].Object,
				name: list.Items[i].GetName(), namespace: list.Items[i].GetNamespace()})
		}
	}
	return objs, served, nil
}

// isAbsent reports whether an error means "this cluster does not serve that
// resource" rather than a real failure. A cluster without the CNI's CRDs, and a
// ServiceAccount without read access to them, both land here: in either case
// Groma has no CNI-native policy to analyze, and saying so is correct.
func isAbsent(err error) bool {
	return apierrors.IsNotFound(err) || meta.IsNoMatchError(err) || apierrors.IsForbidden(err)
}

type unstructuredObject struct {
	gvr       schema.GroupVersionResource
	item      map[string]any
	name      string
	namespace string
}

// id renders the policy identity cited in evidence, e.g.
// "CiliumNetworkPolicy cde/deny-all" or "GlobalNetworkPolicy default-deny".
func (o unstructuredObject) id(kind string) string {
	if o.namespace == "" {
		return kind + " " + o.name
	}
	return kind + " " + o.namespace + "/" + o.name
}

// intersect ANDs the two directions the way every NetworkPolicy-shaped model
// does: a flow needs the source's egress and the destination's ingress to agree.
func intersect(name string, egress, ingress Decision) Decision {
	switch {
	case egress.Verdict == Deny:
		return egress
	case ingress.Verdict == Deny:
		return ingress
	case egress.Verdict == Allow && ingress.Verdict == Allow:
		return Decision{Verdict: Allow, Adapter: name,
			Reason:   egress.Reason + "; " + ingress.Reason,
			Policies: append(append([]string{}, egress.Policies...), ingress.Policies...)}
	case egress.Verdict == Allow:
		return egress
	case ingress.Verdict == Allow:
		return ingress
	default:
		return Decision{Verdict: NoOpinion, Adapter: name}
	}
}

func directionWord(egress bool) string {
	if egress {
		return "egress"
	}
	return "ingress"
}
