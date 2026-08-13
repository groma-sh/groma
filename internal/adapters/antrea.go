package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Antrea orders its native policies by tier before priority. The built-in tiers
// have fixed priorities, and every tier except Baseline is evaluated ahead of
// upstream NetworkPolicy; Baseline is evaluated after it.
var antreaTierPriorities = map[string]int{
	"emergency":   50,
	"securityops": 100,
	"networkops":  150,
	"platform":    200,
	"application": 250,
	"baseline":    253,
}

const (
	antreaDefaultTier  = "application"
	antreaBaselineTier = "baseline"
)

// Antrea served its native policies under v1alpha1 before v1beta1; listing both
// and ignoring whichever is absent covers supported releases.
var antreaGVRs = []schema.GroupVersionResource{
	{Group: "crd.antrea.io", Version: "v1beta1", Resource: "clusternetworkpolicies"},
	{Group: "crd.antrea.io", Version: "v1beta1", Resource: "networkpolicies"},
	{Group: "crd.antrea.io", Version: "v1alpha1", Resource: "clusternetworkpolicies"},
	{Group: "crd.antrea.io", Version: "v1alpha1", Resource: "networkpolicies"},
}

var antreaKinds = map[string]string{
	"clusternetworkpolicies": "Antrea ClusterNetworkPolicy",
	"networkpolicies":        "Antrea NetworkPolicy",
}

type antreaNamespaces struct {
	Match      string   `json:"match,omitempty"`
	SameLabels []string `json:"sameLabels,omitempty"`
}

type antreaPeer struct {
	PodSelector            *metav1.LabelSelector `json:"podSelector,omitempty"`
	NamespaceSelector      *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	Namespaces             *antreaNamespaces     `json:"namespaces,omitempty"`
	NodeSelector           *metav1.LabelSelector `json:"nodeSelector,omitempty"`
	ExternalEntitySelector *metav1.LabelSelector `json:"externalEntitySelector,omitempty"`
	IPBlock                json.RawMessage       `json:"ipBlock,omitempty"`
	FQDN                   string                `json:"fqdn,omitempty"`
	ServiceAccount         json.RawMessage       `json:"serviceAccount,omitempty"`
	Group                  string                `json:"group,omitempty"`
	Scope                  string                `json:"scope,omitempty"`
	Service                json.RawMessage       `json:"service,omitempty"`
}

type antreaPort struct {
	Protocol      string       `json:"protocol,omitempty"`
	Port          *numOrString `json:"port,omitempty"`
	EndPort       int32        `json:"endPort,omitempty"`
	SourcePort    *numOrString `json:"sourcePort,omitempty"`
	SourceEndPort int32        `json:"sourceEndPort,omitempty"`
}

type antreaRule struct {
	Name        string          `json:"name,omitempty"`
	Action      string          `json:"action"`
	AppliedTo   []antreaPeer    `json:"appliedTo,omitempty"`
	From        []antreaPeer    `json:"from,omitempty"`
	To          []antreaPeer    `json:"to,omitempty"`
	Ports       []antreaPort    `json:"ports,omitempty"`
	ToServices  json.RawMessage `json:"toServices,omitempty"`
	L7Protocols json.RawMessage `json:"l7Protocols,omitempty"`
}

type antreaSpec struct {
	Tier      string       `json:"tier,omitempty"`
	Priority  float64      `json:"priority,omitempty"`
	AppliedTo []antreaPeer `json:"appliedTo,omitempty"`
	Ingress   []antreaRule `json:"ingress,omitempty"`
	Egress    []antreaRule `json:"egress,omitempty"`
}

type antreaPolicyDoc struct {
	Spec antreaSpec `json:"spec"`
}

type antreaPolicy struct {
	id        string
	name      string
	namespace string
	spec      antreaSpec
}

type antreaAdapter struct {
	policies []antreaPolicy
}

// LoadAntrea reads Antrea NetworkPolicy and ClusterNetworkPolicy from the
// cluster. It returns (nil, nil) when neither is served.
func LoadAntrea(ctx context.Context, dc dynamic.Interface) (Adapter, error) {
	objs, served, err := listAll(ctx, dc, antreaGVRs)
	if err != nil {
		return nil, err
	}
	if !served {
		return nil, nil
	}
	a := &antreaAdapter{}
	for _, o := range objs {
		var doc antreaPolicyDoc
		if err := decode(o, &doc); err != nil {
			return nil, err
		}
		a.policies = append(a.policies, antreaPolicy{
			id: o.id(antreaKinds[o.gvr.Resource]), name: o.name, namespace: o.namespace, spec: doc.Spec,
		})
	}
	sort.SliceStable(a.policies, func(i, j int) bool {
		ti, oki := antreaTierPriority(a.policies[i].spec.Tier)
		tj, okj := antreaTierPriority(a.policies[j].spec.Tier)
		// A custom tier has no priority Groma knows; sorting it last keeps the
		// modeled ordering intact until direction() reports it as Unknown.
		switch {
		case oki != okj:
			return oki
		case ti != tj:
			return ti < tj
		case a.policies[i].spec.Priority != a.policies[j].spec.Priority:
			return a.policies[i].spec.Priority < a.policies[j].spec.Priority
		}
		return a.policies[i].name < a.policies[j].name
	})
	return a, nil
}

func antreaTierPriority(tier string) (int, bool) {
	if tier == "" {
		tier = antreaDefaultTier
	}
	p, ok := antreaTierPriorities[strings.ToLower(tier)]
	return p, ok
}

func (a *antreaAdapter) Name() string { return "antrea" }

// Evaluate applies Antrea's tiered model. Every tier but Baseline is evaluated
// ahead of upstream NetworkPolicy, so a match there decides the flow outright.
// A Pass action hands the flow to upstream NetworkPolicy, which this adapter
// signals by abstaining.
func (a *antreaAdapter) Evaluate(flow Flow, k8s Verdict) Decision {
	egress := a.direction(flow, true, k8s)
	if egress.Verdict == Unknown {
		return egress
	}
	ingress := a.direction(flow, false, k8s)
	if ingress.Verdict == Unknown {
		return ingress
	}
	return intersect(a.Name(), egress, ingress)
}

func (a *antreaAdapter) direction(flow Flow, egress bool, k8s Verdict) Decision {
	subject := flow.Destination
	if egress {
		subject = flow.Source
	}
	var baseline []string

	for _, p := range a.policies {
		rules := p.spec.Ingress
		if egress {
			rules = p.spec.Egress
		}
		if len(rules) == 0 {
			continue
		}
		if p.namespace != "" && p.namespace != subject.Namespace {
			continue
		}

		for i, r := range rules {
			// A rule-level appliedTo overrides the policy-level one entirely.
			appliedTo := r.AppliedTo
			if len(appliedTo) == 0 {
				appliedTo = p.spec.AppliedTo
			}
			applies, reason := a.peersMatch(p, appliedTo, subject, subject)
			if reason != "" {
				return antreaUnknown(p, fmt.Sprintf("appliedTo of %s rule %d: %s", directionWord(egress), i, reason))
			}
			if !applies {
				continue
			}
			if _, known := antreaTierPriority(p.spec.Tier); !known {
				return antreaUnknown(p, fmt.Sprintf("tier %q is not a built-in tier, so Groma cannot order it against upstream NetworkPolicy", p.spec.Tier))
			}
			if strings.EqualFold(p.spec.Tier, antreaBaselineTier) {
				baseline = append(baseline, p.id)
				continue
			}

			match, reason := a.ruleMatches(p, r, flow, subject, egress)
			if reason != "" {
				return antreaUnknown(p, fmt.Sprintf("%s rule %d: %s", directionWord(egress), i, reason))
			}
			if !match {
				continue
			}
			switch strings.ToLower(r.Action) {
			case "allow":
				return Decision{Verdict: Allow, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s %s rule %d allows this path", p.id, directionWord(egress), i),
					Policies: []string{p.id}}
			case "drop", "reject":
				return Decision{Verdict: Deny, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s %s rule %d %ss this path", p.id, directionWord(egress), i, strings.ToLower(r.Action)),
					Policies: []string{p.id}}
			case "pass":
				return Decision{Verdict: NoOpinion, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s %s rule %d passes this path to upstream NetworkPolicy", p.id, directionWord(egress), i),
					Policies: []string{p.id}}
			default:
				return antreaUnknown(p, fmt.Sprintf("%s rule %d has unknown action %q", directionWord(egress), i, r.Action))
			}
		}
	}

	if len(baseline) == 0 {
		return Decision{Verdict: NoOpinion, Adapter: a.Name()}
	}
	if k8s == Deny {
		// Traffic an upstream NetworkPolicy already dropped never reaches the
		// Baseline tier, so that verdict stands unchanged.
		return Decision{Verdict: NoOpinion, Adapter: a.Name()}
	}
	// The Baseline tier only sees traffic no upstream NetworkPolicy selected.
	// np-guard reports a single allow/deny bit, not whether a policy selected
	// the endpoint at all, so Groma cannot tell those two cases apart here.
	return Decision{Verdict: Unknown, Adapter: a.Name(),
		Reason: fmt.Sprintf("baseline-tier policy applies to the %s path (%s); Groma cannot tell whether an upstream NetworkPolicy already matched, and the Baseline tier only sees traffic that none did",
			directionWord(egress), strings.Join(baseline, ", ")),
		Policies: baseline}
}

func antreaUnknown(p antreaPolicy, reason string) Decision {
	return Decision{Verdict: Unknown, Adapter: "antrea", Reason: p.id + ": " + reason, Policies: []string{p.id}}
}

func (a *antreaAdapter) ruleMatches(p antreaPolicy, r antreaRule, flow Flow, subject Target, egress bool) (bool, string) {
	if len(r.ToServices) > 0 {
		return false, "toServices needs runtime Service resolution"
	}
	if len(r.L7Protocols) > 0 {
		return false, "l7Protocols decide below the port layer"
	}
	ok, reason := antreaPortsMatch(r.Ports, flow)
	if reason != "" || !ok {
		return false, reason
	}

	peers, peer := r.From, flow.Source
	if egress {
		peers, peer = r.To, flow.Destination
	}
	if len(peers) == 0 {
		return false, fmt.Sprintf("rule has no %s peers", map[bool]string{true: "to", false: "from"}[egress])
	}
	return a.peersMatch(p, peers, peer, subject)
}

// peersMatch reports whether any peer in the list covers the target. subject is
// the endpoint the policy is applied to, which "namespaces: {match: Self}"
// resolves against.
func (a *antreaAdapter) peersMatch(p antreaPolicy, peers []antreaPeer, t Target, subject Target) (bool, string) {
	if len(peers) == 0 {
		return false, ""
	}
	for _, peer := range peers {
		match, reason := a.peerMatches(p, peer, t, subject)
		if reason != "" {
			return false, reason
		}
		if match {
			return true, ""
		}
	}
	return false, ""
}

func (a *antreaAdapter) peerMatches(p antreaPolicy, peer antreaPeer, t Target, subject Target) (bool, string) {
	switch {
	case len(peer.IPBlock) > 0:
		return false, "ipBlock peers need pod IPs, which are not known statically"
	case peer.FQDN != "":
		return false, "fqdn peers need runtime DNS resolution"
	case len(peer.ServiceAccount) > 0:
		return false, "serviceAccount peers are not modeled"
	case len(peer.Service) > 0:
		return false, "service peers are not modeled"
	case peer.Group != "":
		return false, "group peers indirect through a ClusterGroup Groma does not resolve"
	case peer.ExternalEntitySelector != nil:
		// An ExternalEntity is by definition not a pod in this cluster.
		return false, ""
	case peer.NodeSelector != nil:
		// A node peer is the host network, never the pod at the other end.
		return false, ""
	case peer.Scope != "" && !strings.EqualFold(peer.Scope, "cluster"):
		return false, "peer scope " + peer.Scope + " reaches beyond this cluster"
	case peer.Namespaces != nil && len(peer.Namespaces.SameLabels) > 0:
		return false, "namespaces.sameLabels peers are not modeled"
	}

	// Namespace scoping: a namespaced Antrea NetworkPolicy confines its peers to
	// its own namespace; a ClusterNetworkPolicy spans every namespace unless a
	// namespaceSelector or "namespaces: {match: Self}" narrows it.
	switch {
	case p.namespace != "":
		if t.Namespace != p.namespace {
			return false, ""
		}
	case peer.Namespaces != nil && strings.EqualFold(peer.Namespaces.Match, "self"):
		if t.Namespace != subject.Namespace {
			return false, ""
		}
	case peer.NamespaceSelector != nil:
		match, err := matchesSelector(peer.NamespaceSelector, t.NamespaceLabels)
		if err != nil {
			return false, "namespaceSelector: " + err.Error()
		}
		if !match {
			return false, ""
		}
	}

	if peer.PodSelector == nil {
		// No pod constraint: every pod in the namespaces selected above matches.
		// A peer with no constraint at all is not a valid Antrea peer, and the
		// checks above have already rejected the shapes that would produce one.
		return peer.NamespaceSelector != nil || peer.Namespaces != nil || p.namespace != "", ""
	}
	match, err := matchesSelector(peer.PodSelector, t.PodLabels)
	if err != nil {
		return false, "podSelector: " + err.Error()
	}
	return match, ""
}

// antreaPortsMatch checks the flow against a rule's ports. An empty list covers
// every port, which is Antrea's own semantics.
func antreaPortsMatch(ports []antreaPort, flow Flow) (bool, string) {
	if len(ports) == 0 {
		return true, ""
	}
	for _, p := range ports {
		if !protocolMatches(p.Protocol, flow.Protocol) {
			continue
		}
		if p.SourcePort != nil || p.SourceEndPort > 0 {
			return false, "source port match criteria are not modeled"
		}
		if p.Port == nil {
			// Protocol matched with no port constraint: every port is covered.
			return true, ""
		}
		from, ok := antreaPortNumber(*p.Port)
		if !ok {
			return false, "named or unparsable port " + p.Port.str
		}
		to := from
		if p.EndPort > 0 {
			to = p.EndPort
		}
		if (portRange{from: from, to: to}).contains(flow.Port) {
			return true, ""
		}
	}
	return false, ""
}

func antreaPortNumber(p numOrString) (int32, bool) {
	if p.isNum {
		if p.num < 0 || p.num > 65535 {
			return 0, false
		}
		return int32(p.num), true
	}
	return parsePort(p.str)
}
