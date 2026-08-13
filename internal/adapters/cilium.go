package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Cilium encodes the pod's namespace and its namespace's labels as ordinary
// labels on the endpoint, which is what lets a CiliumNetworkPolicy select
// across namespaces. Reproducing that flattening here means one selector
// implementation covers matchLabels and matchExpressions alike.
const (
	ciliumNamespaceKey      = "io.kubernetes.pod.namespace"
	ciliumNamespaceLabelKey = "io.kubernetes.pod.namespace.labels."
)

var ciliumGVRs = []schema.GroupVersionResource{
	{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"},
	{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"},
}

var ciliumKinds = map[string]string{
	"ciliumnetworkpolicies":            "CiliumNetworkPolicy",
	"ciliumclusterwidenetworkpolicies": "CiliumClusterwideNetworkPolicy",
}

type ciliumSelector struct {
	MatchLabels      map[string]string                 `json:"matchLabels,omitempty"`
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

type ciliumPortProtocol struct {
	Port     string `json:"port"`
	EndPort  int32  `json:"endPort,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type ciliumPortRule struct {
	Ports          []ciliumPortProtocol `json:"ports,omitempty"`
	Rules          json.RawMessage      `json:"rules,omitempty"`
	ServerNames    []string             `json:"serverNames,omitempty"`
	TerminatingTLS json.RawMessage      `json:"terminatingTLS,omitempty"`
	OriginatingTLS json.RawMessage      `json:"originatingTLS,omitempty"`
}

// ciliumPeerRule flattens the ingress and egress rule shapes, which differ only
// in the direction words in their field names.
type ciliumPeerRule struct {
	FromEndpoints []ciliumSelector `json:"fromEndpoints,omitempty"`
	ToEndpoints   []ciliumSelector `json:"toEndpoints,omitempty"`
	FromEntities  []string         `json:"fromEntities,omitempty"`
	ToEntities    []string         `json:"toEntities,omitempty"`
	FromNodes     []ciliumSelector `json:"fromNodes,omitempty"`
	ToNodes       []ciliumSelector `json:"toNodes,omitempty"`

	FromCIDR     []string          `json:"fromCIDR,omitempty"`
	ToCIDR       []string          `json:"toCIDR,omitempty"`
	FromCIDRSet  []json.RawMessage `json:"fromCIDRSet,omitempty"`
	ToCIDRSet    []json.RawMessage `json:"toCIDRSet,omitempty"`
	FromRequires []json.RawMessage `json:"fromRequires,omitempty"`
	FromGroups   []json.RawMessage `json:"fromGroups,omitempty"`
	ToGroups     []json.RawMessage `json:"toGroups,omitempty"`
	ToServices   []json.RawMessage `json:"toServices,omitempty"`
	ToFQDNs      []json.RawMessage `json:"toFQDNs,omitempty"`

	ToPorts        []ciliumPortRule  `json:"toPorts,omitempty"`
	ICMPs          []json.RawMessage `json:"icmps,omitempty"`
	Authentication json.RawMessage   `json:"authentication,omitempty"`
}

type ciliumDefaultDeny struct {
	Ingress *bool `json:"ingress,omitempty"`
	Egress  *bool `json:"egress,omitempty"`
}

type ciliumRule struct {
	EndpointSelector  *ciliumSelector    `json:"endpointSelector,omitempty"`
	NodeSelector      *ciliumSelector    `json:"nodeSelector,omitempty"`
	Ingress           []ciliumPeerRule   `json:"ingress,omitempty"`
	IngressDeny       []ciliumPeerRule   `json:"ingressDeny,omitempty"`
	Egress            []ciliumPeerRule   `json:"egress,omitempty"`
	EgressDeny        []ciliumPeerRule   `json:"egressDeny,omitempty"`
	EnableDefaultDeny *ciliumDefaultDeny `json:"enableDefaultDeny,omitempty"`
}

type ciliumPolicy struct {
	Spec  *ciliumRule  `json:"spec,omitempty"`
	Specs []ciliumRule `json:"specs,omitempty"`
}

// ciliumScopedRule is one rule plus the namespace scoping it inherits. A
// namespaced CiliumNetworkPolicy confines every bare selector in it to its own
// namespace; a CiliumClusterwideNetworkPolicy does not, and carries "".
type ciliumScopedRule struct {
	id        string
	namespace string
	rule      ciliumRule
}

type ciliumAdapter struct {
	rules []ciliumScopedRule
}

// LoadCilium reads CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy from
// the cluster. It returns (nil, nil) when neither CRD is served.
func LoadCilium(ctx context.Context, dc dynamic.Interface) (Adapter, error) {
	objs, served, err := listAll(ctx, dc, ciliumGVRs)
	if err != nil {
		return nil, err
	}
	if !served {
		return nil, nil
	}
	a := &ciliumAdapter{}
	for _, o := range objs {
		var p ciliumPolicy
		if err := decode(o, &p); err != nil {
			return nil, err
		}
		id := o.id(ciliumKinds[o.gvr.Resource])
		if p.Spec != nil {
			a.rules = append(a.rules, ciliumScopedRule{id: id, namespace: o.namespace, rule: *p.Spec})
		}
		for _, r := range p.Specs {
			a.rules = append(a.rules, ciliumScopedRule{id: id, namespace: o.namespace, rule: r})
		}
	}
	return a, nil
}

func (a *ciliumAdapter) Name() string { return "cilium" }

// Evaluate applies Cilium's own model: a rule that selects an endpoint and
// carries rules for a direction turns that direction default-deny for it, deny
// rules beat allow rules, and both the source's egress and the destination's
// ingress must permit the flow. The upstream NetworkPolicy verdict is folded in
// by the caller, because Cilium evaluates both policy families as one allow-set
// rather than delegating between them.
func (a *ciliumAdapter) Evaluate(flow Flow, _ Verdict) Decision {
	egress := a.direction(flow, true)
	if egress.Verdict == Unknown {
		return egress
	}
	ingress := a.direction(flow, false)
	if ingress.Verdict == Unknown {
		return ingress
	}
	return intersect(a.Name(), egress, ingress)
}

// direction evaluates one half of the flow. When egress is true it asks whether
// the source may send; otherwise whether the destination may receive.
func (a *ciliumAdapter) direction(flow Flow, egress bool) Decision {
	subject, peer := flow.Destination, flow.Source
	if egress {
		subject, peer = flow.Source, flow.Destination
	}

	var (
		restricted bool
		unmodeled  []string
		cited      []string
		allowedBy  string
	)
	for _, sr := range a.rules {
		if sr.rule.NodeSelector != nil {
			// A node policy governs host traffic, never a pod endpoint.
			continue
		}
		selects, reason := a.selects(sr, subject)
		if reason != "" {
			// The endpointSelector itself is unreadable, so whether this rule
			// turns the direction default-deny is unknowable. That is not a
			// question the rest of the evaluation can paper over.
			return Decision{Verdict: Unknown, Adapter: a.Name(),
				Reason: sr.id + ": unmodeled endpointSelector: " + reason, Policies: []string{sr.id}}
		}
		if !selects {
			continue
		}

		allowRules, denyRules := sr.rule.Ingress, sr.rule.IngressDeny
		if egress {
			allowRules, denyRules = sr.rule.Egress, sr.rule.EgressDeny
		}
		if len(allowRules) == 0 && len(denyRules) == 0 {
			continue
		}
		if enablesDefaultDeny(sr.rule.EnableDefaultDeny, egress) {
			restricted = true
		}

		// Deny rules are terminal in Cilium, so they are checked first and end
		// the evaluation immediately.
		for _, r := range denyRules {
			match, reason := a.peerMatches(sr, r, peer, flow, egress)
			if reason != "" {
				// An unreadable deny rule cannot be deferred the way an
				// unreadable allow can: nothing later in the evaluation can
				// override a deny, so if it might have matched, no verdict is
				// safe to give.
				return Decision{Verdict: Unknown, Adapter: a.Name(),
					Reason:   sr.id + ": unmodeled construct in a deny rule: " + reason,
					Policies: []string{sr.id}}
			}
			if match {
				return Decision{Verdict: Deny, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s denies this path (%s)", sr.id, directionWord(egress)),
					Policies: []string{sr.id}}
			}
		}
		for _, r := range allowRules {
			match, reason := a.peerMatches(sr, r, peer, flow, egress)
			if reason != "" {
				unmodeled = append(unmodeled, sr.id+": "+reason)
				continue
			}
			if match && allowedBy == "" {
				allowedBy = sr.id
			}
		}
		cited = append(cited, sr.id)
	}

	if !restricted {
		return Decision{Verdict: NoOpinion, Adapter: a.Name()}
	}
	if allowedBy != "" {
		return Decision{Verdict: Allow, Adapter: a.Name(),
			Reason:   fmt.Sprintf("%s allows this path (%s)", allowedBy, directionWord(egress)),
			Policies: []string{allowedBy}}
	}
	// Nothing allowed the flow, so the answer would be Cilium's default deny.
	// If any selecting rule used a construct this adapter cannot model, that
	// construct might have been the one that allowed it: say so instead.
	if len(unmodeled) > 0 {
		return Decision{Verdict: Unknown, Adapter: a.Name(),
			Reason:   "unmodeled Cilium construct on the " + directionWord(egress) + " path: " + strings.Join(unmodeled, "; "),
			Policies: cited}
	}
	return Decision{Verdict: Deny, Adapter: a.Name(),
		Reason:   fmt.Sprintf("Cilium default-deny on %s: %s selects this endpoint and no rule allows the path", directionWord(egress), strings.Join(cited, ", ")),
		Policies: cited}
}

// enablesDefaultDeny honors spec.enableDefaultDeny, the switch that lets a rule
// add allowances without turning the direction default-deny.
func enablesDefaultDeny(d *ciliumDefaultDeny, egress bool) bool {
	if d == nil {
		return true
	}
	v := d.Ingress
	if egress {
		v = d.Egress
	}
	return v == nil || *v
}

// selects reports whether a rule's endpointSelector picks out the target.
func (a *ciliumAdapter) selects(sr ciliumScopedRule, t Target) (bool, string) {
	if sr.rule.EndpointSelector == nil {
		return false, ""
	}
	return matchCiliumSelector(*sr.rule.EndpointSelector, t, sr.namespace)
}

// peerMatches reports whether one ingress/egress rule covers the peer endpoint
// and the flow's port. The empty string as the second return means "modeled";
// anything else names the construct that forced an Unknown.
func (a *ciliumAdapter) peerMatches(sr ciliumScopedRule, r ciliumPeerRule, peer Target, flow Flow, egress bool) (bool, string) {
	if reason := ciliumUnmodeledPeer(r, egress); reason != "" {
		return false, reason
	}
	portOK, reason := ciliumPortsMatch(r.ToPorts, flow)
	if reason != "" {
		return false, reason
	}
	if !portOK {
		return false, ""
	}

	selectors, entities, nodes := r.FromEndpoints, r.FromEntities, r.FromNodes
	if egress {
		selectors, entities, nodes = r.ToEndpoints, r.ToEntities, r.ToNodes
	}
	if len(selectors) == 0 && len(entities) == 0 && len(nodes) == 0 {
		// Cilium requires a peer field; a rule without one is a shape this
		// adapter does not recognize rather than a match-everything rule.
		return false, "rule has no endpoint, entity, or node peer"
	}
	for _, sel := range selectors {
		match, reason := matchCiliumSelector(sel, peer, sr.namespace)
		if reason != "" {
			return false, reason
		}
		if match {
			return true, ""
		}
	}
	for _, e := range entities {
		match, reason := ciliumEntityMatches(e)
		if reason != "" {
			return false, reason
		}
		if match {
			return true, ""
		}
	}
	// fromNodes/toNodes select the host network, never the pod at the other end
	// of this flow, so they correctly contribute no match.
	return false, ""
}

// ciliumUnmodeledPeer names any construct in the rule that Groma cannot
// evaluate from policy text alone: CIDR peers need pod IPs, toServices and
// toFQDNs need runtime resolution, and L7 rules decide below the port layer.
func ciliumUnmodeledPeer(r ciliumPeerRule, egress bool) string {
	type probe struct {
		present bool
		name    string
	}
	checks := []probe{
		{len(r.FromCIDR) > 0 && !egress, "fromCIDR (pod IPs are not known statically)"},
		{len(r.ToCIDR) > 0 && egress, "toCIDR (pod IPs are not known statically)"},
		{len(r.FromCIDRSet) > 0 && !egress, "fromCIDRSet"},
		{len(r.ToCIDRSet) > 0 && egress, "toCIDRSet"},
		{len(r.FromRequires) > 0 && !egress, "fromRequires"},
		{len(r.FromGroups) > 0 && !egress, "fromGroups"},
		{len(r.ToGroups) > 0 && egress, "toGroups"},
		{len(r.ToServices) > 0 && egress, "toServices"},
		{len(r.ToFQDNs) > 0 && egress, "toFQDNs"},
		{len(r.ICMPs) > 0, "icmps"},
		{len(r.Authentication) > 0, "authentication"},
	}
	for _, c := range checks {
		if c.present {
			return c.name
		}
	}
	return ""
}

// ciliumEntityMatches resolves a Cilium entity against a pod endpoint. Most
// entities name something that is definitively not a pod, so reporting "no
// match" for them is a modeled answer, not a guess.
func ciliumEntityMatches(entity string) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(entity)) {
	case "all", "cluster":
		return true, ""
	case "none", "host", "remote-node", "world", "world-ipv4", "world-ipv6", "kube-apiserver", "health", "ingress":
		return false, ""
	default:
		return false, "entity " + entity
	}
}

// ciliumPortsMatch checks the flow's port against a rule's toPorts. An absent
// toPorts covers every port, which is Cilium's own semantics.
func ciliumPortsMatch(toPorts []ciliumPortRule, flow Flow) (bool, string) {
	if len(toPorts) == 0 {
		return true, ""
	}
	for _, pr := range toPorts {
		if len(pr.Rules) > 0 {
			return false, "L7 rules under toPorts"
		}
		if len(pr.ServerNames) > 0 || len(pr.TerminatingTLS) > 0 || len(pr.OriginatingTLS) > 0 {
			return false, "TLS or SNI matching under toPorts"
		}
		for _, p := range pr.Ports {
			if !protocolMatches(p.Protocol, flow.Protocol) {
				continue
			}
			from, ok := parsePort(p.Port)
			if !ok {
				return false, "named or unparsable port " + p.Port
			}
			to := from
			if p.EndPort > 0 {
				to = p.EndPort
			}
			if (portRange{from: from, to: to}).contains(flow.Port) {
				return true, ""
			}
		}
	}
	return false, ""
}

// matchCiliumSelector evaluates a Cilium endpoint selector against a target.
// implicitNamespace is the namespace a namespaced policy confines bare
// selectors to; it is empty for cluster-wide policies.
func matchCiliumSelector(sel ciliumSelector, t Target, implicitNamespace string) (bool, string) {
	ls := &metav1.LabelSelector{MatchLabels: map[string]string{}}
	constrainsNamespace := false

	for k, v := range sel.MatchLabels {
		key, reason := normalizeCiliumKey(k)
		if reason != "" {
			return false, reason
		}
		if key == ciliumNamespaceKey {
			constrainsNamespace = true
		}
		ls.MatchLabels[key] = v
	}
	for _, req := range sel.MatchExpressions {
		key, reason := normalizeCiliumKey(req.Key)
		if reason != "" {
			return false, reason
		}
		if key == ciliumNamespaceKey {
			constrainsNamespace = true
		}
		req.Key = key
		ls.MatchExpressions = append(ls.MatchExpressions, req)
	}
	if !constrainsNamespace && implicitNamespace != "" {
		ls.MatchLabels[ciliumNamespaceKey] = implicitNamespace
	}

	selector, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return false, "unparsable endpoint selector: " + err.Error()
	}
	return selector.Matches(ciliumLabelSet(t)), ""
}

// normalizeCiliumKey strips Cilium's label-source prefixes. "k8s:" and "any:"
// both resolve to the Kubernetes label source Groma models; "reserved:" names
// an identity that is not a pod at all.
func normalizeCiliumKey(key string) (string, string) {
	switch {
	case strings.HasPrefix(key, "k8s:"):
		return strings.TrimPrefix(key, "k8s:"), ""
	case strings.HasPrefix(key, "any:"):
		return strings.TrimPrefix(key, "any:"), ""
	case strings.HasPrefix(key, "reserved:"):
		return "", "reserved label " + key
	}
	return key, ""
}

// ciliumLabelSet flattens a target into the label space Cilium selectors are
// written against.
func ciliumLabelSet(t Target) labels.Set {
	set := labels.Set{}
	for k, v := range t.PodLabels {
		set[k] = v
	}
	for k, v := range t.NamespaceLabels {
		set[ciliumNamespaceLabelKey+k] = v
	}
	set[ciliumNamespaceKey] = t.Namespace
	return set
}
