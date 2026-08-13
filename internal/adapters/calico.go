package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Calico exposes a pod's namespace and orchestrator as labels on the endpoint,
// and a namespace's own name as a label on the namespace, so selectors can
// reach across namespaces.
const (
	calicoNamespaceKey    = "projectcalico.org/namespace"
	calicoOrchestratorKey = "projectcalico.org/orchestrator"
	calicoNameKey         = "projectcalico.org/name"
	calicoDefaultTier     = "default"
)

// Calico is served under projectcalico.org/v3 when the API server is deployed
// and under crd.projectcalico.org/v1 when only the CRDs are. Listing both and
// ignoring whichever is absent covers every install shape.
var calicoGVRs = []schema.GroupVersionResource{
	{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"},
	{Group: "projectcalico.org", Version: "v3", Resource: "globalnetworkpolicies"},
	{Group: "crd.projectcalico.org", Version: "v1", Resource: "networkpolicies"},
	{Group: "crd.projectcalico.org", Version: "v1", Resource: "globalnetworkpolicies"},
}

var calicoKinds = map[string]string{
	"networkpolicies":       "Calico NetworkPolicy",
	"globalnetworkpolicies": "GlobalNetworkPolicy",
}

type calicoEntityRule struct {
	Nets              []string        `json:"nets,omitempty"`
	NotNets           []string        `json:"notNets,omitempty"`
	Selector          string          `json:"selector,omitempty"`
	NotSelector       string          `json:"notSelector,omitempty"`
	NamespaceSelector string          `json:"namespaceSelector,omitempty"`
	Ports             []numOrString   `json:"ports,omitempty"`
	NotPorts          []numOrString   `json:"notPorts,omitempty"`
	ServiceAccounts   json.RawMessage `json:"serviceAccounts,omitempty"`
	Services          json.RawMessage `json:"services,omitempty"`
}

type calicoRule struct {
	Action      string           `json:"action"`
	Protocol    *numOrString     `json:"protocol,omitempty"`
	NotProtocol *numOrString     `json:"notProtocol,omitempty"`
	ICMP        json.RawMessage  `json:"icmp,omitempty"`
	NotICMP     json.RawMessage  `json:"notICMP,omitempty"`
	HTTP        json.RawMessage  `json:"http,omitempty"`
	Source      calicoEntityRule `json:"source,omitempty"`
	Destination calicoEntityRule `json:"destination,omitempty"`
}

type calicoSpec struct {
	Tier                   string       `json:"tier,omitempty"`
	Order                  *float64     `json:"order,omitempty"`
	Selector               string       `json:"selector,omitempty"`
	NamespaceSelector      string       `json:"namespaceSelector,omitempty"`
	ServiceAccountSelector string       `json:"serviceAccountSelector,omitempty"`
	Types                  []string     `json:"types,omitempty"`
	Ingress                []calicoRule `json:"ingress,omitempty"`
	Egress                 []calicoRule `json:"egress,omitempty"`
	DoNotTrack             bool         `json:"doNotTrack,omitempty"`
	PreDNAT                bool         `json:"preDNAT,omitempty"`
}

type calicoPolicyDoc struct {
	Spec calicoSpec `json:"spec"`
}

type calicoPolicy struct {
	id        string
	name      string
	namespace string
	spec      calicoSpec
}

type calicoAdapter struct {
	policies []calicoPolicy
}

// LoadCalico reads Calico NetworkPolicy and GlobalNetworkPolicy from the
// cluster. It returns (nil, nil) when neither is served.
func LoadCalico(ctx context.Context, dc dynamic.Interface) (Adapter, error) {
	objs, served, err := listAll(ctx, dc, calicoGVRs)
	if err != nil {
		return nil, err
	}
	if !served {
		return nil, nil
	}
	a := &calicoAdapter{}
	for _, o := range objs {
		var doc calicoPolicyDoc
		if err := decode(o, &doc); err != nil {
			return nil, err
		}
		a.policies = append(a.policies, calicoPolicy{
			id: o.id(calicoKinds[o.gvr.Resource]), name: o.name, namespace: o.namespace, spec: doc.Spec,
		})
	}
	// Calico evaluates a tier's policies in ascending order, with unset order
	// last; name is the tie-break so the result is stable across runs.
	sort.SliceStable(a.policies, func(i, j int) bool {
		oi, oj := a.policies[i].spec.Order, a.policies[j].spec.Order
		switch {
		case oi == nil && oj == nil:
			return a.policies[i].name < a.policies[j].name
		case oi == nil:
			return false
		case oj == nil:
			return true
		case *oi != *oj:
			return *oi < *oj
		}
		return a.policies[i].name < a.policies[j].name
	})
	return a, nil
}

func (a *calicoAdapter) Name() string { return "calico" }

// Evaluate walks Calico's default tier in order. The first rule whose match
// criteria cover the flow decides it. When policies apply to an endpoint but no
// rule matches, Calico falls through to the policies it synthesizes from
// upstream NetworkPolicy objects (the knp.default.* set, order 1000), so this
// adapter abstains and lets the np-guard verdict stand.
//
// Modeled scope: the default tier only. A selecting policy in another tier, or
// a Pass action, delegates across a tier boundary this adapter does not order,
// and yields Unknown.
func (a *calicoAdapter) Evaluate(flow Flow, _ Verdict) Decision {
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

func (a *calicoAdapter) direction(flow Flow, egress bool) Decision {
	subject := flow.Destination
	if egress {
		subject = flow.Source
	}

	var applied []string
	for _, p := range a.policies {
		applies, reason := a.applies(p, subject, egress)
		if reason != "" {
			return Decision{Verdict: Unknown, Adapter: a.Name(),
				Reason: p.id + ": " + reason, Policies: []string{p.id}}
		}
		if !applies {
			continue
		}
		if tier := p.spec.Tier; tier != "" && tier != calicoDefaultTier {
			return Decision{Verdict: Unknown, Adapter: a.Name(),
				Reason:   fmt.Sprintf("%s is in tier %q; Groma models the default tier only", p.id, tier),
				Policies: []string{p.id}}
		}
		applied = append(applied, p.id)

		rules := p.spec.Ingress
		if egress {
			rules = p.spec.Egress
		}
		for i, r := range rules {
			match, reason := a.ruleMatches(p, r, flow)
			if reason != "" {
				return Decision{Verdict: Unknown, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s %s rule %d: %s", p.id, directionWord(egress), i, reason),
					Policies: []string{p.id}}
			}
			if !match {
				continue
			}
			switch strings.ToLower(r.Action) {
			case "allow":
				return Decision{Verdict: Allow, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s %s rule %d allows this path", p.id, directionWord(egress), i),
					Policies: []string{p.id}}
			case "deny":
				return Decision{Verdict: Deny, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s %s rule %d denies this path", p.id, directionWord(egress), i),
					Policies: []string{p.id}}
			case "log":
				// Log is not terminal; evaluation continues to the next rule.
				continue
			case "pass":
				return Decision{Verdict: Unknown, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s %s rule %d uses the Pass action, which delegates across tiers Groma does not model", p.id, directionWord(egress), i),
					Policies: []string{p.id}}
			default:
				return Decision{Verdict: Unknown, Adapter: a.Name(),
					Reason:   fmt.Sprintf("%s %s rule %d has unknown action %q", p.id, directionWord(egress), i, r.Action),
					Policies: []string{p.id}}
			}
		}
	}
	if len(applied) == 0 {
		return Decision{Verdict: NoOpinion, Adapter: a.Name()}
	}
	// Policies applied but nothing matched, so Calico continues past them into
	// the converted upstream NetworkPolicy set. Abstaining hands the decision to
	// the np-guard verdict, which models exactly that set.
	return Decision{Verdict: NoOpinion, Adapter: a.Name(),
		Reason:   "Calico policies apply but no rule matched; upstream NetworkPolicy decides: " + strings.Join(applied, ", "),
		Policies: applied}
}

// applies reports whether a policy governs the subject endpoint for a direction.
func (a *calicoAdapter) applies(p calicoPolicy, t Target, egress bool) (bool, string) {
	if p.spec.ServiceAccountSelector != "" {
		return false, "serviceAccountSelector is not modeled"
	}
	if p.spec.DoNotTrack || p.spec.PreDNAT {
		return false, "doNotTrack/preDNAT policies apply to host endpoints, which Groma does not model"
	}
	if !calicoGoverns(p.spec, egress) {
		return false, ""
	}
	if p.namespace != "" && p.namespace != t.Namespace {
		return false, ""
	}
	if p.namespace == "" && p.spec.NamespaceSelector != "" {
		match, err := evalCalicoSelector(p.spec.NamespaceSelector, calicoNamespaceLabelSet(t))
		if err != nil {
			return false, "namespaceSelector: " + err.Error()
		}
		if !match {
			return false, ""
		}
	}
	match, err := evalCalicoSelector(p.spec.Selector, calicoEndpointLabelSet(t))
	if err != nil {
		return false, "selector: " + err.Error()
	}
	return match, ""
}

// calicoGoverns implements spec.types, including Calico's default: Ingress when
// there are no egress rules, Egress when there are egress rules but no ingress
// rules, and both otherwise.
func calicoGoverns(spec calicoSpec, egress bool) bool {
	if len(spec.Types) > 0 {
		want := "ingress"
		if egress {
			want = "egress"
		}
		for _, t := range spec.Types {
			if strings.EqualFold(t, want) {
				return true
			}
		}
		return false
	}
	switch {
	case len(spec.Egress) == 0:
		return !egress
	case len(spec.Ingress) == 0:
		return egress
	default:
		return true
	}
}

func (a *calicoAdapter) ruleMatches(p calicoPolicy, r calicoRule, flow Flow) (bool, string) {
	if len(r.ICMP) > 0 || len(r.NotICMP) > 0 {
		return false, "icmp match criteria are not modeled"
	}
	if len(r.HTTP) > 0 {
		return false, "http match criteria decide below the port layer"
	}
	if r.Protocol != nil {
		ok, reason := calicoProtocolMatches(*r.Protocol, flow.Protocol)
		if reason != "" {
			return false, reason
		}
		if !ok {
			return false, ""
		}
	}
	if r.NotProtocol != nil {
		ok, reason := calicoProtocolMatches(*r.NotProtocol, flow.Protocol)
		if reason != "" {
			return false, reason
		}
		if ok {
			return false, ""
		}
	}
	// A Calico rule names source and destination explicitly in both directions,
	// so the same comparison serves ingress and egress.
	if ok, reason := a.entityMatches(p, r.Source, flow.Source, flow, false); reason != "" || !ok {
		return false, reason
	}
	if ok, reason := a.entityMatches(p, r.Destination, flow.Destination, flow, true); reason != "" || !ok {
		return false, reason
	}
	return true, ""
}

// entityMatches evaluates one side of a Calico rule. isDestination selects
// which side's port constraints apply to the flow's port.
func (a *calicoAdapter) entityMatches(p calicoPolicy, e calicoEntityRule, t Target, flow Flow, isDestination bool) (bool, string) {
	if len(e.Nets) > 0 || len(e.NotNets) > 0 {
		return false, "nets/notNets need pod IPs, which are not known statically"
	}
	if len(e.ServiceAccounts) > 0 {
		return false, "serviceAccounts match criteria are not modeled"
	}
	if len(e.Services) > 0 {
		return false, "services match criteria are not modeled"
	}

	// A namespaced policy confines a bare selector to its own namespace; a
	// global policy does not, unless it names a namespaceSelector.
	switch {
	case e.NamespaceSelector != "":
		match, err := evalCalicoSelector(e.NamespaceSelector, calicoNamespaceLabelSet(t))
		if err != nil {
			return false, "namespaceSelector: " + err.Error()
		}
		if !match {
			return false, ""
		}
	case p.namespace != "" && p.namespace != t.Namespace:
		return false, ""
	}

	if e.Selector != "" {
		match, err := evalCalicoSelector(e.Selector, calicoEndpointLabelSet(t))
		if err != nil {
			return false, "selector: " + err.Error()
		}
		if !match {
			return false, ""
		}
	}
	if e.NotSelector != "" {
		match, err := evalCalicoSelector(e.NotSelector, calicoEndpointLabelSet(t))
		if err != nil {
			return false, "notSelector: " + err.Error()
		}
		if match {
			return false, ""
		}
	}

	if !isDestination {
		// Source ports constrain the ephemeral port a client happens to pick,
		// which no static model can predict.
		if len(e.Ports) > 0 || len(e.NotPorts) > 0 {
			return false, "source port match criteria are not modeled"
		}
		return true, ""
	}
	if len(e.Ports) > 0 {
		match, reason := calicoPortsMatch(e.Ports, flow.Port)
		if reason != "" {
			return false, reason
		}
		if !match {
			return false, ""
		}
	}
	if len(e.NotPorts) > 0 {
		match, reason := calicoPortsMatch(e.NotPorts, flow.Port)
		if reason != "" {
			return false, reason
		}
		if match {
			return false, ""
		}
	}
	return true, ""
}

// calicoProtocolMatches compares a Calico protocol field, which may be a name
// ("TCP") or an IANA protocol number (6), against the flow's protocol.
func calicoProtocolMatches(p numOrString, flow string) (bool, string) {
	if !p.isNum {
		return protocolMatches(p.str, flow), ""
	}
	names := map[int64]string{1: "ICMP", 6: "TCP", 17: "UDP", 132: "SCTP", 58: "ICMPv6"}
	name, ok := names[p.num]
	if !ok {
		return false, "protocol number " + strconv.FormatInt(p.num, 10)
	}
	return protocolMatches(name, flow), ""
}

// calicoPortsMatch handles Calico's three port shapes: a number, a "from:to"
// range string, and a named port that only resolves against a container spec.
func calicoPortsMatch(ports []numOrString, port int32) (bool, string) {
	for _, p := range ports {
		if p.isNum {
			if int32(p.num) == port {
				return true, ""
			}
			continue
		}
		from, to, ok := parseCalicoPortRange(p.str)
		if !ok {
			return false, "named or unparsable port " + p.str
		}
		if (portRange{from: from, to: to}).contains(port) {
			return true, ""
		}
	}
	return false, ""
}

func parseCalicoPortRange(s string) (from, to int32, ok bool) {
	lo, hi, isRange := strings.Cut(s, ":")
	from, ok = parsePort(lo)
	if !ok {
		return 0, 0, false
	}
	if !isRange {
		return from, from, true
	}
	to, ok = parsePort(hi)
	if !ok {
		return 0, 0, false
	}
	return from, to, true
}

func evalCalicoSelector(selector string, set labels.Set) (bool, error) {
	expr, err := parseCalicoSelector(selector)
	if err != nil {
		return false, err
	}
	return expr.eval(set), nil
}

// calicoEndpointLabelSet is the label space a Calico endpoint selector matches
// against: the pod's own labels plus the identity labels Calico synthesizes.
func calicoEndpointLabelSet(t Target) labels.Set {
	set := labels.Set{}
	for k, v := range t.PodLabels {
		set[k] = v
	}
	set[calicoNamespaceKey] = t.Namespace
	set[calicoOrchestratorKey] = "k8s"
	return set
}

// calicoNamespaceLabelSet is the label space a namespaceSelector matches
// against: the namespace's labels plus its name.
func calicoNamespaceLabelSet(t Target) labels.Set {
	set := labels.Set{}
	for k, v := range t.NamespaceLabels {
		set[k] = v
	}
	set[calicoNameKey] = t.Namespace
	return set
}
