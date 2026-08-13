package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	policyapi "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/eval"

	"github.com/groma-sh/groma/internal/adapters"
	"github.com/groma-sh/groma/internal/prober"
)

// upstreamSource names the engine behind a verdict that no CNI adapter changed.
const upstreamSource = "networkpolicy"

type Analyzer struct {
	engine   *eval.PolicyEngine
	adapters []adapters.Adapter
	// nsLabels lets CNI adapters evaluate namespaceSelectors, which upstream
	// NetworkPolicy analysis resolves internally but adapters cannot.
	nsLabels map[string]map[string]string
	peers    map[string]string
	nextIP   int
	nextPod  int
}

type ConfigResult struct {
	Allows bool
	// Unknown marks a path no engine could decide, because a policy that
	// selects one of the endpoints uses a construct Groma does not model. It is
	// deliberately distinct from an error: the analysis ran and its honest
	// answer is "I cannot tell you".
	Unknown bool
	// Source is the engine that decided: "networkpolicy" for upstream analysis,
	// or the CNI adapter name(s) that overrode it.
	Source string
	// Reason and Policies cite the rule behind the verdict, so evidence can
	// point an auditor at the exact policy rather than an opaque verdict.
	Reason   string
	Policies []string
	Err      error
}

// New builds the static analyzer. Passing CNI adapters extends the analysis to
// that CNI's own policy resources; with none, only upstream NetworkPolicy and
// the network-policy-api types are modeled.
func New(ctx context.Context, k8sClient kubernetes.Interface, policyClient policyapi.Interface, cniAdapters ...adapters.Adapter) (*Analyzer, error) {
	engine := eval.NewPolicyEngine()

	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	nsLabels := make(map[string]map[string]string, len(nsList.Items))
	for i := range nsList.Items {
		if err := engine.InsertObject(&nsList.Items[i]); err != nil {
			return nil, fmt.Errorf("load namespace %q: %w", nsList.Items[i].Name, err)
		}
		nsLabels[nsList.Items[i].Name] = nsList.Items[i].Labels
	}

	npList, err := k8sClient.NetworkingV1().NetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list networkpolicies: %w", err)
	}
	for i := range npList.Items {
		if err := engine.InsertObject(&npList.Items[i]); err != nil {
			return nil, fmt.Errorf("load networkpolicy %s/%s: %w", npList.Items[i].Namespace, npList.Items[i].Name, err)
		}
	}

	if policyClient != nil {

		if err := engine.UpdatePolicyEngineWithK8sPolicyAPIObjects(policyClient); err != nil {
			return nil, fmt.Errorf("load network-policy-api objects: %w", err)
		}
	}

	return &Analyzer{engine: engine, adapters: cniAdapters, nsLabels: nsLabels, peers: map[string]string{}}, nil
}

// Adapters lists the CNI adapters in play, for the run's evidence header.
func (a *Analyzer) Adapters() []string {
	out := make([]string, 0, len(a.adapters))
	for _, ad := range a.adapters {
		out = append(out, ad.Name())
	}
	return out
}

func (a *Analyzer) Analyze(checks []prober.Check) []ConfigResult {
	out := make([]ConfigResult, len(checks))
	for i, c := range checks {

		src, err := a.peer(c.From, "src")
		if err != nil {
			out[i] = ConfigResult{Err: err}
			continue
		}
		dst, err := a.peer(c.To, "dst")
		if err != nil {
			out[i] = ConfigResult{Err: err}
			continue
		}
		allowed, err := a.engine.CheckIfAllowed(src, dst, string(c.Port.Protocol), strconv.Itoa(int(c.Port.Port)))
		if err != nil {
			out[i] = ConfigResult{Err: err}
			continue
		}
		out[i] = a.applyAdapters(c, allowed)
	}
	return out
}

// applyAdapters folds every CNI adapter's verdict over the upstream one. With no
// adapters loaded this is the upstream verdict verbatim, so a cluster running a
// CNI Groma has no adapter for behaves exactly as it did before.
func (a *Analyzer) applyAdapters(c prober.Check, upstream bool) ConfigResult {
	base := ConfigResult{Allows: upstream, Source: upstreamSource}
	if len(a.adapters) == 0 {
		return base
	}

	flow := adapters.Flow{
		Source:      a.target(c.From),
		Destination: a.target(c.To),
		Protocol:    string(c.Port.Protocol),
		Port:        c.Port.Port,
	}
	k8sVerdict := adapters.Deny
	if upstream {
		k8sVerdict = adapters.Allow
	}

	decisions := make([]adapters.Decision, 0, len(a.adapters))
	for _, ad := range a.adapters {
		decisions = append(decisions, ad.Evaluate(flow, k8sVerdict))
	}
	combined := adapters.Combine(k8sVerdict, decisions)

	switch combined.Verdict {
	case adapters.Unknown:
		return ConfigResult{Unknown: true, Source: combined.Adapter, Reason: combined.Reason, Policies: combined.Policies}
	case adapters.Allow, adapters.Deny:
		res := ConfigResult{
			Allows:   combined.Verdict == adapters.Allow,
			Source:   combined.Adapter,
			Reason:   combined.Reason,
			Policies: combined.Policies,
		}
		if res.Source == "" {
			res.Source = upstreamSource
		}
		return res
	default:
		return base
	}
}

func (a *Analyzer) target(ep prober.Endpoint) adapters.Target {
	return adapters.Target{
		Namespace:       ep.Namespace,
		NamespaceLabels: a.nsLabels[ep.Namespace],
		PodLabels:       ep.Labels,
	}
}

func (a *Analyzer) peer(ep prober.Endpoint, role string) (string, error) {
	key := role + "|" + ep.Namespace + "|" + labelsKey(ep.Labels)
	if id, ok := a.peers[key]; ok {
		return id, nil
	}
	a.nextPod++
	a.nextIP++
	name := fmt.Sprintf("groma-static-%s-%d", role, a.nextPod)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ep.Namespace, Name: name, Labels: ep.Labels},
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			HostIP: "10.0.0.1",

			PodIPs: []corev1.PodIP{{IP: fmt.Sprintf("10.244.%d.%d", a.nextIP/256, a.nextIP%256)}},
		},
	}
	if err := a.engine.InsertObject(pod); err != nil {
		return "", fmt.Errorf("synthesize representative pod in %q: %w", ep.Namespace, err)
	}
	id := ep.Namespace + "/" + name
	a.peers[key] = id
	return id, nil
}

func labelsKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
