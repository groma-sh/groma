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

	"github.com/groma-sh/groma/internal/prober"
)

type Analyzer struct {
	engine  *eval.PolicyEngine
	peers   map[string]string
	nextIP  int
	nextPod int
}

type ConfigResult struct {
	Allows bool
	Err    error
}

func New(ctx context.Context, k8sClient kubernetes.Interface, policyClient policyapi.Interface) (*Analyzer, error) {
	engine := eval.NewPolicyEngine()

	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	for i := range nsList.Items {
		if err := engine.InsertObject(&nsList.Items[i]); err != nil {
			return nil, fmt.Errorf("load namespace %q: %w", nsList.Items[i].Name, err)
		}
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

	return &Analyzer{engine: engine, peers: map[string]string{}}, nil
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
		out[i] = ConfigResult{Allows: allowed, Err: err}
	}
	return out
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
