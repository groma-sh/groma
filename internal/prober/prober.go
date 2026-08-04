package prober

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/intent"
)

const (
	defaultImage       = "busybox:1.36"
	connectTimeout     = 3
	podStartDeadline   = 60 * time.Second
	defaultConcurrency = 8
	defaultRetries     = 3
	podCreateRetries   = 5
	activeDeadlineSecs = 300
	managedByKey       = "app.kubernetes.io/managed-by"
	managedByVal       = "groma"
	roleKey            = "groma.dev/role"
)

type Options struct {
	MaxConcurrentProbes int
	Image               string
	Retries             int
	DryRun              bool
}

type Prober struct {
	client      kubernetes.Interface
	concurrency int
	image       string
	retries     int
	dryRun      bool
}

func New(client kubernetes.Interface, o Options) *Prober {
	if o.MaxConcurrentProbes <= 0 {
		o.MaxConcurrentProbes = defaultConcurrency
	}
	if o.Image == "" {
		o.Image = defaultImage
	}
	if o.Retries <= 0 {
		o.Retries = defaultRetries
	}
	return &Prober{
		client:      client,
		concurrency: o.MaxConcurrentProbes,
		image:       o.Image,
		retries:     o.Retries,
		dryRun:      o.DryRun,
	}
}

type resolvedZone struct {
	name       string
	namespace  string
	namespaces []string
	labels     map[string]string
}

func (z *resolvedZone) endpoint() Endpoint {
	return Endpoint{Zone: z.name, Namespace: z.namespace, Labels: z.labels}
}

type Endpoint struct {
	Zone      string
	Namespace string
	Labels    map[string]string
}

type Check struct {
	From, To        Endpoint
	Assertion       string
	Port            intent.Port
	ExpectReachable bool
	Note            string
}

func (c Check) BaseProbe() evidence.Probe {
	return evidence.Probe{
		From: c.From.Zone, To: c.To.Zone,
		FromNamespace: c.From.Namespace, ToNamespace: c.To.Namespace,
		Protocol: string(c.Port.Protocol), Port: c.Port.Port,
		Assertion: c.Assertion,
	}
}

func canaryPort(allow []intent.Port) intent.Port {
	used := map[int32]bool{}
	for _, p := range allow {
		used[p.Port] = true
	}
	for _, cand := range []int32{9999, 65000, 65533, 33333, 4242} {
		if !used[cand] {
			return intent.Port{Protocol: intent.TCP, Port: cand}
		}
	}
	return intent.Port{Protocol: intent.TCP, Port: 9998}
}

func (p *Prober) Plan(ctx context.Context, si *intent.SegmentationIntent) ([]Check, []evidence.ResolvedZone, error) {
	resolved := map[string]*resolvedZone{}
	var order []string
	for _, a := range si.Assertions {
		for _, name := range []string{a.From, a.To} {
			if _, ok := resolved[name]; ok {
				continue
			}
			rz, err := p.resolveZone(ctx, si.Zone(name))
			if err != nil {
				return nil, nil, err
			}
			resolved[name] = rz
			order = append(order, name)
		}
	}

	var checks []Check
	for _, a := range si.Assertions {
		from, to := resolved[a.From].endpoint(), resolved[a.To].endpoint()
		switch a.Type {
		case intent.MayReachOnly:
			for _, port := range a.Ports {
				checks = append(checks, Check{From: from, To: to, Assertion: string(a.Type), Port: port, ExpectReachable: true, Note: "allowlisted port"})
			}
			checks = append(checks, Check{From: from, To: to, Assertion: string(a.Type), Port: canaryPort(a.Ports), ExpectReachable: false, Note: "sampled non-allowlisted port"})
		default:
			for _, port := range a.Ports {
				checks = append(checks, Check{From: from, To: to, Assertion: string(a.Type), Port: port, ExpectReachable: a.Type == intent.MustReach})
			}
		}
	}

	zones := make([]evidence.ResolvedZone, 0, len(order))
	for _, name := range order {
		rz := resolved[name]
		zones = append(zones, evidence.ResolvedZone{
			Name:           rz.name,
			Namespace:      rz.namespace,
			Namespaces:     rz.namespaces,
			IdentityLabels: rz.labels,
		})
	}
	return checks, zones, nil
}

func (p *Prober) ProbeChecks(ctx context.Context, checks []Check) []evidence.Probe {
	out := make([]evidence.Probe, len(checks))
	sem := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup
	for i := range checks {
		wg.Add(1)
		go func(idx int, c Check) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if p.dryRun {
				out[idx] = planOne(c)
				return
			}
			out[idx] = p.probeOne(ctx, c)
		}(i, checks[i])
	}
	wg.Wait()
	return out
}

func (p *Prober) Run(ctx context.Context, si *intent.SegmentationIntent) ([]evidence.Probe, []evidence.ResolvedZone, error) {
	checks, zones, err := p.Plan(ctx, si)
	if err != nil {
		return nil, nil, err
	}
	return p.ProbeChecks(ctx, checks), zones, nil
}

func (p *Prober) resolveZone(ctx context.Context, z *intent.Zone) (*resolvedZone, error) {
	rz := &resolvedZone{name: z.Name, labels: z.IdentityLabels()}
	if z.Namespace != "" {
		if _, err := p.client.CoreV1().Namespaces().Get(ctx, z.Namespace, metav1.GetOptions{}); err != nil {
			return nil, fmt.Errorf("zone %q: namespace %q: %w", z.Name, z.Namespace, err)
		}
		rz.namespace = z.Namespace
		rz.namespaces = []string{z.Namespace}
		return rz, nil
	}

	sel := labels.SelectorFromSet(z.NamespaceSelector.MatchLabels).String()
	list, err := p.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, fmt.Errorf("zone %q: list namespaces: %w", z.Name, err)
	}
	if len(list.Items) == 0 {
		return nil, fmt.Errorf("zone %q: namespaceSelector %s matched no namespaces", z.Name, sel)
	}
	for _, ns := range list.Items {
		rz.namespaces = append(rz.namespaces, ns.Name)
	}
	sort.Strings(rz.namespaces)
	rz.namespace = rz.namespaces[0]
	return rz, nil
}

func planOne(c Check) evidence.Probe {
	expect := "blocked"
	if c.ExpectReachable {
		expect = "reachable"
	}
	res := c.BaseProbe()
	res.Result = evidence.Skipped
	res.Detail = fmt.Sprintf("dry-run: would require %s on tcp/%d from %s to %s", expect, c.Port.Port, c.From.Namespace, c.To.Namespace)
	return res
}

func (p *Prober) probeOne(ctx context.Context, c Check) evidence.Probe {
	res := c.BaseProbe()
	res.Detail = c.Note

	receiver, err := p.startReceiver(ctx, c.To, c.Port)
	if err != nil {
		res.Result = evidence.Error
		res.Detail = fmt.Sprintf("start receiver: %v", err)
		return res
	}
	defer p.deletePod(c.To.Namespace, receiver.Name)

	ip, err := p.waitForPodIP(ctx, c.To.Namespace, receiver.Name)
	if err != nil {
		res.Result = evidence.Error
		res.Detail = fmt.Sprintf("receiver not ready: %v", err)
		return res
	}

	reachable, err := p.probeFrom(ctx, c.From.Namespace, c.From.Labels, "client", ip, c.Port)
	if err != nil {
		res.Result = evidence.Error
		res.Detail = fmt.Sprintf("source probe: %v", err)
		return res
	}

	if reachable {
		res.Observed = "REACHABLE"
		if c.ExpectReachable {
			res.Result = evidence.Pass
		} else {
			res.Result = evidence.Fail
			res.Detail = "reachable but must be blocked (enforcement gap)"
		}
		return res
	}

	res.Observed = "BLOCKED"
	pc, err := p.probeFrom(ctx, c.To.Namespace, c.To.Labels, "control", ip, c.Port)
	if err != nil {
		res.Result = evidence.Error
		res.Detail = fmt.Sprintf("positive control: %v", err)
		return res
	}
	if pc {
		res.PositiveControl = "REACHABLE"
	} else {
		res.PositiveControl = "BLOCKED"
	}

	switch {
	case !pc:

		res.Result = evidence.Indeterminate
		res.Detail = "positive control failed: sentinel unreachable from an allowed source, so the block is not attributable to policy"
	case c.ExpectReachable:
		res.Result = evidence.Fail
		res.Detail = "required connectivity is blocked by policy (positive control reached the sentinel)"
	default:
		res.Result = evidence.Pass
	}
	return res
}

func (p *Prober) startReceiver(ctx context.Context, to Endpoint, port intent.Port) (*corev1.Pod, error) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "groma-recv-",
			Namespace:    to.Namespace,
			Labels:       proberLabels(to.Labels, "receiver"),
		},
		Spec: p.podSpec("recv",
			[]string{"sh", "-c", fmt.Sprintf("while true; do nc -l -p %d; done", port.Port)},
			port.Port),
	}
	pod.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: port.Port, Protocol: corev1.ProtocolTCP}}
	return p.createPod(ctx, to.Namespace, pod)
}

func (p *Prober) createPod(ctx context.Context, ns string, pod *corev1.Pod) (*corev1.Pod, error) {
	var last error
	for i := 0; i < podCreateRetries; i++ {
		created, err := p.client.CoreV1().Pods(ns).Create(ctx, pod, metav1.CreateOptions{})
		if err == nil {
			return created, nil
		}
		last = err
		if err := sleep(ctx, time.Second); err != nil {
			break
		}
	}
	return nil, last
}

func (p *Prober) probeFrom(ctx context.Context, ns string, identity map[string]string, role, targetIP string, port intent.Port) (bool, error) {
	cmd := fmt.Sprintf("i=0; while [ $i -lt %d ]; do nc -w %d %s %d </dev/null && exit 0; i=$((i+1)); sleep 1; done; exit 1",
		p.retries, connectTimeout, targetIP, port.Port)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "groma-" + role + "-",
			Namespace:    ns,
			Labels:       proberLabels(identity, role),
		},
		Spec: p.podSpec(role, []string{"sh", "-c", cmd}, 0),
	}
	created, err := p.createPod(ctx, ns, pod)
	if err != nil {
		return false, err
	}
	defer p.deletePod(ns, created.Name)

	phase, err := p.waitForPodFinish(ctx, ns, created.Name)
	if err != nil {
		return false, err
	}
	switch phase {
	case corev1.PodSucceeded:
		return true, nil
	case corev1.PodFailed:
		return false, nil
	default:
		return false, fmt.Errorf("probe pod ended in phase %s", phase)
	}
}

func (p *Prober) waitForPodIP(ctx context.Context, ns, name string) (string, error) {
	deadline := time.Now().Add(podStartDeadline)
	for time.Now().Before(deadline) {
		pod, err := p.client.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		if pod.Status.Phase == corev1.PodRunning && pod.Status.PodIP != "" {
			return pod.Status.PodIP, nil
		}
		if pod.Status.Phase == corev1.PodFailed {
			return "", fmt.Errorf("receiver pod entered Failed phase")
		}
		if err := sleep(ctx, time.Second); err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("timed out waiting for receiver pod IP")
}

func (p *Prober) probeBudget() time.Duration {
	return time.Duration(p.retries*(connectTimeout+1))*time.Second + podStartDeadline
}

func (p *Prober) waitForPodFinish(ctx context.Context, ns, name string) (corev1.PodPhase, error) {
	deadline := time.Now().Add(p.probeBudget())
	for time.Now().Before(deadline) {
		pod, err := p.client.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "", err
		}
		switch pod.Status.Phase {
		case corev1.PodSucceeded, corev1.PodFailed:
			return pod.Status.Phase, nil
		}
		if err := sleep(ctx, time.Second); err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("timed out waiting for probe to finish")
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func (p *Prober) deletePod(ns, name string) {
	grace := int64(0)
	_ = p.client.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{GracePeriodSeconds: &grace})
}

func (p *Prober) podSpec(name string, command []string, listenPort int32) corev1.PodSpec {
	nonRoot := true
	user := int64(65534)
	noEscalate := false
	deadline := int64(activeDeadlineSecs)
	noToken := false

	drop := corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}
	if listenPort > 0 && listenPort < 1024 {
		drop.Add = []corev1.Capability{"NET_BIND_SERVICE"}
	}

	return corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		AutomountServiceAccountToken: &noToken,
		ActiveDeadlineSeconds:        &deadline,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   &nonRoot,
			RunAsUser:      &user,
			RunAsGroup:     &user,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name:    name,
			Image:   p.image,
			Command: command,
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: &noEscalate,
				Capabilities:             &drop,
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("10m"),
					corev1.ResourceMemory: resource.MustParse("16Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("32Mi"),
				},
			},
		}},
	}
}

func proberLabels(identity map[string]string, role string) map[string]string {
	l := map[string]string{managedByKey: managedByVal, roleKey: role}
	for k, v := range identity {
		l[k] = v
	}
	return l
}
