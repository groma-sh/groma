package adapters

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"sigs.k8s.io/yaml"
)

// testListKinds registers every GVR the adapters query, so a fake cluster
// behaves like one with all three CNIs' CRDs installed and simply empty.
var testListKinds = map[schema.GroupVersionResource]string{
	{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}:             "CiliumNetworkPolicyList",
	{Group: "cilium.io", Version: "v2", Resource: "ciliumclusterwidenetworkpolicies"}:  "CiliumClusterwideNetworkPolicyList",
	{Group: "projectcalico.org", Version: "v3", Resource: "networkpolicies"}:           "NetworkPolicyList",
	{Group: "projectcalico.org", Version: "v3", Resource: "globalnetworkpolicies"}:     "GlobalNetworkPolicyList",
	{Group: "crd.projectcalico.org", Version: "v1", Resource: "networkpolicies"}:       "NetworkPolicyList",
	{Group: "crd.projectcalico.org", Version: "v1", Resource: "globalnetworkpolicies"}: "GlobalNetworkPolicyList",
	{Group: "crd.antrea.io", Version: "v1beta1", Resource: "clusternetworkpolicies"}:   "ClusterNetworkPolicyList",
	{Group: "crd.antrea.io", Version: "v1beta1", Resource: "networkpolicies"}:          "NetworkPolicyList",
	{Group: "crd.antrea.io", Version: "v1alpha1", Resource: "clusternetworkpolicies"}:  "ClusterNetworkPolicyList",
	{Group: "crd.antrea.io", Version: "v1alpha1", Resource: "networkpolicies"}:         "NetworkPolicyList",
}

func fakeDynamic(t *testing.T, docs ...string) dynamic.Interface {
	t.Helper()
	objs := make([]runtime.Object, 0, len(docs))
	for _, doc := range docs {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("parse test policy: %v", err)
		}
		objs = append(objs, &unstructured.Unstructured{Object: m})
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), testListKinds, objs...)
}

func loadAdapter(t *testing.T, load Loader, docs ...string) Adapter {
	t.Helper()
	a, err := load(context.Background(), fakeDynamic(t, docs...))
	if err != nil {
		t.Fatalf("load adapter: %v", err)
	}
	if a == nil {
		t.Fatal("adapter reported its CRDs as absent, but the fake cluster serves them")
	}
	return a
}

// flow is the running example: a web pod in the frontend namespace reaching the
// payments database in the cardholder-data namespace on postgres.
func flow() Flow {
	return Flow{
		Source: Target{
			Namespace:       "frontend",
			NamespaceLabels: map[string]string{"pci-scope": "out"},
			PodLabels:       map[string]string{"app": "web"},
		},
		Destination: Target{
			Namespace:       "cde",
			NamespaceLabels: map[string]string{"pci-scope": "cde"},
			PodLabels:       map[string]string{"app": "payments-db"},
		},
		Protocol: "TCP",
		Port:     5432,
	}
}

func assertVerdict(t *testing.T, got Decision, want Verdict) {
	t.Helper()
	if got.Verdict != want {
		t.Fatalf("verdict = %s (%s), want %s", got.Verdict, got.Reason, want)
	}
}
