package adapters

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// decode re-parses one unstructured policy into the minimal typed struct an
// adapter models. Going through JSON rather than the unstructured converter
// keeps the adapters free of any dependency on the CNI's own Go modules: Groma
// stays vendor-neutral in its module graph, not just in its behavior.
func decode(o unstructuredObject, out any) error {
	raw, err := json.Marshal(o.item)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", o.name, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("parse %s: %w", o.name, err)
	}
	return nil
}

// matchesSelector reports whether lbls satisfies a Kubernetes-style selector. A
// nil selector never matches: every caller decides for itself what "unset"
// means in its CNI's grammar, because the CNIs do not agree.
func matchesSelector(sel *metav1.LabelSelector, lbls map[string]string) (bool, error) {
	if sel == nil {
		return false, nil
	}
	s, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return false, err
	}
	return s.Matches(labels.Set(lbls)), nil
}

// protocolMatches compares a rule's protocol against the flow's. An empty or
// "ANY" rule protocol matches every protocol, which is how all three CNIs treat
// an omitted protocol field.
func protocolMatches(rule, flow string) bool {
	r := strings.ToUpper(strings.TrimSpace(rule))
	if r == "" || r == "ANY" {
		return true
	}
	return r == strings.ToUpper(flow)
}

// portRange is a rule's L4 port constraint, already normalized to numbers.
type portRange struct {
	from, to int32
}

func (p portRange) contains(port int32) bool {
	return port >= p.from && port <= p.to
}

// parsePort turns a rule's port field into a number. Named ports resolve
// per-pod against a container spec Groma does not have here, so they are
// reported as unresolvable and force an Unknown verdict rather than a guess.
func parsePort(raw string) (int32, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 32)
	if err != nil || n < 0 || n > 65535 {
		return 0, false
	}
	return int32(n), true
}

// numOrString decodes the numeric-or-string fields both Calico and Antrea use
// for protocols and ports: a protocol may arrive as "TCP" or as the IANA number
// 6, and a port as 5432, "5432", "6000:7000", or a container's named port.
type numOrString struct {
	str   string
	num   int64
	isNum bool
}

func (n *numOrString) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &n.str)
	}
	if err := json.Unmarshal(data, &n.num); err != nil {
		return err
	}
	n.isNum = true
	return nil
}
