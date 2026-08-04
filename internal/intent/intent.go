package intent

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

type Protocol string

const (
	TCP Protocol = "TCP"
	UDP Protocol = "UDP"
)

type Port struct {
	Protocol Protocol `json:"protocol"`
	Port     int32    `json:"port"`
}

type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type Zone struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	NamespaceSelector *LabelSelector    `json:"namespaceSelector,omitempty"`
	PodLabels         map[string]string `json:"podLabels,omitempty"`
	PodSelector       *LabelSelector    `json:"podSelector,omitempty"`
}

func (z *Zone) IdentityLabels() map[string]string {
	if len(z.PodLabels) > 0 {
		return z.PodLabels
	}
	if z.PodSelector != nil {
		return z.PodSelector.MatchLabels
	}
	return nil
}

type AssertionType string

const (
	MustNotReach AssertionType = "MustNotReach"
	MustReach    AssertionType = "MustReach"

	MayReachOnly AssertionType = "MayReachOnly"
)

type Assertion struct {
	From  string        `json:"from"`
	To    string        `json:"to"`
	Type  AssertionType `json:"type"`
	Ports []Port        `json:"ports"`
}

type Compliance struct {
	Framework string   `json:"framework,omitempty"`
	Controls  []string `json:"controls,omitempty"`
}

type Meta struct {
	Name string `json:"name"`
}

type SegmentationIntent struct {
	APIVersion string      `json:"apiVersion"`
	Kind       string      `json:"kind"`
	Metadata   Meta        `json:"metadata"`
	Zones      []Zone      `json:"zones"`
	Assertions []Assertion `json:"assertions"`
	Compliance Compliance  `json:"compliance,omitempty"`
}

func Load(path string) (*SegmentationIntent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var si SegmentationIntent
	if err := yaml.Unmarshal(data, &si); err != nil {
		return nil, fmt.Errorf("parse intent: %w", err)
	}
	if err := si.validate(); err != nil {
		return nil, err
	}
	return &si, nil
}

func (si *SegmentationIntent) validate() error {
	if si.Kind != "SegmentationIntent" {
		return fmt.Errorf("unexpected kind %q, want SegmentationIntent", si.Kind)
	}
	zones := map[string]bool{}
	for _, z := range si.Zones {
		if z.Name == "" {
			return fmt.Errorf("zone with empty name")
		}
		if (z.Namespace == "") == (z.NamespaceSelector == nil) {
			return fmt.Errorf("zone %q: set exactly one of namespace or namespaceSelector", z.Name)
		}
		if z.NamespaceSelector != nil && len(z.NamespaceSelector.MatchLabels) == 0 {
			return fmt.Errorf("zone %q: namespaceSelector.matchLabels must not be empty", z.Name)
		}
		if len(z.PodLabels) > 0 && z.PodSelector != nil {
			return fmt.Errorf("zone %q: set at most one of podLabels or podSelector", z.Name)
		}
		if zones[z.Name] {
			return fmt.Errorf("duplicate zone name %q", z.Name)
		}
		zones[z.Name] = true
	}
	for i, a := range si.Assertions {
		if !zones[a.From] {
			return fmt.Errorf("assertion %d: unknown from-zone %q", i, a.From)
		}
		if !zones[a.To] {
			return fmt.Errorf("assertion %d: unknown to-zone %q", i, a.To)
		}
		if a.Type != MustNotReach && a.Type != MustReach && a.Type != MayReachOnly {
			return fmt.Errorf("assertion %d: invalid type %q", i, a.Type)
		}
		if len(a.Ports) == 0 {
			return fmt.Errorf("assertion %d: no ports", i)
		}
		for _, p := range a.Ports {
			if p.Protocol != TCP {
				return fmt.Errorf("assertion %d: only TCP is supported (UDP/SCTP planned), got %q", i, p.Protocol)
			}
		}
	}
	return nil
}

func (si *SegmentationIntent) Zone(name string) *Zone {
	for i := range si.Zones {
		if si.Zones[i].Name == name {
			return &si.Zones[i]
		}
	}
	return nil
}
