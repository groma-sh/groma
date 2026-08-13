package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/groma-sh/groma/internal/compliance"
	"github.com/groma-sh/groma/internal/evidence"
	"github.com/groma-sh/groma/internal/intent"
)

const (
	StatementType = "https://in-toto.io/Statement/v1"

	PredicateType = "https://groma.dev/attestations/SegmentationConformance/v1"
)

type Meta struct {
	GromaVersion string
	ClusterID    string
	CNI          string
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

type Predicate struct {
	GromaVersion      string   `json:"gromaVersion"`
	Intent            string   `json:"intent"`
	Framework         string   `json:"framework,omitempty"`
	DeclaredControls  []string `json:"declaredControls,omitempty"`
	EvidencedControls []string `json:"evidencedControls,omitempty"`
	Mode              string   `json:"mode"`
	// CNIAdapters names the CNI-native policy engines the static analysis used
	// beyond upstream NetworkPolicy.
	CNIAdapters              []string          `json:"cniAdapters,omitempty"`
	Result                   string            `json:"result"`
	StartedAt                time.Time         `json:"startedAt"`
	FinishedAt               time.Time         `json:"finishedAt"`
	Cluster                  string            `json:"cluster,omitempty"`
	CNI                      string            `json:"cni,omitempty"`
	EnforcementMatchesConfig *bool             `json:"enforcementMatchesConfig,omitempty"`
	EnforcementDetail        string            `json:"enforcementDetail,omitempty"`
	Assertions               []AssertionRecord `json:"assertions"`
}

type AssertionRecord struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	FromNamespace string   `json:"fromNamespace,omitempty"`
	ToNamespace   string   `json:"toNamespace,omitempty"`
	Assertion     string   `json:"assertion"`
	Protocol      string   `json:"protocol"`
	Port          int32    `json:"port"`
	Methods       []string `json:"methods"`
	ConfigAllows  *bool    `json:"configAllows,omitempty"`
	// ConfigSource names the engine that decided ConfigAllows ("networkpolicy"
	// or a CNI adapter name); ConfigReason and ConfigPolicies cite the rule. A
	// nil ConfigAllows with a ConfigSource set means the config verdict was
	// undecidable, and ConfigReason says which construct made it so.
	ConfigSource     string               `json:"configSource,omitempty"`
	ConfigReason     string               `json:"configReason,omitempty"`
	ConfigPolicies   []string             `json:"configPolicies,omitempty"`
	RuntimeReachable string               `json:"runtimeReachable,omitempty"`
	PositiveControl  string               `json:"positiveControl,omitempty"`
	Reconciliation   string               `json:"reconciliation,omitempty"`
	Result           string               `json:"result"`
	MappedControls   []compliance.Control `json:"mappedControls,omitempty"`
	Detail           string               `json:"detail,omitempty"`
}

func BuildStatement(report *evidence.Report, si *intent.SegmentationIntent, meta Meta) (*Statement, error) {
	digest, err := intentDigest(si)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Type: StatementType,
		Subject: []Subject{{
			Name:   "SegmentationIntent/" + report.Intent,
			Digest: map[string]string{"sha256": digest},
		}},
		PredicateType: PredicateType,
		Predicate:     buildPredicate(report, meta),
	}, nil
}

func (s *Statement) Marshal() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func buildPredicate(report *evidence.Report, meta Meta) Predicate {
	methods := methodsFor(report.Mode)
	records := make([]AssertionRecord, len(report.Probes))
	for i, p := range report.Probes {
		records[i] = AssertionRecord{
			From:             p.From,
			To:               p.To,
			FromNamespace:    p.FromNamespace,
			ToNamespace:      p.ToNamespace,
			Assertion:        p.Assertion,
			Protocol:         p.Protocol,
			Port:             p.Port,
			Methods:          methods,
			ConfigAllows:     configAllows(p.Config),
			ConfigSource:     p.ConfigSource,
			ConfigReason:     p.ConfigReason,
			ConfigPolicies:   p.ConfigPolicies,
			RuntimeReachable: p.Observed,
			PositiveControl:  p.PositiveControl,
			Reconciliation:   p.Reconciliation,
			Result:           string(p.Result),
			MappedControls:   compliance.Map(report.Framework, p.Assertion),
			Detail:           p.Detail,
		}
	}
	return Predicate{
		GromaVersion:             meta.GromaVersion,
		Intent:                   report.Intent,
		Framework:                report.Framework,
		DeclaredControls:         report.Controls,
		EvidencedControls:        compliance.Controls(report.Framework),
		Mode:                     report.Mode,
		CNIAdapters:              report.CNIAdapters,
		Result:                   string(report.Result),
		StartedAt:                report.StartedAt,
		FinishedAt:               report.FinishedAt,
		Cluster:                  meta.ClusterID,
		CNI:                      meta.CNI,
		EnforcementMatchesConfig: report.EnforcementMatchesConfig,
		EnforcementDetail:        report.EnforcementDetail,
		Assertions:               records,
	}
}

func intentDigest(si *intent.SegmentationIntent) (string, error) {
	b, err := json.Marshal(si)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func methodsFor(mode string) []string {
	switch mode {
	case "active+static":
		return []string{"static", "active"}
	case "static":
		return []string{"static"}
	default:
		return []string{"active"}
	}
}

func configAllows(s string) *bool {
	switch s {
	case "ALLOWED":
		t := true
		return &t
	case "DENIED":
		f := false
		return &f
	}
	return nil
}
