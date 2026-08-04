package compliance

import (
	"sort"
	"strings"

	"github.com/groma-sh/groma/internal/intent"
)

type Control struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Title     string `json:"title"`
	Rationale string `json:"rationale"`
}

var pciTitles = map[string]string{
	"11.4.5": "Penetration testing is performed on segmentation controls at least once every 12 months and after any changes",
	"1.3.1":  "Inbound traffic to the CDE is restricted to only necessary traffic",
	"1.3.2":  "Outbound traffic from the CDE is restricted to only necessary traffic",
	"1.4.1":  "Network security controls are implemented between trusted and untrusted networks",
}

type controlRef struct {
	id        string
	rationale string
}

var pciCatalog = map[intent.AssertionType][]controlRef{
	intent.MustNotReach: {
		{"11.4.5", "actively proving this path is blocked is the segmentation penetration test 11.4.5 requires, performed continuously rather than annually"},
		{"1.3.1", "confirms inbound traffic into the protected zone is restricted so the out-of-scope source cannot reach it"},
	},
	intent.MayReachOnly: {
		{"11.4.5", "actively proving only the allowlisted ports are reachable is a segmentation control test under 11.4.5"},
		{"1.3.1", "confirms inbound traffic into the zone is restricted to only the necessary (allowlisted) ports"},
	},
}

func Map(framework string, assertionType string) []Control {
	if !isPCI(framework) {
		return nil
	}
	refs := pciCatalog[intent.AssertionType(assertionType)]
	if len(refs) == 0 {
		return nil
	}
	out := make([]Control, 0, len(refs))
	for _, r := range refs {
		out = append(out, Control{
			Framework: "PCI-DSS-4.0",
			ID:        r.id,
			Title:     pciTitles[r.id],
			Rationale: r.rationale,
		})
	}
	return out
}

func Controls(framework string) []string {
	if !isPCI(framework) {
		return nil
	}
	seen := map[string]bool{}
	for _, refs := range pciCatalog {
		for _, r := range refs {
			seen[r.id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func isPCI(framework string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(framework)), "PCI-DSS")
}
