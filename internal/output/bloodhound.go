package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ajm4n/certigo/internal/adcs"
)

// BloodHoundFormatter emits a BloodHound CE OpenGraph document describing the
// ADCS escalation edges discovered by certigo. The schema follows the
// SpecterOps BloodHound OpenGraph ingestion model - a single top-level
// object with "graph.nodes" and "graph.edges" arrays. Each edge's "kind" is
// the ESC class (e.g. "ADCSESC1"), its "start" is the principal SID holding
// the enrollment right, and its "end" is the CA that publishes the template.
//
// Reference: BloodHound CE OpenGraph ingestion format, as used by the
// SpecterOps Certipy-to-BloodHound plugin. When the exact BloodHound schema
// evolves, the translate-edge logic here is the only place that changes.
type BloodHoundFormatter struct{}

// Name returns the format identifier.
func (BloodHoundFormatter) Name() string { return "bloodhound" }

func init() { register(BloodHoundFormatter{}) }

type bhDoc struct {
	Graph bhGraph `json:"graph"`
}

type bhGraph struct {
	Nodes []bhNode `json:"nodes"`
	Edges []bhEdge `json:"edges"`
}

type bhNode struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds,omitempty"`
	Properties map[string]any `json:"properties"`
}

type bhEdge struct {
	Start      bhRef          `json:"start"`
	End        bhRef          `json:"end"`
	Kind       string         `json:"kind"`
	Properties map[string]any `json:"properties,omitempty"`
}

type bhRef struct {
	Value string `json:"value"`
	Kind  string `json:"kind,omitempty"`
}

// Format writes the BloodHound document to w.
func (BloodHoundFormatter) Format(w io.Writer, cas []*adcs.CertificateAuthority, templates []*adcs.Template) error {
	doc := buildBloodHoundDoc(cas, templates)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("output/bloodhound: encode: %w", err)
	}
	return nil
}

func buildBloodHoundDoc(cas []*adcs.CertificateAuthority, templates []*adcs.Template) bhDoc {
	// Index CAs by name for quick lookup when resolving a template's publishers.
	caByName := make(map[string]*adcs.CertificateAuthority, len(cas))
	for _, ca := range cas {
		if ca == nil {
			continue
		}
		caByName[ca.Name] = ca
	}

	nodes := map[string]bhNode{}
	edges := []bhEdge{}

	addNode := func(id string, kind string, props map[string]any) {
		if id == "" {
			return
		}
		if existing, ok := nodes[id]; ok {
			// merge new kind into existing node if absent
			if kind != "" && !containsString(existing.Kinds, kind) {
				existing.Kinds = append(existing.Kinds, kind)
				nodes[id] = existing
			}
			return
		}
		n := bhNode{ID: id, Properties: props}
		if kind != "" {
			n.Kinds = []string{kind}
		}
		if n.Properties == nil {
			n.Properties = map[string]any{}
		}
		nodes[id] = n
	}

	// Seed nodes for every discovered CA.
	for _, ca := range cas {
		if ca == nil {
			continue
		}
		addNode(ca.Name, "EnterpriseCA", map[string]any{
			"name":           ca.Name,
			"dnsname":        ca.DNSName,
			"type":           "EnterpriseCA",
			"web_enrollment": ca.WebEnrollment,
		})
	}

	// For each template with findings, emit edges.
	for _, t := range templates {
		if t == nil || len(t.Findings) == 0 {
			continue
		}
		publishers := resolvePublishers(t, caByName)
		for _, f := range t.Findings {
			kind := bloodhoundEdgeKind(f.ESC)
			if kind == "" {
				continue
			}
			for _, ace := range t.EnrollmentRights {
				sid := ace.SID
				if sid == "" {
					sid = ace.Name
				}
				if sid == "" {
					continue
				}
				addNode(sid, inferPrincipalKind(ace), map[string]any{
					"name": firstNonEmpty(ace.Name, sid),
					"type": inferPrincipalKind(ace),
				})
				for _, ca := range publishers {
					addNode(ca.Name, "EnterpriseCA", map[string]any{
						"name":    ca.Name,
						"dnsname": ca.DNSName,
						"type":    "EnterpriseCA",
					})
					edges = append(edges, bhEdge{
						Start: bhRef{Value: sid},
						End:   bhRef{Value: ca.Name, Kind: "EnterpriseCA"},
						Kind:  kind,
						Properties: map[string]any{
							"templateName": t.Name,
							"esc":          f.ESC,
							"severity":     f.Severity,
							"title":        f.Title,
						},
					})
				}
				if len(publishers) == 0 {
					// No resolved CA - still emit a template-anchored edge so the
					// finding is not silently dropped.
					edges = append(edges, bhEdge{
						Start: bhRef{Value: sid},
						End:   bhRef{Value: t.Name, Kind: "CertTemplate"},
						Kind:  kind,
						Properties: map[string]any{
							"templateName": t.Name,
							"esc":          f.ESC,
							"severity":     f.Severity,
							"title":        f.Title,
						},
					})
					addNode(t.Name, "CertTemplate", map[string]any{
						"name": t.Name,
						"type": "CertTemplate",
					})
				}
			}
		}
	}

	// Stable ordering: nodes by id, edges in insertion order.
	nodeIDs := make([]string, 0, len(nodes))
	for id := range nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)

	out := bhDoc{Graph: bhGraph{
		Nodes: make([]bhNode, 0, len(nodeIDs)),
		Edges: edges,
	}}
	for _, id := range nodeIDs {
		out.Graph.Nodes = append(out.Graph.Nodes, nodes[id])
	}
	return out
}

// bloodhoundEdgeKind maps an ESC id ("ESC1".."ESC16") to its BloodHound edge
// kind ("ADCSESC1".."ADCSESC16"). Unknown ids return "".
func bloodhoundEdgeKind(esc string) string {
	esc = strings.TrimSpace(strings.ToUpper(esc))
	if !strings.HasPrefix(esc, "ESC") {
		return ""
	}
	return "ADCS" + esc
}

func resolvePublishers(t *adcs.Template, caByName map[string]*adcs.CertificateAuthority) []*adcs.CertificateAuthority {
	if len(t.PublishedBy) == 0 {
		return nil
	}
	out := make([]*adcs.CertificateAuthority, 0, len(t.PublishedBy))
	for _, name := range t.PublishedBy {
		if ca, ok := caByName[name]; ok && ca != nil {
			out = append(out, ca)
		}
	}
	return out
}

// inferPrincipalKind makes a best-effort guess at the principal node type
// based on the resolved Name (e.g. "CORP\\alice" vs "CORP\\Domain Admins").
// BloodHound's schema wants Kind values like "User", "Group", "Computer".
func inferPrincipalKind(a adcs.Ace) string {
	lower := strings.ToLower(a.Name)
	switch {
	case strings.HasSuffix(lower, "$"):
		return "Computer"
	case strings.Contains(lower, "admins"), strings.Contains(lower, "users"), strings.Contains(lower, "group"):
		return "Group"
	default:
		return "Base"
	}
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if s != "" {
			return s
		}
	}
	return ""
}
