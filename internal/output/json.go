package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ajm4n/certigo/internal/adcs"
)

// JSONFormatter renders the enumeration result as a pretty-printed JSON
// document. Field names follow Certipy's `find -json` convention
// (snake_case keys, 1-indexed "CAs"/"Certificate Templates" maps in the
// original; we use arrays here for stability but keep the snake_case
// leaf keys for downstream tooling compatibility).
type JSONFormatter struct{}

// Name returns the format identifier.
func (JSONFormatter) Name() string { return "json" }

func init() { register(JSONFormatter{}) }

type jsonDoc struct {
	CAs       []jsonCA       `json:"certificate_authorities"`
	Templates []jsonTemplate `json:"certificate_templates"`
	Findings  []jsonFinding  `json:"findings"`
	Stats     jsonStats      `json:"stats"`
}

type jsonCA struct {
	Name                     string    `json:"ca_name"`
	DNSName                  string    `json:"dns_name,omitempty"`
	CertificateSubject       string    `json:"certificate_subject,omitempty"`
	CertificateSerialNumber  string    `json:"certificate_serial_number,omitempty"`
	CertificateValidityStart string    `json:"certificate_validity_start,omitempty"`
	CertificateValidityEnd   string    `json:"certificate_validity_end,omitempty"`
	WebEnrollment            bool      `json:"web_enrollment"`
	WebEnrollmentHTTPS       bool      `json:"web_enrollment_https"`
	Flags                    uint32    `json:"flags"`
	EditFlags                uint32    `json:"edit_flags"`
	RequestDisposition       uint32    `json:"request_disposition"`
	EnrollmentRights         []jsonAce `json:"enrollment_rights,omitempty"`
	ManageCARights           []jsonAce `json:"manage_ca_rights,omitempty"`
	ManageCertificatesRights []jsonAce `json:"manage_certificates_rights,omitempty"`
	EnrollmentAgents         []string  `json:"enrollment_agents,omitempty"`
	PublishedTemplates       []string  `json:"published_templates,omitempty"`
}

type jsonTemplate struct {
	Name                    string        `json:"template_name"`
	DisplayName             string        `json:"display_name,omitempty"`
	SchemaVersion           int           `json:"schema_version"`
	ValidityPeriod          string        `json:"validity_period,omitempty"`
	RenewalPeriod           string        `json:"renewal_period,omitempty"`
	MinRSAKeyLength         int           `json:"min_rsa_key_length,omitempty"`
	EnrolleeSuppliesSubject bool          `json:"enrollee_supplies_subject"`
	RequiresManagerApproval bool          `json:"requires_manager_approval"`
	AuthorizedSignatures    int           `json:"authorized_signatures,omitempty"`
	CertificateNameFlag     uint32        `json:"certificate_name_flag"`
	EnrollmentFlag          uint32        `json:"enrollment_flag"`
	PrivateKeyFlag          uint32        `json:"private_key_flag"`
	EKUs                    []string      `json:"extended_key_usage,omitempty"`
	ApplicationPolicies     []string      `json:"application_policies,omitempty"`
	CertificatePolicies     []string      `json:"certificate_policies,omitempty"`
	PublishedBy             []string      `json:"published_by,omitempty"`
	EnrollmentRights        []jsonAce     `json:"enrollment_rights,omitempty"`
	AutoEnrollRights        []jsonAce     `json:"auto_enroll_rights,omitempty"`
	WriteOwner              []jsonAce     `json:"write_owner,omitempty"`
	WriteDacl               []jsonAce     `json:"write_dacl,omitempty"`
	WriteProperty           []jsonAce     `json:"write_property,omitempty"`
	FullControl             []jsonAce     `json:"full_control,omitempty"`
	Vulnerabilities         []jsonFinding `json:"vulnerabilities,omitempty"`
}

type jsonAce struct {
	SID    string `json:"sid"`
	Name   string `json:"name,omitempty"`
	Rights string `json:"rights,omitempty"`
}

type jsonFinding struct {
	Template    string         `json:"template,omitempty"`
	ESC         string         `json:"esc"`
	Severity    string         `json:"severity,omitempty"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

type jsonStats struct {
	CACount         int `json:"ca_count"`
	TemplateCount   int `json:"template_count"`
	VulnerableCount int `json:"vulnerable_template_count"`
	FindingCount    int `json:"finding_count"`
}

// Format writes the JSON document to w.
func (JSONFormatter) Format(w io.Writer, cas []*adcs.CertificateAuthority, templates []*adcs.Template) error {
	doc := buildJSONDoc(cas, templates)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("output/json: encode: %w", err)
	}
	return nil
}

func buildJSONDoc(cas []*adcs.CertificateAuthority, templates []*adcs.Template) jsonDoc {
	doc := jsonDoc{
		CAs:       make([]jsonCA, 0, len(cas)),
		Templates: make([]jsonTemplate, 0, len(templates)),
		Findings:  []jsonFinding{},
	}
	for _, ca := range cas {
		if ca == nil {
			continue
		}
		doc.CAs = append(doc.CAs, caToJSON(ca))
	}
	vulnCount := 0
	for _, t := range templates {
		if t == nil {
			continue
		}
		jt := templateToJSON(t)
		doc.Templates = append(doc.Templates, jt)
		if len(t.Findings) > 0 {
			vulnCount++
		}
		for _, f := range t.Findings {
			fj := findingToJSON(f)
			fj.Template = t.Name
			doc.Findings = append(doc.Findings, fj)
		}
	}
	doc.Stats = jsonStats{
		CACount:         len(doc.CAs),
		TemplateCount:   len(doc.Templates),
		VulnerableCount: vulnCount,
		FindingCount:    len(doc.Findings),
	}
	return doc
}

func caToJSON(ca *adcs.CertificateAuthority) jsonCA {
	out := jsonCA{
		Name:                     ca.Name,
		DNSName:                  ca.DNSName,
		WebEnrollment:            ca.WebEnrollment,
		WebEnrollmentHTTPS:       ca.HTTPS,
		Flags:                    ca.Flags,
		EditFlags:                ca.EditFlags,
		RequestDisposition:       ca.RequestDisposition,
		EnrollmentRights:         acesToJSON(ca.EnrollmentRights),
		ManageCARights:           acesToJSON(ca.ManageCARights),
		ManageCertificatesRights: acesToJSON(ca.ManageCertRights),
		EnrollmentAgents:         ca.EnrollmentAgents,
		PublishedTemplates:       ca.Templates,
	}
	if ca.Certificate != nil {
		out.CertificateSubject = ca.Certificate.Subject.String()
		out.CertificateSerialNumber = fmt.Sprintf("%X", ca.Certificate.SerialNumber)
		out.CertificateValidityStart = ca.Certificate.NotBefore.UTC().Format("2006-01-02 15:04:05Z")
		out.CertificateValidityEnd = ca.Certificate.NotAfter.UTC().Format("2006-01-02 15:04:05Z")
	}
	return out
}

func templateToJSON(t *adcs.Template) jsonTemplate {
	out := jsonTemplate{
		Name:                    t.Name,
		DisplayName:             t.DisplayName,
		SchemaVersion:           t.SchemaVersion,
		MinRSAKeyLength:         t.MinRSAKeyLength,
		EnrolleeSuppliesSubject: t.EnrolleeSuppliesSubject,
		RequiresManagerApproval: t.RequiresManagerApproval,
		AuthorizedSignatures:    t.AuthorizedSignatures,
		CertificateNameFlag:     t.MsPKICertificateNameFlag,
		EnrollmentFlag:          t.MsPKIEnrollmentFlag,
		PrivateKeyFlag:          t.MsPKIPrivateKeyFlag,
		EKUs:                    t.EKUs,
		ApplicationPolicies:     t.ApplicationPolicies,
		CertificatePolicies:     t.MsPKICertificatePolicies,
		PublishedBy:             t.PublishedBy,
		EnrollmentRights:        acesToJSON(t.EnrollmentRights),
		AutoEnrollRights:        acesToJSON(t.AutoEnrollRights),
		WriteOwner:              acesToJSON(t.WriteOwner),
		WriteDacl:               acesToJSON(t.WriteDacl),
		WriteProperty:           acesToJSON(t.WriteProperty),
		FullControl:             acesToJSON(t.FullControl),
	}
	if t.ValidityPeriod > 0 {
		out.ValidityPeriod = t.ValidityPeriod.String()
	}
	if t.RenewalPeriod > 0 {
		out.RenewalPeriod = t.RenewalPeriod.String()
	}
	for _, f := range t.Findings {
		out.Vulnerabilities = append(out.Vulnerabilities, findingToJSON(f))
	}
	return out
}

func acesToJSON(aces []adcs.Ace) []jsonAce {
	if len(aces) == 0 {
		return nil
	}
	out := make([]jsonAce, 0, len(aces))
	for _, a := range aces {
		out = append(out, jsonAce{SID: a.SID, Name: a.Name, Rights: a.Rights})
	}
	return out
}

func findingToJSON(f adcs.Finding) jsonFinding {
	return jsonFinding{
		ESC:         f.ESC,
		Severity:    f.Severity,
		Title:       f.Title,
		Description: f.Description,
		Evidence:    f.Evidence,
	}
}
