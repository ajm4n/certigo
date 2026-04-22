package esc

import (
	"strings"

	"github.com/ajm4n/certigo/internal/adcs"
)

// Rule is a single ESC detection check. Input: one template + its
// publishing CA (may be nil if the template is unpublished, or if the CA
// context is unavailable). Output: zero or more findings.
//
// Rules must be side-effect-free on their inputs - Scan is the only
// caller that mutates Template.Findings.
type Rule interface {
	// Name returns the stable identifier, e.g. "ESC1".
	Name() string
	// Check evaluates the rule and returns any findings.
	Check(tpl *adcs.Template, ca *adcs.CertificateAuthority) []adcs.Finding
}

// AllRules returns every registered rule in display order
// (ESC1, ESC2, ...). ESC12 is intentionally absent - no public ESC12
// definition exists at time of writing. Additional rules are registered
// here as they land.
func AllRules() []Rule {
	return []Rule{
		ESC1{},
		ESC2{},
		ESC3{},
		ESC4{},
		ESC5{},
		ESC6{},
		ESC7{},
		ESC8{},
		ESC9{},
		ESC10{},
		ESC11{},
		ESC13{},
		ESC14{},
		ESC15{},
		ESC16{},
	}
}

// Scan runs every rule against every template. Each template's
// publishing CA (if any) is resolved by name from cas. Findings are
// appended onto each Template's Findings slice. Returns the total
// number of findings produced.
func Scan(templates []*adcs.Template, cas []*adcs.CertificateAuthority) int {
	caByName := make(map[string]*adcs.CertificateAuthority, len(cas))
	for _, c := range cas {
		if c == nil {
			continue
		}
		caByName[c.Name] = c
	}

	rules := AllRules()
	total := 0
	for _, tpl := range templates {
		if tpl == nil {
			continue
		}
		ca := firstPublishingCA(tpl, caByName)
		for _, r := range rules {
			findings := r.Check(tpl, ca)
			if len(findings) > 0 {
				tpl.Findings = append(tpl.Findings, findings...)
				total += len(findings)
			}
		}
	}
	return total
}

// firstPublishingCA returns the first CA that lists the template as
// published, or nil if none is found. For templates published on
// multiple CAs, callers that need per-CA scanning should call the
// individual Rule.Check directly.
func firstPublishingCA(tpl *adcs.Template, byName map[string]*adcs.CertificateAuthority) *adcs.CertificateAuthority {
	for _, n := range tpl.PublishedBy {
		if ca, ok := byName[n]; ok {
			return ca
		}
	}
	return nil
}

// containsAny reports whether haystack contains any string in needles.
func containsAny(haystack, needles []string) bool {
	if len(haystack) == 0 || len(needles) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(needles))
	for _, n := range needles {
		set[n] = struct{}{}
	}
	for _, h := range haystack {
		if _, ok := set[h]; ok {
			return true
		}
	}
	return false
}

// contains reports whether haystack contains needle.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// templateEnrollableByLowPriv returns the low-priv ACEs that actually hold
// Enroll (or AutoEnroll) rights on the template. Empty slice means only
// privileged principals can enrol. Read-only ACEs (ReadControl /
// ReadProperty) are ignored - they do not grant enrollment.
func templateEnrollableByLowPriv(tpl *adcs.Template) []adcs.Ace {
	if tpl == nil {
		return nil
	}
	combined := make([]adcs.Ace, 0, len(tpl.EnrollmentRights)+len(tpl.AutoEnrollRights))
	combined = append(combined, enrollAces(tpl.EnrollmentRights)...)
	combined = append(combined, enrollAces(tpl.AutoEnrollRights)...)
	return lowPrivAces(combined)
}

// enrollAces filters an ACE list to ALLOW aces that grant enrollment
// (ControlAccess). DENY aces are excluded - they don't make a template
// enrollable, they make it un-enrollable for the denied principal.
// A template protected by "Cert-Machine-Block-GS (DENY|ControlAccess)"
// was previously mis-reported as low-priv-enrollable.
func enrollAces(aces []adcs.Ace) []adcs.Ace {
	out := make([]adcs.Ace, 0, len(aces))
	for _, a := range aces {
		if strings.Contains(a.Rights, "DENY") {
			continue
		}
		if strings.Contains(a.Rights, "ControlAccess") {
			out = append(out, a)
		}
	}
	return out
}
