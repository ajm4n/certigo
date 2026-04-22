package adcs

import "strings"

// MarkEnrollableTemplates sets Template.EnrollableByCurrentUser only when
// every check below passes for the supplied principal (identitySet):
//
//  1. No DENY ACE on the template denies Enroll to a SID in the set.
//  2. At least one ALLOW ACE on the template grants Enroll (ControlAccess).
//  3. No DENY ACE on a publishing CA denies Enroll to the principal, and
//     at least one publishing CA ALLOW-grants Enroll.
//
// DENY ACEs win over ALLOW (AD evaluates them first). Without this
// ordering a template like "Cert-Machine-Block-GS (DENY|ControlAccess) +
// Authenticated Users (ControlAccess)" was reported as enrollable for
// every authenticated principal - even the ones explicitly blocked.
//
// Safe to call with a nil / empty identitySet; every template keeps
// EnrollableByCurrentUser false.
func MarkEnrollableTemplates(templates []*Template, cas []*CertificateAuthority, identitySet map[string]bool) {
	if len(identitySet) == 0 {
		return
	}
	caByName := make(map[string]*CertificateAuthority, len(cas))
	for _, c := range cas {
		if c != nil && c.Name != "" {
			caByName[c.Name] = c
		}
	}
	for _, t := range templates {
		if t == nil {
			continue
		}
		// Template-level gate.
		if denyEnrollMatches(t.EnrollmentRights, identitySet) ||
			denyEnrollMatches(t.AutoEnrollRights, identitySet) {
			continue
		}
		if !allowEnrollMatches(t.EnrollmentRights, identitySet) &&
			!allowEnrollMatches(t.AutoEnrollRights, identitySet) {
			continue
		}
		// CA-level gate: at least one publishing CA must ALLOW and not
		// DENY. Templates with no PublishedBy are unreachable.
		for _, caName := range t.PublishedBy {
			ca, ok := caByName[caName]
			if !ok || ca == nil {
				continue
			}
			if denyEnrollMatches(ca.EnrollmentRights, identitySet) {
				continue
			}
			if allowEnrollMatches(ca.EnrollmentRights, identitySet) {
				t.EnrollableByCurrentUser = true
				break
			}
		}
	}
}

// allowEnrollMatches reports whether any ALLOW ACE in aces grants
// ControlAccess to a SID in set.
func allowEnrollMatches(aces []Ace, set map[string]bool) bool {
	for _, a := range aces {
		if !set[a.SID] {
			continue
		}
		if strings.Contains(a.Rights, "DENY") {
			continue
		}
		if strings.Contains(a.Rights, "ControlAccess") {
			return true
		}
	}
	return false
}

// denyEnrollMatches reports whether any DENY ACE in aces denies
// ControlAccess to a SID in set.
func denyEnrollMatches(aces []Ace, set map[string]bool) bool {
	for _, a := range aces {
		if !set[a.SID] {
			continue
		}
		if strings.Contains(a.Rights, "DENY") && strings.Contains(a.Rights, "ControlAccess") {
			return true
		}
	}
	return false
}
