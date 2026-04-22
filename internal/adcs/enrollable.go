package adcs

import "strings"

// MarkEnrollableTemplates sets Template.EnrollableByCurrentUser only when
// BOTH of these hold for the supplied principal (identitySet):
//
//  1. At least one ACE on the template grants Enroll (ControlAccess).
//  2. At least one of the CAs that publishes the template grants
//     Enroll to the same principal.
//
// Without the second check we over-reported templates as enrollable
// whenever their DACL had "Authenticated Users (ControlAccess)" - the
// CA object itself frequently restricts who can actually request a
// cert, and DCOM activation fails with ACCESS_DENIED even though the
// template would permit the request.
//
// Safe to call with a nil / empty identitySet; every template simply
// keeps EnrollableByCurrentUser false.
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
		// Template-level enrollment permission.
		if !enrollAceMatches(t.EnrollmentRights, identitySet) &&
			!enrollAceMatches(t.AutoEnrollRights, identitySet) {
			continue
		}
		// CA-level enrollment permission: at least one publishing CA must
		// also grant Enroll (ControlAccess) to the principal. A template
		// with no PublishedBy list is effectively unreachable, so it
		// stays false.
		for _, caName := range t.PublishedBy {
			ca, ok := caByName[caName]
			if !ok || ca == nil {
				continue
			}
			if enrollAceMatches(ca.EnrollmentRights, identitySet) {
				t.EnrollableByCurrentUser = true
				break
			}
		}
	}
}

// enrollAceMatches reports whether any ACE in aces grants enrollment
// (ControlAccess mask) to a principal whose SID is in set.
func enrollAceMatches(aces []Ace, set map[string]bool) bool {
	for _, a := range aces {
		if !set[a.SID] {
			continue
		}
		if strings.Contains(a.Rights, "ControlAccess") {
			return true
		}
	}
	return false
}
