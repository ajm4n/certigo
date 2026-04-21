package adcs

import "strings"

// MarkEnrollableTemplates walks each template's Enrollment + AutoEnroll
// ACEs and sets Template.EnrollableByCurrentUser whenever at least one
// ACE's SID is in identitySet AND that ACE actually grants the Enroll
// (ControlAccess) right. A read-only ACE like "Authenticated Users
// (ReadControl|ReadProperty)" does NOT make a template enrollable even
// though the principal is in the set, and previously this function
// over-reported enrollability. identitySet is the value returned by
// IdentitySet() for the currently-bound principal. Safe to call with a
// nil / empty set - all templates simply retain EnrollableByCurrentUser
// false.
func MarkEnrollableTemplates(templates []*Template, identitySet map[string]bool) {
	if len(identitySet) == 0 {
		return
	}
	for _, t := range templates {
		if t == nil {
			continue
		}
		if enrollAceMatches(t.EnrollmentRights, identitySet) ||
			enrollAceMatches(t.AutoEnrollRights, identitySet) {
			t.EnrollableByCurrentUser = true
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
