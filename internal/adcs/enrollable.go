package adcs

// MarkEnrollableTemplates walks each template's Enrollment + AutoEnroll
// ACEs and sets Template.EnrollableByCurrentUser whenever at least one
// ACE's SID is in identitySet. identitySet is the value returned by
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
		if aceMatchesSet(t.EnrollmentRights, identitySet) ||
			aceMatchesSet(t.AutoEnrollRights, identitySet) {
			t.EnrollableByCurrentUser = true
		}
	}
}

func aceMatchesSet(aces []Ace, set map[string]bool) bool {
	for _, a := range aces {
		if set[a.SID] {
			return true
		}
	}
	return false
}
