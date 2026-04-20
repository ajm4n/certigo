package esc

import (
	"strings"

	"github.com/ajm4n/certigo/internal/adcs"
)

// privilegedLiteralSIDs is the set of well-known absolute SIDs that are
// unconditionally considered privileged regardless of domain.
var privilegedLiteralSIDs = map[string]struct{}{
	"S-1-5-18":     {}, // LOCAL SYSTEM
	"S-1-5-32-544": {}, // BUILTIN\Administrators
	"S-1-5-32-548": {}, // BUILTIN\Account Operators
	"S-1-5-32-549": {}, // BUILTIN\Server Operators
	"S-1-5-32-550": {}, // BUILTIN\Print Operators
	"S-1-5-32-551": {}, // BUILTIN\Backup Operators
	"S-1-5-9":      {}, // Enterprise Domain Controllers
}

// privilegedRIDs are the trailing RIDs (on a domain SID
// S-1-5-21-a-b-c-RID) that denote privileged domain groups. The domain
// SID prefix varies per environment, so we match by trailing RID only.
var privilegedRIDs = []string{
	"-512", // Domain Admins
	"-516", // Domain Controllers
	"-518", // Schema Admins
	"-519", // Enterprise Admins
	"-521", // Read-only Domain Controllers
	"-498", // Enterprise Read-only Domain Controllers
}

// IsPrivileged reports whether sid represents a built-in or
// high-privilege AD principal. A SID NOT in this set is treated as
// "low-privilege" for the purposes of ESC rule evaluation.
//
// Matching strategy:
//  1. Exact match against a short fixed set of BUILTIN / well-known SIDs.
//  2. RID-suffix match against known privileged domain group RIDs. The
//     domain SID prefix varies per environment, so literal-match on the
//     full SID is not workable.
//
// SIDs that fail both checks are considered low-privilege.
func IsPrivileged(sid string) bool {
	if sid == "" {
		return false
	}
	if _, ok := privilegedLiteralSIDs[sid]; ok {
		return true
	}
	if strings.HasPrefix(sid, "S-1-5-21-") {
		for _, rid := range privilegedRIDs {
			if strings.HasSuffix(sid, rid) {
				return true
			}
		}
	}
	return false
}

// lowPrivAces returns the subset of aces whose principals are
// low-privilege.
func lowPrivAces(aces []adcs.Ace) []adcs.Ace {
	if len(aces) == 0 {
		return nil
	}
	out := make([]adcs.Ace, 0, len(aces))
	for _, a := range aces {
		if !IsPrivileged(a.SID) {
			out = append(out, a)
		}
	}
	return out
}

// aceSIDs extracts the SID strings from an ACE slice for evidence output.
func aceSIDs(aces []adcs.Ace) []string {
	out := make([]string, 0, len(aces))
	for _, a := range aces {
		out = append(out, a.SID)
	}
	return out
}
