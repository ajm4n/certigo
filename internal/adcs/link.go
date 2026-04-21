package adcs

// LinkPublishedTemplates cross-references the CA.Templates slices against
// the discovered templates, populating Template.PublishedBy and
// Template.Enabled. Call after EnumCAs + EnumTemplates and before running
// the ESC engine so rules that care about publication state (ESC6, ESC7,
// ESC11) see the right linkage.
func LinkPublishedTemplates(cas []*CertificateAuthority, templates []*Template) {
	byName := make(map[string]*Template, len(templates))
	byDisplay := make(map[string]*Template, len(templates))
	for _, t := range templates {
		if t == nil {
			continue
		}
		if t.Name != "" {
			byName[t.Name] = t
		}
		if t.DisplayName != "" && t.DisplayName != t.Name {
			byDisplay[t.DisplayName] = t
		}
	}

	for _, ca := range cas {
		if ca == nil {
			continue
		}
		for _, pub := range ca.Templates {
			t := byName[pub]
			if t == nil {
				t = byDisplay[pub]
			}
			if t == nil {
				continue
			}
			t.PublishedBy = appendUnique(t.PublishedBy, ca.Name)
			t.Enabled = true
		}
	}
}

func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}
