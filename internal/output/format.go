package output

import (
	"fmt"
	"io"
	"sort"

	"github.com/ajm4n/certigo/internal/adcs"
)

// Formatter renders an enumeration result in one of the supported formats.
// Each call is one-shot: Format builds the whole document in memory and
// writes it to w.
type Formatter interface {
	Name() string // "text", "json", "zip", "bloodhound"
	Format(w io.Writer, cas []*adcs.CertificateAuthority, templates []*adcs.Template) error
}

// registry holds the built-in formatters keyed by Name(). Each formatter
// registers itself via register() in an init() function in its own file so
// that commits can add formatters atomically without requiring a central
// edit point.
var registry = map[string]Formatter{}

// register adds f to the registry. Duplicate names panic at init time.
func register(f Formatter) {
	if _, exists := registry[f.Name()]; exists {
		panic(fmt.Sprintf("output: duplicate formatter registration for %q", f.Name()))
	}
	registry[f.Name()] = f
}

// Get returns the formatter for name, or an error if unknown.
func Get(name string) (Formatter, error) {
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("output: unknown format %q (supported: %v)", name, Names())
	}
	return f, nil
}

// Names returns supported format names in stable order.
func Names() []string {
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
