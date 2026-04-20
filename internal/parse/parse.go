// Package parse provides offline readers for AD CS artifacts: Windows
// registry text dumps (.reg) and Event Tracing logs (.evtx). The .reg path
// is fully implemented; the .evtx path is a stub pending a pure-Go
// EVTX library (the binary format is complex and there is no widely-used
// pure-Go reader today).
package parse

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Event is a generic typed record emitted by any parser in this package.
// Fields holds key/value pairs pulled from the artifact (registry values,
// event XML data items, etc.). Source identifies the file the record came
// from; Time is a best-effort timestamp (zero value if unavailable).
type Event struct {
	Source   string
	Time     time.Time
	EventID  int
	Severity string
	Fields   map[string]string
}

// ParseFile dispatches on file extension.
//
//	.reg  → registry text dump (Unicode or ASCII)
//	.evtx → Windows event log  (returns ErrEVTXUnimplemented)
func ParseFile(path string) ([]Event, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".reg":
		return parseReg(path)
	case ".evtx":
		return nil, ErrEVTXUnimplemented
	default:
		return nil, fmt.Errorf("parse: unsupported extension %q (want .reg or .evtx)", ext)
	}
}

// ErrEVTXUnimplemented is returned until a pure-Go EVTX library is adopted.
var ErrEVTXUnimplemented = fmt.Errorf("parse: EVTX parsing not yet implemented (no pure-Go library adopted yet)")

// parseReg reads a Windows 5.00 / 4.00 / 3.00 text registry dump and emits
// one Event per section (registry key), with each key's values folded into
// the Event.Fields map. Binary ("hex:xx,xx"), DWORD ("dword:"), and
// ExpandString ("hex(2):") values are stringified verbatim; multi-string
// (REG_MULTI_SZ) values are preserved as a single string with embedded
// nulls replaced by "; " separators.
func parseReg(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	// Registry dumps can have long binary lines; raise the buffer.
	scanner.Buffer(make([]byte, 1<<20), 1<<24)

	var events []Event
	var current *Event
	var pendingKey, pendingVal string
	continuation := false

	flushPending := func() {
		if current != nil && pendingKey != "" {
			current.Fields[pendingKey] = strings.TrimSpace(strings.TrimSuffix(pendingVal, "\\"))
			pendingKey, pendingVal = "", ""
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip the header line and blank lines.
		if trimmed == "" || strings.HasPrefix(trimmed, "Windows Registry Editor Version") ||
			strings.HasPrefix(trimmed, "REGEDIT4") {
			continuation = false
			continue
		}

		// Continuation of a multi-line hex value.
		if continuation {
			pendingVal += trimmed
			if !strings.HasSuffix(trimmed, "\\") {
				continuation = false
				flushPending()
			} else {
				// keep accumulating
				pendingVal = strings.TrimSuffix(pendingVal, "\\")
			}
			continue
		}

		// New section header: [KEY_PATH]
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			flushPending()
			if current != nil {
				events = append(events, *current)
			}
			current = &Event{
				Source:   path,
				Severity: "info",
				Fields:   map[string]string{"_path": trimmed[1 : len(trimmed)-1]},
			}
			continue
		}

		if current == nil {
			continue
		}

		// Value line: "name"=value  OR  @=value (default)
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		name := trimmed[:eq]
		val := trimmed[eq+1:]

		if name == "@" {
			name = "(default)"
		} else if strings.HasPrefix(name, `"`) && strings.HasSuffix(name, `"`) {
			name = strings.TrimSuffix(strings.TrimPrefix(name, `"`), `"`)
		}

		// Multi-line (hex) value: ends with a backslash.
		if strings.HasSuffix(val, "\\") {
			pendingKey = name
			pendingVal = val
			continuation = true
			continue
		}

		current.Fields[name] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flushPending()
	if current != nil {
		events = append(events, *current)
	}
	return events, nil
}
