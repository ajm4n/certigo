// Package output rendering is configured via process-global options set by
// the CLI before Format is called. Subcommands read these to decide whether
// to emit optional extras (exploit hints, verbose dumps, etc.).
package output

// ShowHowto controls whether the text formatter prints an exploit
// command block under each ESC finding. Enabled by --howto.
var ShowHowto bool

// HowtoCtx carries the live invocation creds / domain / DC so the
// exploit command printed under each finding is copy-paste-ready
// rather than a placeholder hint. Left nil, the formatter falls back
// to the placeholder esc.ExploitHint.
var HowtoCtx interface{} // *esc.ExploitContext; kept untyped to avoid import cycle
