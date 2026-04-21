// Package output rendering is configured via process-global options set by
// the CLI before Format is called. Subcommands read these to decide whether
// to emit optional extras (exploit hints, verbose dumps, etc.).
package output

// ShowHowto controls whether the text / short formatters print the
// esc.ExploitHint block under each ESC finding. The CLI sets this to
// true when --howto AND --vulnerable are both passed.
var ShowHowto bool
