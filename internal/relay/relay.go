// Package relay implements certigo's NTLM-to-AD-CS relay. The current
// implementation ships as a skeleton: HTTP listener + 501 for relay
// endpoints. Full MITM NTLM forwarding to /certsrv/ requires careful
// sequencing of challenge/response between the client side (our listener)
// and the outbound side (the AD CS web enrollment endpoint) and is planned
// for a follow-up milestone.
package relay

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

// Options configures the relay server.
type Options struct {
	Listen    string // e.g. ":80"
	TargetURL string // e.g. "https://ca.ctg.local/certsrv/"
	Template  string
	TLSCert   string
	TLSKey    string
	OutDir    string
}

// Run starts the HTTP listener. It returns when the server exits or an
// error occurs binding. Every request is logged; unhandled paths return
// 501 with a short explanatory body.
func Run(opts Options) error {
	mux := http.NewServeMux()
	var hitCount atomic.Int64

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := hitCount.Add(1)
		log.Printf("relay[%d]: %s %s from %s — stub response (NTLM relay pipeline pending)", n, r.Method, r.URL.Path, r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", "Negotiate,NTLM")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = fmt.Fprintln(w, "certigo relay: NTLM-to-AD-CS forwarding is a work-in-progress (M7).")
	})

	srv := &http.Server{
		Addr:    opts.Listen,
		Handler: mux,
	}
	log.Printf("relay: listening on %s (target=%s template=%s)", opts.Listen, opts.TargetURL, opts.Template)

	if opts.TLSCert != "" && opts.TLSKey != "" {
		return srv.ListenAndServeTLS(opts.TLSCert, opts.TLSKey)
	}
	return srv.ListenAndServe()
}
