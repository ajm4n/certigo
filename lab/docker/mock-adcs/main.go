// Package main implements mock-adcs, a minimal HTTP/HTTPS stub that imitates
// a handful of AD CS enrolment endpoints so Certigo integration tests can
// exercise request plumbing without requiring a real Windows AD CS server.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

func logMW(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		h.ServeHTTP(w, r)
	})
}

func notImplemented(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte("mock-adcs: enrollment not implemented (real AD CS required)"))
}

func newMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/certsrv/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", "Negotiate,NTLM")
		w.WriteHeader(http.StatusUnauthorized)
	})

	mux.HandleFunc("/certsrv/certrqma.asp", notImplemented)
	mux.HandleFunc("/certsrv/mscep/mscep.dll", notImplemented)
	mux.HandleFunc("/certsrv/certfnsh.asp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		notImplemented(w, r)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	return logMW(mux)
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mock-adcs"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"mock-adcs", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	handler := newMux()

	cert, err := selfSignedCert()
	if err != nil {
		log.Fatalf("mock-adcs: failed to generate self-signed cert: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		log.Printf("mock-adcs: HTTP listening on :8080")
		if err := http.ListenAndServe(":8080", handler); err != nil {
			log.Fatalf("mock-adcs: HTTP server error: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		srv := &http.Server{
			Addr:              ":8443",
			Handler:           handler,
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 10 * time.Second,
		}
		log.Printf("mock-adcs: HTTPS listening on :8443")
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("mock-adcs: HTTPS server error: %v", err)
		}
	}()

	wg.Wait()
}
