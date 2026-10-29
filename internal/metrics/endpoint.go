// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics provides opt-in, bounded Prometheus endpoints.
package metrics

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"supivpn/internal/vm"
)

type Config struct {
	Enabled              bool   `json:"enabled"`
	Listen               string `json:"listen,omitempty"`
	TLSCertificate       string `json:"tls_certificate,omitempty"`
	TLSChain             string `json:"tls_chain,omitempty"`
	TLSPrivateKey        string `json:"tls_private_key,omitempty"`
	BearerTokenSecretARN string `json:"bearer_token_secret_arn,omitempty"`
}

func (c *Config) IsEnabled() bool { return c != nil && c.Enabled }

// Disabled configuration does not read certificates/secrets or bind a socket.
func (c *Config) Validate(lambda bool) error {
	if !c.IsEnabled() {
		return nil
	}
	if lambda {
		if c.BearerTokenSecretARN == "" || c.Listen != "" || c.TLSCertificate != "" || c.TLSChain != "" || c.TLSPrivateKey != "" {
			return errors.New("Lambda metrics require only a dedicated bearer_token_secret_arn")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(c.Listen)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || n < 1024 || n > 65535 || net.ParseIP(host) == nil ||
		!filepath.IsAbs(c.TLSCertificate) || !filepath.IsAbs(c.TLSPrivateKey) ||
		c.TLSChain != "" && !filepath.IsAbs(c.TLSChain) || c.BearerTokenSecretARN != "" {
		return errors.New("VM metrics require a literal listen IP, port 1024..65535 and absolute TLS certificate/key paths")
	}
	return nil
}

// Handler limits concurrent collection and rejects bodies, query strings and
// cleartext. It never logs requests or returns collector/driver errors.
func Handler(collect func(context.Context) ([]Family, error)) http.Handler {
	busy := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case busy <- struct{}{}:
			defer func() { <-busy }()
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		families, err := collect(ctx)
		if err != nil || ctx.Err() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, err := Encode(families)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write(body)
	})
}

// TokenDigest accepts exactly one canonical base64url-encoded 32-byte token.
// Operators generate it independently of every SAML/profile/database credential.
func TokenDigest(token []byte) ([32]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(string(token))
	if err != nil || len(token) != 43 || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != string(token) {
		return [32]byte{}, errors.New("invalid metrics bearer credential")
	}
	return sha256.Sum256(token), nil
}

// Protect authenticates before entering collection, including the snapshot cache.
func Protect(digest [32]byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		valid := false
		if r.TLS != nil && len(values) == 1 && len(values[0]) == 50 && strings.EqualFold(values[0][:7], "Bearer ") {
			got := sha256.Sum256([]byte(values[0][7:]))
			valid = subtle.ConstantTimeCompare(got[:], digest[:]) == 1
		}
		if !valid {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// PublicRoute preserves the existing SAML handler and exposes exactly one path.
func PublicRoute(base string, next, endpoint http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == base+"/metrics" {
			if endpoint == nil || r.URL.RawPath != "" {
				http.NotFound(w, r)
				return
			}
			endpoint.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Listen starts a separate TLS listener. It never changes the public VPN routes.
func Listen(ctx context.Context, c *Config, endpoint http.Handler) (func(), error) {
	if !c.IsEnabled() {
		return func() {}, nil
	}
	if err := c.Validate(false); err != nil {
		return nil, err
	}
	var tlsConfig *tls.Config
	var err error
	if c.TLSChain == "" {
		var pair tls.Certificate
		pair, err = tls.LoadX509KeyPair(c.TLSCertificate, c.TLSPrivateKey)
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	} else {
		tlsConfig, err = vm.LoadTLS(vm.Config{TLSCertificate: c.TLSCertificate, TLSChain: c.TLSChain, TLSPrivateKey: c.TLSPrivateKey})
	}
	if err != nil {
		return nil, errors.New("metrics TLS unavailable")
	}
	listener, err := tls.Listen("tcp", c.Listen, tlsConfig)
	if err != nil {
		return nil, errors.New("metrics listener unavailable")
	}
	server := &http.Server{
		Handler:           PublicRoute("", http.NotFoundHandler(), endpoint),
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
		MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0),
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	return func() { _ = server.Close(); <-done }, nil
}
