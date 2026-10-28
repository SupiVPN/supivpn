// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Real-IdP acceptance probe. Credentials and assertions must never be logged.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/controlruntime"
	"supivpn/internal/logging"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
)

var origin = os.Getenv("OKTA_TEST_ORIGIN")
var tenant = os.Getenv("OKTA_TENANT_ORIGIN")
var testUser = os.Getenv("OKTA_TEST_USERNAME")
var userGroup = os.Getenv("OKTA_TEST_ALLOWED_GROUP")

type observedBackend struct {
	*postgres.ProfileBackend
	expectedSubject           [32]byte
	mu                        sync.Mutex
	allowed, denied, verified int
}

func (b *observedBackend) Complete(ctx context.Context, p controller.Pending, d controller.Authorization) error {
	err := b.ProfileBackend.Complete(ctx, p, d)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.allowed++
		if d.Username == testUser && d.SubjectHash == b.expectedSubject && d.GroupName == userGroup &&
			d.DenialReason == "" && d.ValidAt(time.Now()) {
			b.verified++
		}
	} else if errors.Is(err, controller.ErrGroupDenied) && d.DenialReason == "no_vpn_group" {
		b.denied++
	}
	return err
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Profile acceptance server failed; raw diagnostics withheld")
		os.Exit(1)
	}
}

func run() error {
	port := flag.Int("db-port", 0, "port of this run's disposable loopback PostgreSQL")
	runID := flag.String("run-id", "", "nonsecret probe instance identifier")
	deny := flag.Bool("deny-group", false, "allow only the configured empty group locally")
	rootPath := flag.String("root", "", "private per-run fixture directory")
	encryptionMode := flag.String("encryption-mode", "optional", "assertion encryption policy under test")
	encryptedApp := flag.Bool("encrypted-app", false, "use the dedicated encrypted test app")
	wrongKey := flag.Bool("wrong-encryption-key", false, "negative test with an unrelated recipient key")
	flag.Parse()
	if *port < 1024 || *port > 65535 || !regexp.MustCompile("^[a-f0-9]{24}$").MatchString(*runID) {
		return errors.New("invalid local test arguments")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 5*time.Minute)
	defer timeout()
	root := *rootPath
	if !filepath.IsAbs(root) || origin != "https://test.supivpn.com:18443" || tenant == "" || testUser == "" || userGroup == "" || os.Getenv("OKTA_TEST_DENIED_GROUP") == "" {
		return errors.New("missing isolated test settings")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("unsafe test directory")
	}
	// Never consult unrelated machine database credentials or service files.
	for _, name := range []string{"PGSERVICE", "PGSERVICEFILE", "PGPASSWORD", "PGHOST", "PGPORT", "PGDATABASE", "PGUSER"} {
		os.Unsetenv(name)
	}
	os.Setenv("PGPASSFILE", filepath.Join(root, "absent-pgpass"))
	pool, err := postgres.Open(ctx, fmt.Sprintf("host=127.0.0.1 port=%d user=postgres dbname=supivpn_test sslmode=disable", *port))
	if err != nil {
		return err
	}
	defer pool.Close()
	var database string
	if err = pool.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil || database != "supivpn_test" {
		return errors.New("wrong disposable database")
	}
	if err = postgres.Migrate(ctx, pool); err != nil {
		return err
	}
	store := postgres.New(pool)
	if !store.Ready(ctx) {
		return errors.New("database not ready")
	}
	metadataName, recipientName := "idp-metadata.xml", "saml"
	if *encryptedApp {
		metadataName, recipientName = "encrypted-idp-metadata.xml", "encrypted-saml"
	}
	if *wrongKey {
		if !*encryptedApp || *encryptionMode == "disabled" {
			return errors.New("wrong-key test requires encrypted assertions")
		}
		recipientName = "saml"
	}
	data, err := os.ReadFile(filepath.Join(root, metadataName))
	if err != nil {
		return err
	}
	md, err := saml.ParseMetadata(data)
	if err != nil {
		return err
	}
	base, _ := url.Parse(origin)
	sp := &saml.ServiceProvider{EntityID: origin + "/saml/metadata",
		MetadataURL: *base.JoinPath("saml/metadata"), AcsURL: *base.JoinPath("saml/acs"),
		IDPMetadata: md, AuthnNameIDFormat: saml.UnspecifiedNameIDFormat}
	encryptionConfig := &saml.EncryptionConfig{Mode: *encryptionMode}
	if *encryptionMode != "disabled" {
		encryptionConfig.CertificateFile = filepath.Join(root, recipientName+".crt")
		encryptionConfig.PrivateKeyFile = filepath.Join(root, recipientName+".key")
	}
	sp.AssertionEncryption, err = encryptionConfig.Load()
	if err != nil {
		return err
	}
	idp, err := url.Parse(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding))
	if err != nil || idp.Scheme+"://"+idp.Host != tenant {
		return errors.New("unexpected IdP")
	}
	template, err := os.ReadFile("internal/agent/testdata/client.ovpn.example")
	if err != nil {
		return err
	}
	// Ephemeral synthetic wrapping material is never persisted or reused by a VPN.
	key := make([]byte, 128)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	wrapping := pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: key})
	clear(key)
	defer clear(wrapping)
	var keyLoads atomic.Int32
	issue, err := profile.BoundDownloadIssuer(template, "test.supivpn.com", 1194, func(context.Context) ([]byte, error) {
		keyLoads.Add(1)
		return bytes.Clone(wrapping), nil
	}, store.CreateProfile)
	if err != nil {
		return err
	}
	backend := &observedBackend{ProfileBackend: postgres.NewProfileBackend(store, 180*time.Second),
		expectedSubject: sha256.Sum256([]byte(md.EntityID + "\x00" + testUser))}
	groups := []controller.Group{{GroupName: os.Getenv("OKTA_TEST_DENIED_GROUP"), Priority: 10}, {GroupName: userGroup, Priority: 20}}
	if *deny {
		groups = groups[:1]
	}
	c, err := controller.New(controller.Config{Policy: controller.Policy{SAMLGroupsAttribute: "groups", Groups: groups},
		PendingSeconds: 180, SessionSeconds: 900}, base, sp, store, time.Now,
		controller.ProfileDownloads{Backend: backend, IssueForSubject: issue})
	if err != nil {
		return err
	}
	product := controlruntime.Bounded(c.Handler())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Host != "test.supivpn.com:18443" || r.TLS == nil {
			http.Error(w, "invalid origin", 400)
			return
		}
		if r.URL.Path == "/lab/status" {
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			var total, consumed, assertions, vpnLogins, nodes, issued, owned int
			e := pool.QueryRow(r.Context(), `
    SELECT (SELECT count(*) FROM supivpn.profile_logins),
     (SELECT count(*) FROM supivpn.profile_logins WHERE consumed),
     (SELECT count(*) FROM supivpn.assertions),
     (SELECT count(*) FROM supivpn.logins),
     (SELECT count(*) FROM supivpn.nodes),
     (SELECT count(*) FROM supivpn.issued_profiles),
     (SELECT count(*) FROM supivpn.issued_profiles WHERE subject_hash=$1 AND owner_username=$2 AND state='active')`,
				backend.expectedSubject[:], testUser).Scan(&total, &consumed, &assertions, &vpnLogins, &nodes, &issued, &owned)
			if e != nil {
				http.Error(w, "probe unavailable", 503)
				return
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"run_id": *runID, "ready": true, "allowed": backend.allowed, "denied": backend.denied,
				"verified_identity_and_group": backend.verified, "key_loads": keyLoads.Load(),
				"profile_logins": total, "consumed_logins": consumed, "assertions": assertions,
				"vpn_logins": vpnLogins, "nodes": nodes,
				"issued_profiles": issued, "verified_profile_owners": owned,
			})
			return
		}
		product.ServeHTTP(w, r.WithContext(logging.WithLogger(r.Context(), logging.New(io.Discard, "public"))))
	})
	cert, err := tls.LoadX509KeyPair(filepath.Join(root, "server.crt"),
		filepath.Join(root, "server.key"))
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:18443")
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { <-ctx.Done(); server.Close() }()
	err = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
