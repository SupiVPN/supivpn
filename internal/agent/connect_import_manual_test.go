// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/controlruntime"
	"supivpn/internal/logging"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
)

// Opt-in desktop acceptance: the human/desktop automation must use Connect's
// Server URL screen. Counters prove server processing, not native UI success.
func TestConnectServerURLManual(t *testing.T) {
	if os.Getenv("SUPIVPN_TEST_CONNECT_IMPORT") != "1" {
		t.Skip("requires explicit interactive Connect import acceptance")
	}
	origin := os.Getenv("SUPIVPN_TEST_CONNECT_ORIGIN")
	base, err := url.Parse(origin)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.Port() != "18443" || base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("explicit HTTPS test origin on port 18443 required")
	}
	certPath, keyPath := os.Getenv("SUPIVPN_TEST_CONNECT_CERT"), os.Getenv("SUPIVPN_TEST_CONNECT_KEY")
	if !filepath.IsAbs(certPath) || !filepath.IsAbs(keyPath) {
		t.Fatal("explicit trusted test HTTPS certificate paths required")
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal("test HTTPS identity unavailable")
	}
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	store := postgres.New(pool)
	signer, metadata := testIdP(t)
	metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location = origin + "/test-idp"
	fixture, _ := testApp(t, metadata)
	fixture.origin, _ = url.Parse(origin)
	fixture.sp.EntityID = origin + "/saml/metadata"
	fixture.sp.AcsURL = *fixture.origin.JoinPath("saml/acs")
	fixture.sp.MetadataURL = *fixture.origin.JoinPath("saml/metadata")
	enableTestGroups(fixture)
	raw := make([]byte, 128)
	if _, err = rand.Read(raw); err != nil {
		t.Fatal("test entropy unavailable")
	}
	wrapping := pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: raw})
	clear(raw)
	defer clear(wrapping)
	var issued, discoveries, browserVisits, redemptions atomic.Int32
	issue, err := profile.BoundDownloadIssuer([]byte(openVPNClientTemplate), base.Hostname(), 1195,
		func(context.Context) ([]byte, error) { return bytes.Clone(wrapping), nil },
		func(ctx context.Context, c profile.Credential, subject profile.Owner) error {
			if e := store.CreateProfile(ctx, c, subject); e != nil {
				return e
			}
			issued.Add(1)
			return nil
		})
	if err != nil {
		t.Fatal("bound issuer unavailable")
	}
	c, err := controller.New(controller.Config{Policy: controller.Policy{SAMLGroupsAttribute: "groups",
		Groups: []controller.Group{{GroupName: coreGroup, Priority: 10}}}, PendingSeconds: 180, SessionSeconds: 900},
		fixture.origin, fixture.sp, store, time.Now, controller.ProfileDownloads{
			Backend: postgres.NewProfileBackend(store, 180*time.Second), Imports: store, IssueForSubject: issue})
	if err != nil {
		t.Fatal("controller unavailable")
	}
	product := controlruntime.Bounded(c.Handler())
	idpPage := template.Must(template.New("mock-idp").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>SupiVPN isolated SAML test</title><h1>Authorize the test profile</h1><p>This is an isolated test identity. No real account or password is used.</p><form method="post" action="{{.ACS}}"><input type="hidden" name="RelayState" value="{{.Ticket}}"><input type="hidden" name="SAMLResponse" value="{{.Response}}"><button type="submit">Authorize test identity</button></form></html>`))
	mux := http.NewServeMux()
	mux.HandleFunc("/test-idp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != "GET" || r.Host != base.Host {
			http.NotFound(w, r)
			return
		}
		compressed, e := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLRequest"))
		if e != nil || len(compressed) > 16384 {
			http.Error(w, "Invalid test request", 400)
			return
		}
		reader := flate.NewReader(bytes.NewReader(compressed))
		data, e := io.ReadAll(io.LimitReader(reader, 65537))
		reader.Close()
		var request saml.AuthnRequest
		if e != nil || len(data) > 65536 || xml.Unmarshal(data, &request) != nil || request.ID == "" || request.AssertionConsumerServiceURL != origin+"/saml/acs" {
			http.Error(w, "Invalid test request", 400)
			return
		}
		assertion := groupAssertionFor(fixture, coreGroup)
		assertion.ID = "connect-import-" + request.ID
		assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = request.ID
		body := profileSAMLBody(t, fixture, signer, controller.Pending{Ticket: r.URL.Query().Get("RelayState"), RequestID: request.ID}, assertion, true)
		values, _ := url.ParseQuery(body)
		browserVisits.Add(1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = idpPage.Execute(w, struct{ ACS, Ticket, Response string }{origin + "/saml/acs", values.Get("RelayState"), values.Get("SAMLResponse")})
	})
	mux.HandleFunc("/lab/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int32{"discovery": discoveries.Load(), "browser_saml": browserVisits.Load(), "redemption_requests": redemptions.Load(), "issued": issued.Load()})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openvpn-api/profile" {
			discoveries.Add(1)
		}
		if strings.HasPrefix(r.URL.Path, "/profile/import/") {
			redemptions.Add(1)
		}
		product.ServeHTTP(w, r.WithContext(logging.WithLogger(r.Context(), logging.New(io.Discard, "public"))))
	})
	listener, err := net.Listen("tcp", "127.0.0.1:18443")
	if err != nil {
		t.Fatal("test HTTPS port unavailable")
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	t.Cleanup(func() { server.Close() })
	go func() {
		_ = server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}))
	}()
	t.Log("READY_FOR_CONNECT_SERVER_URL:", origin, "; synthetic SAML identity only")
	deadline := time.NewTimer(20 * time.Minute)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if issued.Load() > 0 {
				if discoveries.Load() == 0 || browserVisits.Load() == 0 || redemptions.Load() == 0 {
					t.Fatal("issuance did not use the expected discovery/SAML/import stages")
				}
				var profiles int
				if pool.QueryRow(ctx, "SELECT count(*) FROM supivpn.issued_profiles WHERE state='active'").Scan(&profiles) != nil || profiles != int(issued.Load()) {
					t.Fatal("issued profile not persisted")
				}
				t.Log("SERVER_FLOW_COMPLETE: signed SAML and one-use import issued a persisted active bound profile; verify native Connect UI separately")
				return
			}
		case <-deadline.C:
			t.Fatal("interactive Server URL import not completed")
		}
	}
}
