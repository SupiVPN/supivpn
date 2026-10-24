// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"supivpn/internal/controller"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"testing"
	"time"
)

func TestServerURLSAMLProfileImport(t *testing.T) {
	pool, other := integrationDatabase(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "TRUNCATE supivpn.profile_logins,supivpn.profile_imports,supivpn.issued_profiles,supivpn.assertions CASCADE"); err != nil {
		t.Fatal("reset")
	}
	signer, metadata := testIdP(t)
	fixture, _ := testApp(t, metadata)
	enableTestGroups(fixture)
	s, replica := postgres.New(pool), postgres.New(other)
	raw := make([]byte, 128)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	wrapping := pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: raw})
	template := []byte("client\nremote supivpn.example.test 1194\n<tls-crypt-v2>\n" + profile.Placeholder + "\n</tls-crypt-v2>\n")
	loads := 0
	issue, err := profile.BoundDownloadIssuer(template, "vpn.example.test", 1195, func(context.Context) ([]byte, error) { loads++; return bytes.Clone(wrapping), nil }, s.CreateProfile)
	if err != nil {
		t.Fatal(err)
	}
	handler := func(store *postgres.Store) http.Handler {
		c, e := controller.New(controller.Config{Policy: controller.Policy{SAMLGroupsAttribute: "groups", Groups: []controller.Group{{GroupName: coreGroup, Priority: 10}}}, PendingSeconds: 60, SessionSeconds: 900}, fixture.origin, fixture.sp, store, time.Now, controller.ProfileDownloads{Backend: postgres.NewProfileBackend(store, time.Minute), Imports: store, IssueForSubject: issue})
		if e != nil {
			t.Fatal(e)
		}
		return c.Handler()
	}
	first, second := handler(s), handler(replica)
	for _, method := range []string{"HEAD", "GET"} {
		w := httptest.NewRecorder()
		first.ServeHTTP(w, httptest.NewRequest(method, fixture.origin.String()+"/openvpn-api/profile?deviceID=untrusted&redirect=https://evil.example.test", nil))
		if w.Code != 200 || w.Header().Get("Ovpn-WebAuth") != "SupiVPN,external" || strings.Contains(w.Body.String(), "evil.example.test") || len(w.Result().Cookies()) != 0 || loads != 0 {
			t.Fatal("unsafe discovery")
		}
	}
	w := httptest.NewRecorder()
	first.ServeHTTP(w, httptest.NewRequest("GET", fixture.origin.String()+"/profile/connect", nil))
	if w.Code != 302 || len(w.Result().Cookies()) != 1 {
		t.Fatal("SAML not started")
	}
	target, _ := url.Parse(w.Header().Get("Location"))
	ticket := target.Query().Get("RelayState")
	cookie := w.Result().Cookies()[0]
	pending, err := postgres.NewProfileBackend(replica, time.Minute).Lookup(ctx, ticket, sha256.Sum256([]byte(cookie.Value)))
	if err != nil {
		t.Fatal("replica lookup", err)
	}
	assertion := groupAssertionFor(fixture, coreGroup)
	assertion.ID = "import-" + pending.RequestID
	assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = pending.RequestID
	body := profileSAMLBody(t, fixture, signer, pending, assertion, true)
	submit := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", fixture.sp.AcsURL.String(), strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		second.ServeHTTP(w, r)
		return w
	}
	if submit(nil).Code != 403 || loads != 0 {
		t.Fatal("unbound browser imported")
	}
	w = submit(cookie)
	if w.Code != 200 || loads != 0 || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("handoff failed or prematurely loaded key")
	}
	match := regexp.MustCompile(`openvpn://import-profile/(https://[^"<>]+)`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("Connect link missing")
	}
	if submit(cookie).Code < 400 {
		t.Fatal("SAML handoff replayed")
	}
	w = httptest.NewRecorder()
	first.ServeHTTP(w, httptest.NewRequest("HEAD", match[1], nil))
	if w.Code != 405 || loads != 0 {
		t.Fatal("HEAD consumed grant")
	}
	w = httptest.NewRecorder()
	first.ServeHTTP(w, httptest.NewRequest("GET", match[1], nil))
	if w.Code != 200 || loads != 1 || w.Header().Get("Content-Type") != "application/x-openvpn-profile" || !strings.Contains(w.Body.String(), "remote vpn.example.test 1195") {
		t.Fatal("profile import failed")
	}
	credential := regexp.MustCompile(`<auth-user-pass>\n([^\n]+)\n([^\n]+)\n</auth-user-pass>`).FindStringSubmatch(w.Body.String())
	if len(credential) != 3 {
		t.Fatal("bound proof absent")
	}
	proof := profile.Credential{ID: credential[1], Secret: credential[2]}
	if !proof.Valid() {
		t.Fatal("invalid proof")
	}
	var stored []byte
	var state string
	if err = pool.QueryRow(ctx, "SELECT secret_hash,state FROM supivpn.issued_profiles WHERE profile_id=$1", proof.ID).Scan(&stored, &state); err != nil || state != "active" {
		t.Fatal("profile not persisted")
	}
	digest, _ := proof.Digest()
	if !bytes.Equal(stored, digest[:]) {
		t.Fatal("digest mismatch")
	}
	w = httptest.NewRecorder()
	second.ServeHTTP(w, httptest.NewRequest("GET", match[1], nil))
	if w.Code != 410 || loads != 1 {
		t.Fatal("handoff replayed across replicas")
	}
}
