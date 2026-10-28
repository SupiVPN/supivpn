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
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beevik/etree"
	"supivpn/internal/controller"
	"supivpn/internal/logging"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
	"supivpn/internal/tracecontext"
)

func profileSAMLBody(t *testing.T, fixture *testApplication, signer *saml.ServiceProvider, pending controller.Pending, assertion *saml.Assertion, sign bool, encrypt ...func(*etree.Element) *etree.Element) string {
	t.Helper()
	response := saml.Response{
		ID: "response-" + pending.RequestID, InResponseTo: pending.RequestID,
		Version: "2.0", IssueInstant: time.Now().UTC(), Destination: fixture.sp.AcsURL.String(),
		Issuer:    &assertion.Issuer,
		Status:    saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}},
		Assertion: assertion,
	}
	element := response.Element()
	if len(encrypt) == 1 && encrypt[0] != nil {
		element = encrypt[0](element)
	}
	if sign {
		signing, err := saml.GetSigningContext(signer)
		if err != nil {
			t.Fatal("test signing context unavailable")
		}
		element, err = signing.SignEnveloped(element)
		if err != nil {
			t.Fatal("test signing failed")
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(element)
	data, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal("test assertion encoding failed")
	}
	return url.Values{"RelayState": {pending.Ticket}, "SAMLResponse": {base64.StdEncoding.EncodeToString(data)}}.Encode()
}

func TestProfileDownloadPostgresSAML(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plaintext"
		if encrypted {
			name = "encrypted"
		}
		t.Run(name, func(t *testing.T) { testProfileDownloadPostgresSAML(t, encrypted) })
	}
}

func testProfileDownloadPostgresSAML(t *testing.T, encrypted bool) {
	pool, other := integrationDatabase(t)
	ctx := context.Background()
	signer, metadata := testIdP(t)
	fixture, commands := testApp(t, metadata)
	var encrypt func(*etree.Element) *etree.Element
	if encrypted {
		encrypt = enableAssertionEncryption(t, fixture.sp)
	}
	enableTestGroups(fixture)
	fixture.origin.Path = "/supivpn"
	fixture.sp.EntityID = fixture.origin.String() + "/saml/metadata"
	fixture.sp.MetadataURL = *fixture.origin.JoinPath("saml/metadata")
	fixture.sp.AcsURL = *fixture.origin.JoinPath("saml/acs")
	s, second := postgres.New(pool), postgres.New(other)
	firstBackend := postgres.NewProfileBackend(s, time.Minute)
	secondBackend := postgres.NewProfileBackend(second, time.Minute)
	var calls atomic.Int32
	var issuerFails atomic.Bool
	// Only ephemeral test material, never a deployed wrapping key.
	keyBytes := make([]byte, 128)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatal("test entropy unavailable")
	}
	wrappingKey := pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: keyBytes})
	template := []byte("client\nremote supivpn.example.test 1194\n<tls-crypt-v2>\n" + profile.Placeholder + "\n</tls-crypt-v2>\n")
	issue, err := profile.DownloadIssuer(template, "vpn.example.test", func(context.Context) ([]byte, error) {
		calls.Add(1)
		if issuerFails.Load() {
			return nil, errors.New("synthetic-loader-failure")
		}
		return bytes.Clone(wrappingKey), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := controller.Config{Policy: controller.Policy{
		SAMLGroupsAttribute: "groups",
		Groups:              []controller.Group{{GroupName: coreGroup, Priority: 10}, {GroupName: devGroup, Priority: 20}},
	}, PendingSeconds: 60, SessionSeconds: 900}
	logs := &auditBuffer{}
	makeHandler := func(backend *postgres.ProfileBackend) http.Handler {
		c, err := controller.New(policy, fixture.origin, fixture.sp, s, time.Now,
			controller.ProfileDownloads{Backend: backend, Issue: issue})
		if err != nil {
			t.Fatal(err)
		}
		h := c.Handler()
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01")
			h.ServeHTTP(w, r.WithContext(logging.WithLogger(r.Context(), logging.New(logs, "public"))))
		})
	}
	first, replica := makeHandler(firstBackend), makeHandler(secondBackend)
	reset := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(ctx, "TRUNCATE supivpn.profile_logins,supivpn.assertions,supivpn.logins,supivpn.nodes CASCADE"); err != nil {
			t.Fatal("cannot reset disposable profile database")
		}
		issuerFails.Store(false)
	}
	begin := func(t *testing.T, viaTile bool) (controller.Pending, *http.Cookie) {
		t.Helper()
		before := calls.Load()
		if viaTile {
			// The tile assertion grants nothing. The existing IdP session is
			// used only by the fresh AuthnRequest after the fixed redirect.
			tile := httptest.NewRecorder()
			r := httptest.NewRequest("POST", fixture.origin.String()+"/saml/launch",
				strings.NewReader("SAMLResponse=ignored&RelayState=https://evil.example.test"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			first.ServeHTTP(tile, r)
			if tile.Code != 303 || tile.Header().Get("Location") != "/supivpn/profile" ||
				len(tile.Result().Cookies()) != 0 || tile.Body.Len() != 0 || calls.Load() != before {
				t.Fatal("tile launch did more than redirect")
			}
			var pendingCount int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM supivpn.profile_logins").Scan(&pendingCount); err != nil || pendingCount != 0 {
				t.Fatal("tile launch created pending authentication state")
			}
		}
		w := httptest.NewRecorder()
		first.ServeHTTP(w, httptest.NewRequest("GET", fixture.origin.String()+"/profile", nil))
		if w.Code != 302 || calls.Load() != before || len(w.Result().Cookies()) != 1 {
			t.Fatal("profile entry failed or accessed key before authentication")
		}
		target, err := url.Parse(w.Header().Get("Location"))
		if err != nil || target.Host != "idp.example.test" || target.Query().Get("SAMLRequest") == "" {
			t.Fatal("profile entry did not start SP-initiated SAML")
		}
		cookie := w.Result().Cookies()[0]
		if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode {
			t.Fatal("browser binding flags missing")
		}
		ticket := target.Query().Get("RelayState")
		pending, err := secondBackend.Lookup(ctx, ticket, sha256.Sum256([]byte(cookie.Value)))
		if err != nil {
			t.Fatal("replica cannot read profile login")
		}
		if _, err := s.Lookup(ctx, ticket, pending.BrowserHash); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("profile ticket became a VPN login")
		}
		return pending, cookie
	}
	submitProfile := func(h http.Handler, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", fixture.sp.AcsURL.String(), strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	var lastProfile []byte
	for _, name := range []string{"valid", "valid-again", "valid-direct", "no-group", "missing-cookie", "wrong-cookie", "unsigned", "wrong-request", "unsolicited", "wrong-recipient", "wrong-destination", "expired", "issuer-failure", "concurrent"} {
		t.Run(name, func(t *testing.T) {
			reset(t)
			pending, cookie := begin(t, name != "valid-direct")
			assertion := groupAssertionFor(fixture, coreGroup, devGroup)
			assertion.ID = "assertion-" + pending.RequestID
			assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = pending.RequestID
			switch name {
			case "no-group":
				assertion.AttributeStatements = nil
			case "missing-cookie":
				cookie = nil
			case "wrong-cookie":
				cookie.Value = "wrong-browser"
			case "wrong-request":
				assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "other-request"
			case "unsolicited":
				pending.RequestID = ""
				assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = ""
			case "wrong-recipient":
				assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = fixture.origin.String() + "/saml/launch"
			case "expired":
				if _, err := pool.Exec(ctx, "UPDATE supivpn.profile_logins SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
					t.Fatal("cannot expire disposable login")
				}
			case "issuer-failure":
				issuerFails.Store(true)
			}
			bodyFixture, bodySP := *fixture, *fixture.sp
			bodyFixture.sp = &bodySP
			if name == "wrong-destination" {
				bodySP.AcsURL.Path = "/supivpn/saml/launch"
			}
			body := profileSAMLBody(t, &bodyFixture, signer, pending, assertion, name != "unsigned", encrypt)
			before := calls.Load()
			if name == "valid" {
				// Even a valid signed callback with its cookie is not consumed
				// on the launch endpoint; only the real ACS may authorize it.
				r := httptest.NewRequest("POST", fixture.origin.String()+"/saml/launch", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				replica.ServeHTTP(w, r)
				if w.Code != 303 || w.Body.Len() != 0 || calls.Load() != before {
					t.Fatal("launch consumed a signed callback")
				}
				if _, err := firstBackend.Lookup(ctx, pending.Ticket, pending.BrowserHash); err != nil {
					t.Fatal("launch changed pending login state")
				}
			}
			if name == "concurrent" {
				responses := make(chan *httptest.ResponseRecorder, 2)
				var wg sync.WaitGroup
				for _, h := range []http.Handler{first, replica} {
					wg.Add(1)
					go func(h http.Handler) { defer wg.Done(); responses <- submitProfile(h, body, cookie) }(h)
				}
				wg.Wait()
				close(responses)
				ok, refused := 0, 0
				for w := range responses {
					if w.Code == 200 {
						ok++
					}
					if w.Code == 410 {
						refused++
					}
				}
				if ok != 1 || refused != 1 || calls.Load() != before+1 {
					t.Fatal("concurrent replicas issued more than one profile")
				}
				return
			}
			w := submitProfile(replica, body, cookie)
			if strings.HasPrefix(name, "valid") {
				trace := tracecontext.ForLogin(pending.Ticket)
				seen := map[string]bool{}
				for _, row := range traceRows(t, logs) {
					if row["trace_id"] == trace {
						seen[row["event"].(string)] = true
					}
				}
				if !seen["saml.login_started"] || !seen["saml.authorization_decided"] || !seen["profile.issued"] {
					t.Fatal("profile trace lost between replicas")
				}
				if bytes.Contains(w.Body.Bytes(), []byte(trace)) || strings.Contains(logs.String(), pending.Ticket) {
					t.Fatal("profile/log disclosed correlation or login material")
				}
				if w.Code != 200 || calls.Load() != before+1 ||
					w.Header().Get("Content-Disposition") != "attachment; filename=\"supivpn.ovpn\"" ||
					w.Header().Get("Content-Type") != "application/x-openvpn-profile" ||
					!strings.Contains(w.Header().Get("Cache-Control"), "no-store") ||
					!bytes.Contains(w.Body.Bytes(), []byte("remote vpn.example.test 1194\n")) ||
					!bytes.Contains(w.Body.Bytes(), []byte("BEGIN OpenVPN tls-crypt-v2 client key")) ||
					bytes.Contains(w.Body.Bytes(), wrappingKey) {
					t.Fatal("authorized profile response invalid")
				}
				if bytes.Equal(lastProfile, w.Body.Bytes()) {
					t.Fatal("downloads shared a client key")
				}
				lastProfile = bytes.Clone(w.Body.Bytes())
				if submitProfile(first, body, cookie).Code != 410 || calls.Load() != before+1 {
					t.Fatal("profile assertion replayed")
				}
			} else {
				expected := 403
				if name == "wrong-cookie" || name == "expired" {
					expected = 410
				}
				if name == "issuer-failure" {
					expected = 503
				}
				if w.Code != expected || bytes.Contains(w.Body.Bytes(), []byte("<tls-crypt-v2>")) ||
					strings.Contains(w.Body.String(), "synthetic-loader-failure") {
					t.Fatalf("invalid profile request status: %d, expected %d", w.Code, expected)
				}
				expectedCalls := before
				if name == "issuer-failure" {
					expectedCalls++
				}
				if calls.Load() != expectedCalls {
					t.Fatal("unauthorized request accessed key")
				}
				if name == "no-group" || name == "issuer-failure" {
					if submitProfile(first, body, cookie).Code != 410 {
						t.Fatal("consumed login retried")
					}
				}
			}
			select {
			case <-commands:
				t.Fatal("profile download issued an OpenVPN management command")
			default:
			}
		})
	}
}

func TestProfileMigrationUpgradeAndExpiry(t *testing.T) {
	pool, other := integrationDatabase(t)
	ctx := context.Background()
	store := postgres.New(pool)
	if _, err := pool.Exec(ctx, "TRUNCATE supivpn.profile_logins,supivpn.assertions,supivpn.logins,supivpn.nodes CASCADE"); err != nil {
		t.Fatal("cannot reset disposable database")
	}
	if err := store.RotateNode(ctx, "migration-node", "", "generation-a"); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if pool.QueryRow(ctx, "SELECT checksum FROM public.supivpn_schema_migrations WHERE version=1").Scan(&original) != nil {
		t.Fatal("missing v1 migration")
	}
	// Recreate the already deployed v1 state, preserving its node and checksum.
	removeProfileSchema(t, pool)
	if _, err := pool.Exec(ctx, `DROP FUNCTION supivpn.lock_node(text),supivpn.agent_heartbeat(text,text,boolean),supivpn.agent_rotate(text,text,text),supivpn.prune_auth(integer);
        DROP TABLE supivpn.profile_logins;
        DROP TABLE supivpn.node_recovery, supivpn.node_recovery_starts,supivpn.node_recovery_stops,
            supivpn.node_maintenance,supivpn.operator_requests;
        ALTER TABLE supivpn.nodes DROP COLUMN healthy_since;
        DROP INDEX supivpn.logins_connection;
        ALTER TABLE supivpn.logins DROP CONSTRAINT logins_decision_bounds;
        ALTER TABLE supivpn.logins DROP COLUMN session_unlimited CASCADE;
        ALTER TABLE supivpn.logins ADD CONSTRAINT logins_check2 CHECK (
            state NOT IN ('decided','acknowledged') OR
            (decision_id IS NOT NULL AND not_before IS NOT NULL AND not_after IS NOT NULL
             AND session_expires_at IS NOT NULL AND not_before < not_after));
        ALTER TABLE supivpn.logins ADD UNIQUE (node_id,generation,cid,kid);
        ALTER TABLE supivpn.logins DROP CONSTRAINT grant_requires_subject;
        ALTER TABLE supivpn.logins DROP COLUMN subject_hash CASCADE, DROP COLUMN username;
        ALTER TABLE supivpn.nodes DROP COLUMN lease_expires_at, DROP COLUMN fence_state, DROP COLUMN fence_retry_at;
        DELETE FROM public.supivpn_schema_migrations WHERE version>1`); err != nil {
		t.Fatal("cannot prepare disposable v1 schema")
	}
	if store.Ready(ctx) {
		t.Fatal("old schema reported ready")
	}
	if postgres.Migrate(ctx, pool) != nil || postgres.Migrate(ctx, other) != nil || !store.Ready(ctx) {
		t.Fatal("v1 to current schema upgrade/retry failed")
	}
	var unchanged []byte
	var nodes int
	if pool.QueryRow(ctx, "SELECT checksum FROM public.supivpn_schema_migrations WHERE version=1").Scan(&unchanged) != nil ||
		!bytes.Equal(original, unchanged) ||
		pool.QueryRow(ctx, "SELECT count(*) FROM supivpn.nodes WHERE node_id='migration-node'").Scan(&nodes) != nil || nodes != 1 {
		t.Fatal("upgrade changed v1 data or checksum")
	}
	backend := postgres.NewProfileBackend(store, time.Minute)
	ticket := "profile_" + strings.Repeat("a", 43)
	browser := sha256.Sum256([]byte("profile-browser"))
	if backend.Start(ctx, ticket, "profile-request", browser) != nil {
		t.Fatal("cannot start profile login")
	}
	if err := backend.Start(ctx, ticket, "replacement-request", browser); !errors.Is(err, controller.ErrLoginStarted) {
		t.Fatal("profile request binding overwritten")
	}
	if _, err := pool.Exec(ctx, "UPDATE supivpn.profile_logins SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal("cannot expire disposable profile")
	}
	if _, err := backend.Lookup(ctx, ticket, browser); !errors.Is(err, controller.ErrLoginExpired) {
		t.Fatal("expired profile login accepted before cleanup")
	}
	if _, err := store.Prune(ctx, 500); err != nil {
		t.Fatal("profile cleanup failed")
	}
	var remaining int
	if pool.QueryRow(ctx, "SELECT count(*) FROM supivpn.profile_logins").Scan(&remaining) != nil || remaining != 0 {
		t.Fatal("expired profile state not pruned")
	}
	// Saturating anonymous starts cannot grow the profile table indefinitely.
	if _, err := pool.Exec(ctx, `
        INSERT INTO supivpn.profile_logins(ticket_hash,request_id,browser_hash,expires_at)
        SELECT decode(md5(n::text)||md5(n::text),'hex'), 'capacity-'||n,
            decode(md5(n::text)||md5(n::text),'hex'), clock_timestamp()+interval '1 minute'
        FROM generate_series(1,256) AS n
    `); err != nil {
		t.Fatal("cannot prepare disposable capacity fixture")
	}
	if err := backend.Start(ctx, ticket, "capacity-overflow", browser); !errors.Is(err, controller.ErrUnavailable) {
		t.Fatal("anonymous profile admission exceeded capacity")
	}
	if _, err := pool.Exec(ctx, "UPDATE supivpn.profile_logins SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal("cannot expire capacity fixture")
	}
	if backend.Start(ctx, ticket, "capacity-recovered", browser) != nil {
		t.Fatal("admission did not recover without scheduled cleanup")
	}
	if pool.QueryRow(ctx, "SELECT count(*) FROM supivpn.profile_logins").Scan(&remaining) != nil || remaining != 1 {
		t.Fatal("expired anonymous state accumulated during admission")
	}
	pending, err := backend.Lookup(ctx, ticket, browser)
	if err != nil {
		t.Fatal("cannot recover admitted profile login")
	}
	now := time.Now().UTC()
	decision := controller.Authorization{SubjectHash: sha256.Sum256([]byte("test-user")), MaxConnections: 1, GroupName: coreGroup,
		AssertionHash:      sha256.Sum256([]byte("cross-purpose-assertion")),
		AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute),
		NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(15 * time.Minute)}
	if backend.Complete(ctx, pending, decision) != nil {
		t.Fatal("profile completion failed")
	}
	// Upgraded legacy nodes cannot renew their expired lease. A clean process
	// restart must establish a new generation before admitting VPN sessions.
	if err := store.RotateNode(ctx, "migration-node", "generation-a", "generation-b"); err != nil {
		t.Fatal("post-upgrade node rotation failed")
	}
	actor := postgres.Agent{NodeID: "migration-node", Generation: "generation-b"}
	vpnTicket := strings.Repeat("v", 43)
	if registerOwnedFixture(t, store, ctx, actor, postgres.Connection{CID: 1, KID: 1}, vpnTicket, time.Minute, decision.SubjectHash) != nil ||
		store.Start(ctx, vpnTicket, "vpn-request", browser) != nil {
		t.Fatal("VPN fixture registration failed")
	}
	vpnPending, err := store.Lookup(ctx, vpnTicket, browser)
	if err != nil {
		t.Fatal("VPN fixture lookup failed")
	}
	if err = store.Complete(ctx, vpnPending, decision); !errors.Is(err, controller.ErrLoginExpired) {
		t.Fatal("profile assertion replayed as a VPN authorization")
	}
	decision.AssertionHash = sha256.Sum256([]byte("fresh-vpn-assertion"))
	if err = store.Complete(ctx, vpnPending, decision); !errors.Is(err, controller.ErrDecisionPending) {
		t.Fatal("replay refusal damaged a fresh VPN login")
	}
}
