// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"supivpn/internal/controller"
	"supivpn/internal/postgres"
	"supivpn/internal/saml"
)

// Explicitly opt-in. Refuse RDS, non-loopback hosts and any database except the
// dedicated disposable supivpn_test. Neither DSN nor raw driver errors are logged.
func integrationDatabase(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("SUPIVPN_TEST_POSTGRES_URL")
	if dsn == "" || os.Getenv("SUPIVPN_TEST_POSTGRES_ALLOW_RESET") != "1" {
		t.Fatal("integration tests require a disposable local supivpn_test database and explicit reset opt-in")
	}
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid integration database configuration")
	}
	ip := net.ParseIP(c.ConnConfig.Host)
	if ip == nil || !ip.IsLoopback() || c.ConnConfig.Database != "supivpn_test" ||
		len(c.ConnConfig.Fallbacks) != 0 {
		t.Fatal("integration database must be literal loopback/supivpn_test with no fallbacks")
	}
	p, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal("local integration database unavailable")
	}
	t.Cleanup(p.Close)
	var version int
	if err = p.QueryRow(context.Background(), "SELECT current_setting('server_version_num')::integer").Scan(&version); err != nil || version < 180000 || version >= 190000 {
		t.Fatal("integration tests require PostgreSQL 18")
	}
	if err = postgres.Migrate(context.Background(), p); err != nil {
		t.Fatal("initial migration failed:", err)
	}
	if err = postgres.Migrate(context.Background(), p); err != nil {
		t.Fatal("migration is not repeatable")
	}
	other, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal("second integration pool unavailable")
	}
	t.Cleanup(other.Close)
	return p, other
}
func TestPostgresIntegration(t *testing.T) {
	p, other := integrationDatabase(t)
	ctx := context.Background()
	s, second := postgres.New(p), postgres.New(other)
	actor := postgres.Agent{NodeID: "node-a", Generation: "generation-a"}
	conn := postgres.Connection{CID: 7, KID: 2}
	ticket := strings.Repeat("a", 43)
	browser := sha256.Sum256([]byte("test-browser"))
	reset := func(t *testing.T) {
		t.Helper()
		if _, err := p.Exec(ctx, "TRUNCATE supivpn.logins,supivpn.assertions,supivpn.nodes RESTART IDENTITY CASCADE"); err != nil {
			t.Fatal("cannot reset disposable database")
		}
		if err := s.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil {
			t.Fatal("cannot register node")
		}
		if err := s.Register(ctx, actor, conn, ticket, time.Minute); err != nil {
			t.Fatal("cannot register login")
		}
	}
	started := func(t *testing.T) controller.Pending {
		t.Helper()
		if err := s.Start(ctx, ticket, "request-7", browser); err != nil {
			t.Fatal("cannot start login")
		}
		pending, err := second.Lookup(ctx, ticket, browser)
		if err != nil {
			t.Fatal("second controller cannot read login")
		}
		return pending
	}
	decision := func() controller.Authorization {
		now := time.Now().UTC()
		return controller.Authorization{Username: "test-user", SubjectHash: sha256.Sum256([]byte("test-user")), MaxConnections: 1, GroupName: "admins-vpn",
			AssertionHash:      sha256.Sum256([]byte("https://idp.example.test/assertion-7")),
			AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute),
			NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(15 * time.Minute)}
	}
	expire := func(t *testing.T) {
		t.Helper()
		if _, err := p.Exec(ctx, "UPDATE supivpn.logins SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
			t.Fatal("cannot expire test login")
		}
	}
	t.Run("registration-and-binding", func(t *testing.T) {
		reset(t)
		pending := started(t)
		if err := second.Register(ctx, actor, conn, ticket, 180*time.Second); err != nil {
			t.Fatal("registration retry failed")
		}
		again, err := s.Lookup(ctx, ticket, browser)
		if err != nil || !again.ExpiresAt.Equal(pending.ExpiresAt) {
			t.Fatal("registration retry extended expiry")
		}
		if err = s.Register(ctx, actor, conn, strings.Repeat("b", 43), time.Minute); !errors.Is(err, postgres.ErrConflict) {
			t.Fatal("second ticket for same connection accepted")
		}
		if err = second.Start(ctx, ticket, "request-other", browser); !errors.Is(err, controller.ErrLoginStarted) {
			t.Fatal("request binding overwritten")
		}
		if _, err = second.Lookup(ctx, ticket, sha256.Sum256([]byte("wrong browser"))); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("wrong browser accepted")
		}
		expire(t)
		if err = s.Register(ctx, actor, conn, ticket, time.Minute); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("expired registration resurrected")
		}
	})
	t.Run("concurrent-completion-and-lost-response", func(t *testing.T) {
		reset(t)
		pending := started(t)
		d := decision()
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for _, store := range []*postgres.Store{s, second} {
			wg.Add(1)
			go func(store *postgres.Store) { defer wg.Done(); results <- store.Complete(ctx, pending, d) }(store)
		}
		wg.Wait()
		close(results)
		queued, replayed := 0, 0
		for err := range results {
			if errors.Is(err, controller.ErrDecisionPending) {
				queued++
			}
			if errors.Is(err, controller.ErrLoginExpired) {
				replayed++
			}
		}
		if queued != 1 || replayed != 1 {
			t.Fatal("concurrent callbacks did not consume exactly once")
		}
		first, err := s.Fetch(ctx, actor, conn)
		if err != nil {
			t.Fatal("cannot recover committed result after discarding callback response")
		}
		repeat, err := second.Fetch(ctx, actor, conn)
		if err != nil || first != repeat {
			t.Fatal("poll retry changed decision")
		}
		if first.Agent != actor || first.Connection != conn || first.GroupName != "admins-vpn" || first.Username != "test-user" {
			t.Fatal("decision binding changed")
		}
		stranger := postgres.Agent{NodeID: "node-b", Generation: actor.Generation}
		if _, err = second.Fetch(ctx, stranger, conn); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("another node fetched decision")
		}
		if err = second.Acknowledge(ctx, stranger, first.ID, postgres.Applied); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("another node acknowledged decision")
		}
		if err = s.Acknowledge(ctx, actor, first.ID, postgres.Applied); err != nil {
			t.Fatal("ACK failed")
		}
		expire(t)
		// Simulate losing the first ACK response: committed identical ACK survives
		// retry even after delivery deadline, without issuing another grant.
		if err = second.Acknowledge(ctx, actor, first.ID, postgres.Applied); err != nil {
			t.Fatal("ACK retry failed")
		}
		if err = s.Acknowledge(ctx, actor, first.ID, postgres.Failed); !errors.Is(err, postgres.ErrConflict) {
			t.Fatal("conflicting ACK overwrote result")
		}
		if _, err = s.Fetch(ctx, actor, conn); !errors.Is(err, postgres.ErrNoDecision) {
			t.Fatal("acknowledged decision redelivered")
		}
	})
	t.Run("assertion-replay-across-logins", func(t *testing.T) {
		reset(t)
		first := started(t)
		d := decision()
		if err := s.Complete(ctx, first, d); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("first completion failed")
		}
		secondTicket := strings.Repeat("b", 43)
		if err := s.Register(ctx, actor, postgres.Connection{CID: 8, KID: 2}, secondTicket, time.Minute); err != nil {
			t.Fatal("registration failed")
		}
		if err := s.Start(ctx, secondTicket, "request-8", browser); err != nil {
			t.Fatal("start failed")
		}
		pending, err := s.Lookup(ctx, secondTicket, browser)
		if err != nil {
			t.Fatal("lookup failed")
		}
		if err = second.Complete(ctx, pending, d); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("assertion reused across requests")
		}
	})
	t.Run("cancel-and-generation-fencing", func(t *testing.T) {
		reset(t)
		pending := started(t)
		if err := s.Cancel(ctx, actor, conn); err != nil {
			t.Fatal("cancel failed")
		}
		if err := s.Cancel(ctx, actor, conn); err != nil {
			t.Fatal("cancel retry failed")
		}
		if err := second.Complete(ctx, pending, decision()); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("disconnected request authorized")
		}
		reset(t)
		pending = started(t)
		if err := s.Complete(ctx, pending, decision()); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("completion failed")
		}
		if err := s.RotateNode(ctx, actor.NodeID, actor.Generation, "generation-b"); err != nil {
			t.Fatal("rotation failed")
		}
		if _, err := s.Fetch(ctx, actor, conn); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("old agent fetched decision")
		}
		if err := s.RotateNode(ctx, actor.NodeID, "", "generation-a"); !errors.Is(err, postgres.ErrGeneration) {
			t.Fatal("old bootstrap replay changed generation")
		}
		if err := second.RotateNode(ctx, actor.NodeID, actor.Generation, "generation-b"); err != nil {
			t.Fatal("rotation retry failed")
		}
		if err := s.RotateNode(ctx, actor.NodeID, "generation-b", actor.Generation); !errors.Is(err, postgres.ErrGeneration) {
			t.Fatal("retired generation reused")
		}
		if err := s.RotateNode(ctx, "unknown-node", "missing-generation", "new-generation"); !errors.Is(err, postgres.ErrGeneration) {
			t.Fatal("unknown predecessor accepted")
		}
		if err := s.Register(ctx, actor, postgres.Connection{CID: 9, KID: 2}, strings.Repeat("c", 43), time.Minute); !errors.Is(err, postgres.ErrGeneration) {
			t.Fatal("old agent registered login")
		}
	})
	t.Run("late-decision-and-stale-snapshot", func(t *testing.T) {
		reset(t)
		pending := started(t)
		d := decision()
		stale := pending
		stale.Revision++
		if err := s.Complete(ctx, stale, d); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("stale revision accepted")
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if err := s.Complete(cancelled, pending, d); !errors.Is(err, controller.ErrUnavailable) {
			t.Fatal("cancelled operation succeeded")
		}
		if _, err := s.Lookup(ctx, ticket, browser); err != nil {
			t.Fatal("cancelled operation consumed request")
		}
		lock, err := p.Begin(ctx)
		if err != nil {
			t.Fatal("cannot begin lock test")
		}
		defer lock.Rollback(ctx)
		if _, err = lock.Exec(ctx, "SELECT ticket_hash FROM supivpn.logins FOR UPDATE"); err != nil {
			t.Fatal("cannot lock test row")
		}
		d.NotOnOrAfter = time.Now().Add(100 * time.Millisecond)
		completed := make(chan error, 1)
		go func() { completed <- second.Complete(ctx, pending, d) }()
		time.Sleep(200 * time.Millisecond)
		if err = lock.Commit(ctx); err != nil {
			t.Fatal("cannot release test row")
		}
		if err = <-completed; !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("expiry not rechecked after row lock")
		}
		var count int
		if err = p.QueryRow(ctx, "SELECT count(*) FROM supivpn.assertions").Scan(&count); err != nil || count != 0 {
			t.Fatal("failed completion committed replay entry")
		}
	})
	t.Run("denial-and-expired-delivery", func(t *testing.T) {
		reset(t)
		pending := started(t)
		d := decision()
		d.GroupName = ""
		d.DenialReason = "no_vpn_group"
		if err := s.Complete(ctx, pending, d); !errors.Is(err, controller.ErrGroupDenied) {
			t.Fatal("denial not persisted")
		}
		result, err := s.Fetch(ctx, actor, conn)
		if err != nil || result.DenialReason != "no_vpn_group" {
			t.Fatal("agent did not receive denial")
		}
		if err = s.Acknowledge(ctx, actor, result.ID, postgres.Applied); !errors.Is(err, postgres.ErrConflict) {
			t.Fatal("denial acknowledged as grant")
		}
		if err = s.Acknowledge(ctx, actor, result.ID, postgres.Denied); err != nil {
			t.Fatal("denial ACK failed")
		}
		reset(t)
		pending = started(t)
		if err = s.Complete(ctx, pending, decision()); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("grant failed")
		}
		result, err = s.Fetch(ctx, actor, conn)
		if err != nil {
			t.Fatal("fetch failed")
		}
		expire(t)
		if _, err = s.Fetch(ctx, actor, conn); !errors.Is(err, postgres.ErrNoDecision) {
			t.Fatal("expired result delivered")
		}
		if err = s.Acknowledge(ctx, actor, result.ID, postgres.Applied); !errors.Is(err, controller.ErrLoginExpired) {
			t.Fatal("late ACK accepted")
		}
	})
	t.Run("bounded-cleanup", func(t *testing.T) {
		reset(t)
		pending := started(t)
		if err := s.Complete(ctx, pending, decision()); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("completion failed")
		}
		if n, err := s.Prune(ctx, 10); err != nil || n != 0 {
			t.Fatal("live state deleted")
		}
		if _, err := p.Exec(ctx, "UPDATE supivpn.logins SET expires_at=clock_timestamp()-interval '25 hours'"); err != nil {
			t.Fatal("cannot age test tombstone")
		}
		if n, err := s.Prune(ctx, 1); err != nil || n != 0 {
			t.Fatal("unconfirmed active session deleted by TTL")
		}
		if err := s.Cancel(ctx, actor, conn); err != nil {
			t.Fatal("cannot confirm test disconnect")
		}
		if n, err := s.Prune(ctx, 1); err != nil || n != 1 {
			t.Fatal("tombstone not deleted")
		}
		var count int
		if err := p.QueryRow(ctx, "SELECT count(*) FROM supivpn.assertions").Scan(&count); err != nil || count != 1 {
			t.Fatal("live assertion replay protection deleted")
		}
	})
	t.Run("completion-transaction-rollback", func(t *testing.T) {
		reset(t)
		pending := started(t)
		// Force a database failure AFTER the replay INSERT, at the decision UPDATE.
		if _, err := p.Exec(ctx, `CREATE FUNCTION supivpn.reject_test_decision() RETURNS trigger
			LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test decision failure'; END $$;
			CREATE TRIGGER reject_test_decision BEFORE UPDATE ON supivpn.logins
			FOR EACH ROW WHEN (NEW.state='decided') EXECUTE FUNCTION supivpn.reject_test_decision()`); err != nil {
			t.Fatal("cannot install local failure fixture")
		}
		defer func() {
			if _, err := p.Exec(ctx, `DROP TRIGGER IF EXISTS reject_test_decision ON supivpn.logins;
				DROP FUNCTION IF EXISTS supivpn.reject_test_decision()`); err != nil {
				t.Error("cannot remove local failure fixture")
			}
		}()
		if err := s.Complete(ctx, pending, decision()); !errors.Is(err, controller.ErrUnavailable) {
			t.Fatal("database failure was not reported safely")
		}
		var count int
		if err := p.QueryRow(ctx, "SELECT count(*) FROM supivpn.assertions").Scan(&count); err != nil || count != 0 {
			t.Fatal("failed decision committed replay entry")
		}
		if _, err := second.Lookup(ctx, ticket, browser); err != nil {
			t.Fatal("failed decision consumed pending request")
		}
	})
	t.Run("migration-guards", func(t *testing.T) {
		results := make(chan error, 2)
		for _, pool := range []*pgxpool.Pool{p, other} {
			go func(pool *pgxpool.Pool) { results <- postgres.Migrate(ctx, pool) }(pool)
		}
		for range 2 {
			if err := <-results; err != nil {
				t.Fatal("concurrent migration retry failed")
			}
		}
		var checksum []byte
		if err := p.QueryRow(ctx, "SELECT checksum FROM public.supivpn_schema_migrations WHERE version=1").Scan(&checksum); err != nil {
			t.Fatal("cannot read test migration checksum")
		}
		defer func() {
			if _, err := p.Exec(ctx, "UPDATE public.supivpn_schema_migrations SET checksum=$1 WHERE version=1", checksum); err != nil {
				t.Error("cannot restore test migration checksum")
			}
		}()
		if _, err := p.Exec(ctx, "UPDATE public.supivpn_schema_migrations SET checksum=$1 WHERE version=1", []byte("changed-test-migration")); err != nil {
			t.Fatal("cannot set local checksum fixture")
		}
		if err := postgres.Migrate(ctx, other); err == nil {
			t.Fatal("modified migration accepted")
		}
	})
	t.Run("signed-saml-across-controllers", func(t *testing.T) {
		reset(t)
		signer, md := testIdP(t)
		a, _ := testApp(t, md)
		policy := controller.Config{Policy: controller.Policy{SAMLGroupsAttribute: "groups",
			Groups: []controller.Group{{GroupName: "admins-vpn", Priority: 10}}}, PendingSeconds: 180, SessionSeconds: 900}
		first, err := controller.New(policy, a.origin, a.sp, s, time.Now)
		if err != nil {
			t.Fatal("first controller initialization failed")
		}
		next, err := controller.New(policy, a.origin, a.sp, second, time.Now)
		if err != nil {
			t.Fatal("second controller initialization failed")
		}
		response := httptest.NewRecorder()
		first.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, a.origin.String()+"/login/"+ticket, nil))
		if response.Code != http.StatusFound || len(response.Result().Cookies()) != 1 {
			t.Fatal("controller did not start login")
		}
		cookie := response.Result().Cookies()[0]
		pending, err := second.Lookup(ctx, ticket, sha256.Sum256([]byte(cookie.Value)))
		if err != nil {
			t.Fatal("second controller cannot find browser binding")
		}
		assertion := assertionFor(a)
		assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = pending.RequestID
		assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: []saml.Attribute{
			{Name: "groups", Values: []saml.AttributeValue{{Value: "admins-vpn"}}},
		}}}
		sr := saml.Response{ID: "response-pg", InResponseTo: pending.RequestID, Version: "2.0",
			IssueInstant: time.Now().UTC(), Destination: a.sp.AcsURL.String(), Issuer: &assertion.Issuer,
			Status: saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}}, Assertion: assertion}
		signing, err := saml.GetSigningContext(signer)
		if err != nil {
			t.Fatal("signing fixture unavailable")
		}
		signed, err := signing.SignEnveloped(sr.Element())
		if err != nil {
			t.Fatal("cannot sign fixture")
		}
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		xml, err := doc.WriteToString()
		if err != nil {
			t.Fatal("cannot render fixture")
		}
		body := url.Values{"RelayState": {ticket}, "SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(xml))}}.Encode()
		send := func(h http.Handler) int {
			req := httptest.NewRequest(http.MethodPost, a.sp.AcsURL.String(), strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			return out.Code
		}
		if send(next.Handler()) != http.StatusAccepted {
			t.Fatal("second controller did not queue verified SAML decision")
		}
		if send(first.Handler()) != http.StatusGone {
			t.Fatal("first controller accepted replay")
		}
		result, err := s.Fetch(ctx, actor, conn)
		if err != nil || result.GroupName != "admins-vpn" {
			t.Fatal("verified group not delivered to agent")
		}
	})
}
