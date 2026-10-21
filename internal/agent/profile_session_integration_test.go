// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

func TestProfileDownloadSessionPolicy(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	signer, metadata := testIdP(t)
	unlimited, finite := 0, 900
	for _, tc := range []struct {
		name         string
		seconds      int
		groupSeconds *int
		idpCap       time.Duration
		status       int
	}{
		{"finite", finite, nil, 0, http.StatusOK},
		{"inherited-unlimited", unlimited, nil, 0, http.StatusOK},
		{"group-unlimited", finite, &unlimited, 0, http.StatusOK},
		{"group-finite", unlimited, &finite, 0, http.StatusOK},
		{"unlimited-with-idp-cap", unlimited, nil, 5 * time.Minute, http.StatusOK},
		{"group-unlimited-with-idp-cap", finite, &unlimited, 5 * time.Minute, http.StatusOK},
		{"unlimited-with-expired-idp-cap", unlimited, nil, -time.Minute, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, "TRUNCATE supivpn.profile_logins,supivpn.assertions CASCADE"); err != nil {
				t.Fatal("cannot reset disposable profile database")
			}
			fixture, _ := testApp(t, metadata)
			enableTestGroups(fixture)
			store := postgres.New(pool)
			backend := postgres.NewProfileBackend(store, time.Minute)
			calls := 0
			c, err := controller.New(controller.Config{Policy: controller.Policy{
				SAMLGroupsAttribute: "groups",
				Groups:              []controller.Group{{GroupName: coreGroup, Priority: 10, SessionSeconds: tc.groupSeconds}},
			}, PendingSeconds: 60, SessionSeconds: tc.seconds}, fixture.origin, fixture.sp, store, time.Now,
				controller.ProfileDownloads{Backend: backend, Issue: func(context.Context) ([]byte, error) {
					calls++
					return []byte("synthetic test profile"), nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			h := c.Handler()
			entry := httptest.NewRecorder()
			h.ServeHTTP(entry, httptest.NewRequest("GET", fixture.origin.String()+"/profile", nil))
			if entry.Code != http.StatusFound || len(entry.Result().Cookies()) != 1 || calls != 0 {
				t.Fatal("profile entry failed or issued before authentication")
			}
			target, err := url.Parse(entry.Header().Get("Location"))
			if err != nil {
				t.Fatal("invalid authentication redirect")
			}
			cookie := entry.Result().Cookies()[0]
			pending, err := backend.Lookup(ctx, target.Query().Get("RelayState"), sha256.Sum256([]byte(cookie.Value)))
			if err != nil {
				t.Fatal("cannot look up profile login")
			}
			assertion := groupAssertionFor(fixture, coreGroup)
			assertion.ID = "assertion-" + pending.RequestID
			assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = pending.RequestID
			for i := range assertion.AuthnStatements {
				assertion.AuthnStatements[i].SessionNotOnOrAfter = nil
				if tc.idpCap != 0 {
					expiry := time.Now().Add(tc.idpCap)
					assertion.AuthnStatements[i].SessionNotOnOrAfter = &expiry
				}
			}
			body := profileSAMLBody(t, fixture, signer, pending, assertion, true)
			submit := func() int {
				req := httptest.NewRequest("POST", fixture.sp.AcsURL.String(), strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.AddCookie(cookie)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req)
				return w.Code
			}
			if status := submit(); status != tc.status {
				t.Fatalf("profile response = %d, want %d", status, tc.status)
			}
			var consumed bool
			var assertions int
			if pool.QueryRow(ctx, "SELECT consumed FROM supivpn.profile_logins").Scan(&consumed) != nil ||
				pool.QueryRow(ctx, "SELECT count(*) FROM supivpn.assertions").Scan(&assertions) != nil {
				t.Fatal("cannot inspect disposable profile state")
			}
			if tc.status == http.StatusOK {
				if calls != 1 || !consumed || assertions != 1 || submit() != http.StatusGone || calls != 1 {
					t.Fatal("profile authorization was not consumed exactly once")
				}
			} else if calls != 0 || consumed || assertions != 0 {
				t.Fatal("expired IdP authorization issued or consumed a profile")
			}
		})
	}
}

func TestProfileCompletionSessionBounds(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	backend := postgres.NewProfileBackend(postgres.New(pool), time.Minute)
	for _, tc := range []struct {
		name   string
		mutate func(*controller.Pending, *controller.Authorization, time.Time)
	}{
		{"missing-expiry-without-unlimited", func(_ *controller.Pending, d *controller.Authorization, _ time.Time) { d.SessionUnlimited = false }},
		{"unlimited-with-expiry", func(_ *controller.Pending, d *controller.Authorization, now time.Time) {
			d.SessionExpiresAt = now.Add(time.Minute)
		}},
		{"expired-finite-session", func(_ *controller.Pending, d *controller.Authorization, now time.Time) {
			d.SessionUnlimited, d.SessionExpiresAt = false, now.Add(-time.Second)
		}},
		{"expired-assertion", func(_ *controller.Pending, d *controller.Authorization, now time.Time) {
			d.NotOnOrAfter = now.Add(-time.Second)
		}},
		{"future-assertion", func(_ *controller.Pending, d *controller.Authorization, now time.Time) {
			d.NotBefore = now.Add(time.Minute)
		}},
		{"wrong-browser", func(p *controller.Pending, _ *controller.Authorization, _ time.Time) {
			p.BrowserHash = sha256.Sum256([]byte("other-browser"))
		}},
		{"wrong-request", func(p *controller.Pending, _ *controller.Authorization, _ time.Time) { p.RequestID = "other-request" }},
		{"wrong-expiry", func(p *controller.Pending, _ *controller.Authorization, _ time.Time) {
			p.ExpiresAt = p.ExpiresAt.Add(time.Minute)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, "TRUNCATE supivpn.profile_logins,supivpn.assertions CASCADE"); err != nil {
				t.Fatal("cannot reset disposable profile database")
			}
			ticket := "profile_" + strings.Repeat("a", 43)
			browser := sha256.Sum256([]byte("profile-browser"))
			if err := backend.Start(ctx, ticket, "profile-request", browser); err != nil {
				t.Fatal(err)
			}
			pending, err := backend.Lookup(ctx, ticket, browser)
			if err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now) != nil {
				t.Fatal("cannot read disposable database clock")
			}
			decision := controller.Authorization{
				SubjectHash: sha256.Sum256([]byte("test-subject")), MaxConnections: 1, GroupName: coreGroup,
				AssertionHash: sha256.Sum256([]byte("test-assertion")), AssertionExpiresAt: now.Add(5 * time.Minute),
				NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute), SessionUnlimited: true,
			}
			invalidPending, invalidDecision := pending, decision
			tc.mutate(&invalidPending, &invalidDecision, now)
			if err := backend.Complete(ctx, invalidPending, invalidDecision); !errors.Is(err, controller.ErrLoginExpired) {
				t.Fatalf("invalid profile authorization: %v", err)
			}
			// Rejection must preserve the pending login and roll back any replay insert.
			if err := backend.Complete(ctx, pending, decision); err != nil {
				t.Fatalf("valid unlimited authorization failed after rejection: %v", err)
			}
			if err := backend.Complete(ctx, pending, decision); !errors.Is(err, controller.ErrLoginExpired) {
				t.Fatal("unlimited authorization replayed")
			}
		})
	}
}

func TestProfileCompletionExpiryAfterReplayLock(t *testing.T) {
	pool, other := integrationDatabase(t)
	for _, bound := range []string{"pending", "assertion", "session"} {
		t.Run(bound, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := pool.Exec(ctx, "TRUNCATE supivpn.profile_logins,supivpn.assertions CASCADE"); err != nil {
				t.Fatal("cannot reset disposable profile database")
			}
			backend := postgres.NewProfileBackend(postgres.New(pool), time.Minute)
			ticket := "profile_" + strings.Repeat("a", 43)
			browser := sha256.Sum256([]byte("profile-browser"))
			if err := backend.Start(ctx, ticket, "profile-request", browser); err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now) != nil {
				t.Fatal("cannot read disposable database clock")
			}
			deadline := now.Add(time.Second)
			if bound == "pending" {
				if _, err := pool.Exec(ctx, "UPDATE supivpn.profile_logins SET expires_at=$1", deadline); err != nil {
					t.Fatal("cannot bound disposable profile lifetime")
				}
			}
			pending, err := backend.Lookup(ctx, ticket, browser)
			if err != nil {
				t.Fatal(err)
			}
			decision := controller.Authorization{
				SubjectHash: sha256.Sum256([]byte("test-subject")), MaxConnections: 1, GroupName: coreGroup,
				AssertionHash: sha256.Sum256([]byte("test-assertion")), AssertionExpiresAt: now.Add(5 * time.Minute),
				NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute), SessionUnlimited: true,
			}
			switch bound {
			case "assertion":
				decision.NotOnOrAfter = deadline
			case "session":
				decision.SessionUnlimited, decision.SessionExpiresAt = false, deadline
			}
			blocker, err := other.Begin(ctx)
			if err != nil {
				t.Fatal("cannot start disposable blocking transaction")
			}
			defer blocker.Rollback(context.Background())
			if _, err := blocker.Exec(ctx, "INSERT INTO supivpn.assertions(assertion_hash,expires_at) VALUES($1,$2)",
				decision.AssertionHash[:], decision.AssertionExpiresAt); err != nil {
				t.Fatal("cannot reserve disposable assertion")
			}
			result := make(chan error, 1)
			go func() { result <- backend.Complete(ctx, pending, decision) }()
			// Prove Complete passed its initial validation and now waits at the
			// replay INSERT. Releasing this transaction after expiry must not grant.
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			for {
				var waiting bool
				if pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
					int32(blocker.Conn().PgConn().PID())).Scan(&waiting) != nil {
					t.Fatal("cannot observe disposable assertion lock")
				}
				if waiting {
					break
				}
				select {
				case err := <-result:
					t.Fatalf("completion returned before replay lock: %v", err)
				case <-ctx.Done():
					t.Fatal("completion did not reach replay lock")
				case <-tick.C:
				}
			}
			for {
				var expired bool
				if pool.QueryRow(ctx, "SELECT clock_timestamp()>=$1", deadline).Scan(&expired) != nil {
					t.Fatal("cannot observe disposable deadline")
				}
				if expired {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("database deadline did not elapse")
				case <-tick.C:
				}
			}
			if err := blocker.Rollback(ctx); err != nil {
				t.Fatal("cannot release disposable assertion lock")
			}
			if err := <-result; !errors.Is(err, controller.ErrLoginExpired) {
				t.Fatalf("authorization expired during replay wait: %v", err)
			}
			var consumed bool
			var assertions int
			if pool.QueryRow(ctx, "SELECT consumed FROM supivpn.profile_logins").Scan(&consumed) != nil ||
				pool.QueryRow(ctx, "SELECT count(*) FROM supivpn.assertions").Scan(&assertions) != nil || consumed || assertions != 0 {
				t.Fatal("expired completion consumed profile or retained assertion")
			}
		})
	}
}
