// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
	"time"

	"supivpn/internal/controller"

	"supivpn/internal/saml"
)

// The existing end-to-end SAML tests exercise the extracted controller against
// the real local backend and management protocol, rather than a second verifier.
type testApplication struct {
	*agent
	sp *saml.ServiceProvider
}

func (a *testApplication) handler() http.Handler {
	control, err := newController(a.agent, a.sp)
	if err != nil {
		panic(err) // Invalid test setup, not a production request path.
	}
	return control.Handler()
}

func cookieName(ticket string) string { return controller.CookieName(ticket) }

const groupAttributeFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"

func TestLocalBackendRechecksCompletion(t *testing.T) {
	for _, name := range []string{"expired-assertion", "expired-session", "not-yet-valid",
		"expired-pending", "disconnected", "replaced-connection", "wrong-browser",
		"cancelled", "already-used", "management-lost"} {
		t.Run(name, func(t *testing.T) {
			a, commands := testApp(t, nil)
			ctx := context.Background()
			pending, err := a.Lookup(ctx, "test-ticket", sha256.Sum256([]byte("test-browser")))
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			decision := controller.Authorization{SubjectHash: sha256.Sum256([]byte("test-user")), MaxConnections: 1, NotBefore: now.Add(-time.Minute),
				NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(15 * time.Minute)}
			switch name {
			case "expired-assertion":
				decision.NotOnOrAfter = now.Add(-time.Second)
			case "expired-session":
				decision.SessionExpiresAt = now.Add(-time.Second)
			case "not-yet-valid":
				decision.NotBefore = now.Add(time.Minute)
			case "expired-pending":
				a.connections[7].expires = now.Add(-time.Second)
			case "disconnected":
				a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 7})
			case "replaced-connection":
				replacement := *a.connections[7]
				replacement.revision++
				a.connections[7], a.tickets["test-ticket"] = &replacement, &replacement
			case "wrong-browser":
				pending.BrowserHash = sha256.Sum256([]byte("other-browser"))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "already-used":
				if err := a.Complete(ctx, pending, decision); err != nil {
					t.Fatal(err)
				}
				<-commands
			case "management-lost":
				a.management.close()
			}
			if err := a.Complete(ctx, pending, decision); err == nil {
				t.Fatal("stale or invalid completion authorized")
			}
			if len(commands) != 0 {
				t.Fatal("invalid completion issued a management command")
			}
		})
	}
}

func TestControllerReplacementPreservesAgentState(t *testing.T) {
	signer, md := testIdP(t)
	a, commands := testApp(t, md)
	first, err := newController(a.agent, a.sp)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newController(a.agent, a.sp)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("test requires separate controller instances")
	}
	// One controller sees an invalid reply; another must still see the pending
	// entry. After successful redemption, neither may accept the same reply.
	unsigned := responseBody(t, a, signer, assertionFor(a), false, false)
	if submitTo(first.Handler(), a, unsigned, "test-browser").Code != http.StatusForbidden {
		t.Fatal("unsigned reply accepted")
	}
	body := responseBody(t, a, signer, assertionFor(a), true, false)
	if submitTo(second.Handler(), a, body, "test-browser").Code != http.StatusOK {
		t.Fatal("replacement controller lost the pending login")
	}
	<-commands
	expires := a.connections[7].expires
	if submitTo(first.Handler(), a, body, "test-browser").Code == http.StatusOK {
		t.Fatal("replacement controller accepted a replay")
	}
	a.handleEvent(clientEvent{kind: "REAUTH", cid: 7, kid: 3})
	if command := <-commands; command != "client-auth-nt 7 3" || a.connections[7].expires != expires {
		t.Fatal("controller replacement changed the active VPN session")
	}
}

func TestLocalBackendStartOnlyOnce(t *testing.T) {
	a, _ := testApp(t, nil)
	a.connections[7].requestID = ""
	hash := sha256.Sum256([]byte("test-browser"))
	if err := a.Start(context.Background(), "test-ticket", "new-request", hash); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background(), "test-ticket", "other-request", hash); !errors.Is(err, controller.ErrLoginStarted) {
		t.Fatal("browser binding was overwritten")
	}
}

type delayedCompletion struct {
	controller.Backend
	beforeComplete func()
}

func (b delayedCompletion) Complete(ctx context.Context, pending controller.Pending, decision controller.Authorization) error {
	b.beforeComplete()
	return b.Backend.Complete(ctx, pending, decision)
}

func TestSignedAssertionExpiryBetweenValidationAndCommit(t *testing.T) {
	signer, md := testIdP(t)
	a, commands := testApp(t, md)
	assertion := assertionFor(a)
	assertion.Conditions.NotOnOrAfter = time.Now().Add(10 * time.Second)
	control, err := controller.New(controller.Config{Policy: controllerPolicy(a.config),
		PendingSeconds: 180, SessionSeconds: 900}, a.origin, a.sp,
		delayedCompletion{Backend: a.agent, beforeComplete: func() {
			a.now = func() time.Time { return assertion.Conditions.NotOnOrAfter }
		}}, func() time.Time { return a.now() })
	if err != nil {
		t.Fatal(err)
	}
	body := responseBody(t, a, signer, assertion, true, false)
	if submitTo(control.Handler(), a, body, "test-browser").Code != http.StatusGone ||
		a.connections[7].active || len(commands) != 0 {
		t.Fatal("signature-validated but expired assertion authorized at commit")
	}
}
