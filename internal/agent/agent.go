// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"supivpn/internal/logging"
	"supivpn/internal/tracecontext"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

const maxConnections = 16

type connection struct {
	username string
    sessionUnlimited bool
    closeBy time.Time
	subjectHash [32]byte
	cid, kid    uint64
	revision    uint64
	ticket      string
	expires     time.Time
	active      bool
	requestID   string
	browserHash [32]byte
	closing     bool
	groupName   string
	address     netip.Addr
}

type agent struct {
	logger *logging.Logger
	mu           sync.Mutex
	config       config
	origin       *url.URL
	management   *management
	connections  map[uint64]*connection
	tickets      map[string]*connection
	now          func() time.Time
	pools        *poolAllocator
	nextRevision uint64
	remote       *remoteAgent
}

// Unlimited is valid only for an explicitly authorized active session.
func (c *connection) sessionValid(now time.Time) bool {
    return c.active && c.sessionUnlimited && c.expires.IsZero() || !c.sessionUnlimited && !c.expires.IsZero() && now.Before(c.expires)
}

func newAgent(c config, origin *url.URL) *agent {
	a := &agent{config: c, origin: origin, connections: make(map[uint64]*connection),
		tickets: make(map[string]*connection), now: time.Now}
	return a
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *agent) attach(m *management) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.management = m
}

func (a *agent) readyLocked() bool {
	if a.management == nil {
		return false
	}
	select {
	case <-a.management.done:
		return false
	default:
		return true
	}
}

func (a *agent) removeLocked(c *connection) {
	delete(a.tickets, c.ticket)
	if a.connections[c.cid] == c {
		if a.remote != nil {
			a.cancelRemoteLocked(c)
		}
		delete(a.connections, c.cid)
		if a.pools != nil {
			a.pools.release(c.cid)
		}
	}
}

func (a *agent) commandLocked(command string) error {
	if !a.readyLocked() {
		return errors.New("OpenVPN unavailable")
	}
	return a.management.command(command)
}

func (a *agent) denyLocked(e clientEvent) {
	if a.commandLocked(fmt.Sprintf("client-deny %d %d \"SSO required or expired\"", e.cid, e.kid)) != nil {
		// An uncertain authorization result is not recoverable within this process.
		a.management.close()
	}
}

// A successful kill command is not proof of disconnection. Keep the IP/slot
// until DISCONNECT; an unresponsive daemon must not retain an expired grant.
func (a *agent) closeClientLocked(c *connection) {
    if !c.closeBy.IsZero() { return }
    c.closing = true
    c.closeBy = a.now().Add(30*time.Second)
    delete(a.tickets, c.ticket)
    if a.commandLocked(fmt.Sprintf("client-kill %d", c.cid)) != nil {
        a.management.close()
    }
}

// Management events and authorization commits share this lock. No web callback
// can authorize a disconnected/replaced CID, or redeem the same request twice.
func (a *agent) handleEvent(e clientEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.remote != nil && !a.now().Before(a.remote.leaseUntil) {
		a.management.close()
		return
	}
	switch e.kind {
	case "CONNECT":
		if _, exists := a.connections[e.cid]; exists {
			a.management.close()
			return
		}
		if len(a.connections) >= maxConnections || !supportsWebAuth(e.sso) {
			a.denyLocked(e)
			a.logEvent("vpn.authentication_refused", nil, slog.Uint64("cid", e.cid), slog.String("reason", "capacity_or_missing_webauth"))
			return
		}
		if a.remote != nil && !a.remote.canRegister(e) {
			a.denyLocked(e)
			return
		}
		token, err := randomToken()
		if err != nil {
			a.denyLocked(e)
			return
		}
		a.nextRevision++
		c := &connection{cid: e.cid, kid: e.kid, revision: a.nextRevision, ticket: token,
			expires: a.now().Add(time.Duration(a.config.PendingSeconds) * time.Second)}
		a.connections[e.cid], a.tickets[token] = c, c
		a.logEvent("vpn.connection_requested", c)
		if a.remote != nil {
			a.remote.enqueue(c)
			return
		}
		command := fmt.Sprintf("client-pending-auth %d %d \"WEB_AUTH:external:%s/login/%s\" %d",
			c.cid, c.kid, a.origin.String(), token, a.config.PendingSeconds)
		if a.commandLocked(command) != nil {
			a.removeLocked(c)
			a.management.close()
			return
		}
		a.logEvent("vpn.browser_auth_requested", c)
	case "REAUTH":
		c := a.connections[e.cid]
		if c != nil && c.active && (c.closing || !c.sessionValid(a.now())) {
            // Normal expiry requests RESTART, not AUTH_FAILED: Connect must be
            // allowed to reconnect and perform a fresh browser authentication.
            a.closeClientLocked(c)
            return
        }
		if c == nil || c.closing || !c.active || !c.sessionValid(a.now()) {
			a.denyLocked(e)
			// client-deny alone may leave the old TLS key alive until it expires.
			if c != nil {
				a.closeClientLocked(c)
			} else if a.commandLocked(fmt.Sprintf("client-kill %d", e.cid)) != nil {
				a.management.close()
			}
			return
		}
		if a.commandLocked(fmt.Sprintf("client-auth-nt %d %d", e.cid, e.kid)) != nil {
			a.management.close()
		} else {
			a.logEvent("vpn.tls_reauthenticated", c, slog.Uint64("kid", e.kid))
		}
	case "DISCONNECT":
		if c := a.connections[e.cid]; c != nil {
			a.logTunnelEvent("vpn.disconnected", c)
			a.removeLocked(c)
		} else {
			a.logEvent("vpn.disconnected", nil, slog.Uint64("cid", e.cid))
		}
	case "ESTABLISHED":
		if c := a.connections[e.cid]; c != nil && c.active && !c.closing {
			a.logTunnelEvent("vpn.tunnel_established", c)
		} else {
			a.management.close()
		}
	}
}

func (a *agent) logEvent(event string, c *connection, attrs ...slog.Attr) {
	if c != nil { attrs = append(attrs, slog.Uint64("cid", c.cid), slog.Uint64("kid", c.kid)) }
	if a.remote != nil { attrs = append(attrs, slog.String("node_id", a.remote.node), slog.String("generation", a.remote.generation)) }
	ctx := logging.WithLogger(context.Background(), a.logger)
	if c != nil { ctx = tracecontext.WithID(ctx, tracecontext.ForLogin(c.ticket)) }
	logging.Emit(ctx, event, attrs...)
}
func (a *agent) logTunnelEvent(event string, c *connection) {
	var attrs []slog.Attr
	if c.active { attrs = append(attrs, slog.String("username", c.username)) }
	if c.address.IsValid() { attrs = append(attrs, slog.String("group_name", c.groupName), slog.String("address", c.address.String())) }
	a.logEvent(event, c, attrs...)
}

func (a *agent) expire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.remote != nil && !a.now().Before(a.remote.leaseUntil) {
		a.logEvent("controller.lease_expired", nil)
		a.management.close()
		return
	}
	for _, c := range a.connections {
		if c.closing {
            if !c.closeBy.IsZero() && !a.now().Before(c.closeBy) {
                a.management.close()
                return
            }
			continue
		}
		if c.sessionValid(a.now()) {
			continue
		}
		// Keep the lease reserved until DISCONNECT confirms the old client is gone.
		// Kill both an abandoned pending handshake and an expired active session.
        a.closeClientLocked(c)
		if !a.readyLocked() { return }
		a.logEvent("vpn.session_expired", c)
	}
}

func (a *agent) events(ctx context.Context, m *management) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case e, ok := <-m.events:
			if !ok {
				return
			}
			a.handleEvent(e)
		case <-ticker.C:
			a.expire()
		case <-ctx.Done():
			return
		case <-m.done:
			return
		}
	}
}
