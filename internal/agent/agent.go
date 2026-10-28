// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"supivpn/internal/logging"
	"supivpn/internal/profile"
	"supivpn/internal/tracecontext"
	"sync"
	"time"
)

const maxConnections = 16

type connection struct {
	registrationMayExist       bool
	proof                      profile.Credential
	proofDigest                [32]byte
	username                   string
	sessionUnlimited           bool
	closeBy                    time.Time
	subjectHash                [32]byte
	cid, kid                   uint64
	revision                   uint64
	ticket                     string
	expires                    time.Time
	active                     bool
	requestID                  string
	browserHash                [32]byte
	closing                    bool
	groupName                  string
	address                    netip.Addr
	peer                       netip.AddrPort
	client                     clientInfo
	requestedAt, establishedAt time.Time
	disconnectReason           string
}

type agent struct {
	logger       *logging.Logger
	mu           sync.Mutex
	config       config
	origin       *url.URL
	management   *management
	connections  map[uint64]*connection
	tickets      map[string]*connection
	now          func() time.Time
	pools        *poolAllocator
	nextRevision uint64
	reconcileDue time.Time
	remote       *remoteAgent
}

// Unlimited is valid only for an explicitly authorized active session.
func (c *connection) sessionValid(now time.Time) bool {
	if c.sessionUnlimited {
		return c.active && c.expires.IsZero()
	}
	return !c.expires.IsZero() && now.Before(c.expires)
}

func newAgent(c config, origin *url.URL) *agent {
	return &agent{config: c, origin: origin, connections: make(map[uint64]*connection),
		tickets: make(map[string]*connection), now: time.Now}
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

// Every authorization path rechecks the same live pending connection under mu.
// Pointer identity fences replies to a CID that OpenVPN has since reused.
func (a *agent) pendingConnectionLocked(c *connection) bool {
	return c != nil && !c.active && !c.closing && a.readyLocked() &&
		a.connections[c.cid] == c && a.now().Before(c.expires)
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

func (a *agent) denyConnectionLocked(c *connection, reason string) {
	c.closing = true
	c.disconnectReason = reason
	delete(a.tickets, c.ticket)
	a.denyLocked(clientEvent{cid: c.cid, kid: c.kid})
}

// A successful kill command is not proof of disconnection. Keep the IP/slot
// until DISCONNECT or a complete status snapshot confirms absence.
func (a *agent) closeClientLocked(c *connection, reason string) {
	if !c.closeBy.IsZero() {
		return
	}
	if c.disconnectReason == "" {
		c.disconnectReason = reason
	}
	c.closing = true
	c.closeBy = a.now().Add(30 * time.Second)
	delete(a.tickets, c.ticket)
	if err := a.commandLocked(fmt.Sprintf("client-kill %d", c.cid)); err != nil {
		// The CID may have disappeared without DISCONNECT. A rejection alone
		// is not proof; retain the slot until the ordered snapshot is handled.
		if errors.Is(err, errManagementRejected) {
			_ = a.management.requestStatus() // Closes management on uncertainty.
		} else {
			a.management.close()
		}
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
		if a.config.ProfileBinding == "required" && (a.remote == nil || !e.proof.Valid()) {
			a.denyLocked(e)
			return
		}
		if err != nil {
			a.denyLocked(e)
			return
		}
		a.nextRevision++
		c := &connection{cid: e.cid, kid: e.kid, revision: a.nextRevision, ticket: token,
			expires: a.now().Add(time.Duration(a.config.PendingSeconds) * time.Second), peer: e.peer,
			client: e.client, requestedAt: a.now()}
		if a.config.ProfileBinding == "required" {
			c.proof = e.proof
			c.proofDigest, _ = e.proof.Digest()
		}
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
		if c != nil && a.config.ProfileBinding == "required" {
			digest, err := e.proof.Digest()
			if err != nil || subtle.ConstantTimeCompare(digest[:], c.proofDigest[:]) != 1 {
				a.denyLocked(e)
				a.closeClientLocked(c, "reauthentication_refused")
				return
			}
		}
		if c != nil && c.active && (c.closing || !c.sessionValid(a.now())) {
			// Normal expiry requests RESTART, not AUTH_FAILED: Connect must be
			// allowed to reconnect and perform a fresh browser authentication.
			a.closeClientLocked(c, "session_expired")
			return
		}
		if c == nil || c.closing || !c.active || !c.sessionValid(a.now()) {
			a.denyLocked(e)
			// client-deny alone may leave the old TLS key alive until it expires.
			if c != nil {
				a.closeClientLocked(c, "reauthentication_refused")
			} else if a.commandLocked(fmt.Sprintf("client-kill %d", e.cid)) != nil {
				a.management.close()
			}
			return
		}
		if a.commandLocked(fmt.Sprintf("client-auth-nt %d %d", e.cid, e.kid)) != nil {
			a.management.close()
		} else {
			if e.peer.IsValid() {
				c.peer = e.peer
			}
			a.logEvent("vpn.tls_reauthenticated", c, slog.Uint64("kid", e.kid))
		}
	case "DISCONNECT":
		if c := a.connections[e.cid]; c != nil {
			if e.peer.IsValid() {
				c.peer = e.peer
			}
			a.logDisconnect(c, "management_event", e.metrics)
			a.removeLocked(c)
		} else {
			a.logEvent("vpn.disconnected", nil, slog.Uint64("cid", e.cid), slog.String("disconnect_source", "management_event"))
		}
	case "ESTABLISHED":
		if c := a.connections[e.cid]; c != nil && c.active && !c.closing {
			if c.establishedAt.IsZero() {
				c.establishedAt = a.now()
			}
			if e.peer.IsValid() {
				c.peer = e.peer
			}
			a.logTunnelEvent("vpn.tunnel_established", c)
		} else {
			a.management.close()
		}
	case "STATUS":
		for cid, c := range a.connections {
			// A snapshot proves absence only in the daemon that produced it.
			if e.scoped && int(cid/transportCIDBit) != e.transport {
				continue
			}
			if _, exists := e.clients[cid]; !exists {
				// The daemon no longer owns this CID, even if it never emitted
				// DISCONNECT for the abandoned handshake. Use normal cancellation.
				a.logDisconnect(c, "status_snapshot", disconnectMetrics{})
				a.removeLocked(c)
			}
		}
	}
}

func (a *agent) logEvent(event string, c *connection, attrs ...slog.Attr) {
	if c != nil {
		attrs = append(attrs, slog.Uint64("cid", c.cid), slog.Uint64("kid", c.kid))
		if a.config.TCPManagementSocket != "" {
			transport := "udp"
			if c.cid >= transportCIDBit {
				transport = "tcp"
			}
			attrs = append(attrs, slog.String("transport", transport))
		}
	}
	if a.remote != nil {
		attrs = append(attrs, slog.String("node_id", a.remote.node), slog.String("generation", a.remote.generation))
	}
	ctx := logging.WithLogger(context.Background(), a.logger)
	if c != nil {
		ctx = tracecontext.WithID(ctx, tracecontext.ForLogin(c.ticket))
	}
	logging.Emit(ctx, event, attrs...)
}
func (a *agent) logTunnelEvent(event string, c *connection, attrs ...slog.Attr) {
	if event == "vpn.tunnel_established" && c.active {
		if c.client.version != "" {
			attrs = append(attrs, slog.String("client_version", c.client.version))
		}
		if c.client.platform != "" {
			attrs = append(attrs, slog.String("client_platform", c.client.platform))
		}
		if c.client.deviceID != "" {
			attrs = append(attrs, slog.String("client_device_id", c.client.deviceID), slog.String("client_device_id_source", c.client.deviceIDSource))
		}
		if !c.requestedAt.IsZero() && !c.establishedAt.IsZero() && !c.establishedAt.Before(c.requestedAt) {
			attrs = append(attrs, slog.Int64("establishment_ms", c.establishedAt.Sub(c.requestedAt).Milliseconds()))
		}
	}
	if c.active {
		if c.proof.ID != "" {
			attrs = append(attrs, slog.String("profile_id", c.proof.ID))
		}
		attrs = append(attrs, slog.String("username", c.username))
	}
	if c.active && c.peer.IsValid() {
		attrs = append(attrs, slog.String("peer_ip", c.peer.Addr().String()), slog.Uint64("peer_port", uint64(c.peer.Port())))
	}
	if c.address.IsValid() {
		attrs = append(attrs, slog.String("group_name", c.groupName), slog.String("address", c.address.String()))
	}
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
		// Keep the lease reserved until the daemon confirms the old client is gone.
		// Kill both an abandoned pending handshake and an expired active session.
		reason := "pending_auth_expired"
		if c.active {
			reason = "session_expired"
		}
		a.closeClientLocked(c, reason)
		if !a.readyLocked() {
			return
		}
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
			if !a.reconcile() {
				a.expire()
			}
		case <-ctx.Done():
			return
		case <-m.done:
			return
		}
	}
}

// Periodically reconcile daemon-owned CIDs. Status is delivered through the
// event queue, so all preceding connection events are handled before cleanup.
func (a *agent) reconcile() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.readyLocked() || len(a.connections) == 0 || a.now().Before(a.reconcileDue) {
		return false
	}
	a.reconcileDue = a.now().Add(5 * time.Second)
	if err := a.management.requestStatus(); err != nil {
		a.management.close()
	}
	return true
}
