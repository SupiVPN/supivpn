// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"

	"supivpn/internal/controller"
)

var _ controller.Backend = (*agent)(nil)

// This in-process adapter preserves the agent's single lock across connection
// events, expiry, lease allocation and management ACK. It is not shared storage.
func (a *agent) Ready(ctx context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ctx.Err() == nil && a.readyLocked()
}

func (a *agent) Start(ctx context.Context, ticket, requestID string, browserHash [32]byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil {
		return controller.ErrUnavailable
	}
	c := a.tickets[ticket]
	if !a.pendingConnectionLocked(c) {
		return controller.ErrLoginExpired
	}
	if c.requestID != "" {
		return controller.ErrLoginStarted
	}
	if requestID == "" {
		return controller.ErrUnavailable
	}
	c.requestID, c.browserHash = requestID, browserHash
	return nil
}

func (a *agent) pendingLocked(ticket string, hash [32]byte) (*connection, error) {
	c := a.tickets[ticket]
	if !a.pendingConnectionLocked(c) || c.requestID == "" ||
		subtle.ConstantTimeCompare(hash[:], c.browserHash[:]) != 1 {
		return nil, controller.ErrLoginExpired
	}
	return c, nil
}

func pendingSnapshot(c *connection) controller.Pending {
	return controller.Pending{Ticket: c.ticket, RequestID: c.requestID,
		BrowserHash: c.browserHash, ExpiresAt: c.expires, Revision: c.revision}
}

func (a *agent) Lookup(ctx context.Context, ticket string, hash [32]byte) (controller.Pending, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil {
		return controller.Pending{}, controller.ErrUnavailable
	}
	c, err := a.pendingLocked(ticket, hash)
	if err != nil {
		return controller.Pending{}, err
	}
	return pendingSnapshot(c), nil
}

func (a *agent) Complete(ctx context.Context, pending controller.Pending, decision controller.Authorization) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil {
		return controller.ErrUnavailable
	}
	c, err := a.pendingLocked(pending.Ticket, pending.BrowserHash)
	if err != nil || pendingSnapshot(c) != pending || !decision.ValidAt(a.now()) {
		return controller.ErrLoginExpired
	}
	if decision.SubjectHash == [32]byte{} || decision.MaxConnections < 1 || decision.MaxConnections > 16 || !controller.ValidLogUsername(decision.Username) {
		return controller.ErrUnavailable
	}
	policy := controller.Config{Policy: controllerPolicy(a.config), SessionSeconds: a.config.SessionSeconds}
	if !validSessionDecision(a.now(), decision.NotOnOrAfter, decision.SessionExpiresAt, decision.SessionUnlimited, policy.SessionLimit(decision.GroupName)) {
		return controller.ErrLoginExpired
	}
	if decision.DenialReason == "" {
		count := 0
		for _, other := range a.connections {
			if other != c && other.active && other.subjectHash == decision.SubjectHash {
				count++
			}
		}
		if count >= decision.MaxConnections {
			a.denyConnectionLocked(c, "connection_limit")
			a.logEvent("vpn.authorization_denied", c, slog.String("reason", "connection_limit"))
			return controller.ErrConnectionLimit
		}
	}
	c.subjectHash = decision.SubjectHash
	return a.applyAuthorizationLocked(c, decision)
}

// Both transports commit a decision under the same lock as disconnect/expiry.
func (a *agent) applyAuthorizationLocked(c *connection, decision controller.Authorization) error {
	var err error
	reason := decision.DenialReason
	if a.config.SAMLGroupsAttribute == "" && decision.GroupName != "" {
		return controller.ErrUnavailable
	}
	if a.config.SAMLGroupsAttribute != "" && reason == "" {
		if a.pools == nil {
			reason = "invalid_groups_claim"
		} else {
			c.address, err = a.pools.acquire(c.cid, decision.GroupName)
			switch {
			case err == nil:
				c.groupName = decision.GroupName
			case errors.Is(err, errPoolFull):
				reason = "pool_full"
			default:
				reason = "no_vpn_group"
			}
		}
	}
	if reason != "" {
		a.denyConnectionLocked(c, reason)
		a.logEvent("vpn.authorization_denied", c, slog.String("reason", reason))
		return controller.ErrGroupDenied
	}
	delete(a.tickets, c.ticket) // One-time redemption, before issuing the command.
	c.active = true
	c.username = decision.Username
	c.expires = decision.SessionExpiresAt
	c.sessionUnlimited = decision.SessionUnlimited
	if a.pools != nil {
		err = a.management.authorizeIPv4(c.cid, c.kid, c.address, a.pools.netmask())
	} else {
		err = a.commandLocked(fmt.Sprintf("client-auth-nt %d %d", c.cid, c.kid))
	}
	if err != nil {
		a.management.close()
		return controller.ErrUnavailable
	}
	a.logEvent("vpn.authorization_applied", c)
	return nil
}
