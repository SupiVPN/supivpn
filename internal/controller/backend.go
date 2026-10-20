// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrLoginExpired    = errors.New("pending login unavailable")
	ErrLoginStarted    = errors.New("login already started")
	ErrUnavailable     = errors.New("authorization backend unavailable")
	ErrGroupDenied     = errors.New("VPN group authorization refused")
	ErrConnectionLimit = errors.New("VPN connection limit reached")
	ErrDecisionPending = errors.New("authorization saved; awaiting agent acknowledgement")
)

// Pending is a value snapshot, never a pointer into mutable agent/store state.
// Revision distinguishes a replaced connection even if its local CID is reused.
type Pending struct {
	Ticket      string
	RequestID   string
	BrowserHash [32]byte
	ExpiresAt   time.Time
	Revision    uint64
}

// Authorization contains only the decision derived from verified SAML.
// No assertion, cookie, IP allocation, or OpenVPN command crosses this boundary.
type Authorization struct {
	// Username is the verified NameID for audit logs only; SubjectHash remains the identity key.
	Username           string
	SubjectHash        [32]byte
	MaxConnections     int
	AssertionHash      [32]byte
	AssertionExpiresAt time.Time
	GroupName          string
	DenialReason       string
	NotBefore          time.Time
	NotOnOrAfter       time.Time
	SessionExpiresAt   time.Time
    SessionUnlimited   bool
}

// ValidLogUsername bounds audit data without restricting ordinary Unicode names.
// Empty means unavailable (e.g. an older decision). Log with %q, never raw %s.
func ValidLogUsername(s string) bool {
	return len(s) <= 1024 && utf8.ValidString(s) && !strings.ContainsRune(s, '\x00')
}

func (a Authorization) ValidAt(now time.Time) bool {
	return !now.Before(a.NotBefore) && now.Before(a.NotOnOrAfter) &&
		((a.SessionUnlimited && a.SessionExpiresAt.IsZero()) || (!a.SessionUnlimited && !a.SessionExpiresAt.IsZero() && now.Before(a.SessionExpiresAt)))
}

// Backend owns pending state and its atomic transition to an agent result.
// Start must bind an unstarted, live ticket exactly once. Lookup validates the
// browser hash and returns a snapshot. Complete must recheck that exact snapshot,
// liveness, browser binding, expiry and Authorization.ValidAt under the same
// serialization/transaction that consumes it. Concurrent/replayed completions
// cannot authorize twice. A stale or disconnected request returns ErrLoginExpired.
//
// The local adapter returns nil after OpenVPN ACK. A shared store instead returns
// ErrDecisionPending after committing an immutable decision to the agent mailbox.
// Stored liveness includes cancellation and node generation; the receiving agent
// must also recheck its actual connection before applying a remote decision.
// Cancellation observed before commit rejects the request; cancellation after
// commit cannot roll back a recorded decision. A retry must not create a new one.
type Backend interface {
	Ready(context.Context) bool
	Start(context.Context, string, string, [32]byte) error
	Lookup(context.Context, string, [32]byte) (Pending, error)
	Complete(context.Context, Pending, Authorization) error
}
