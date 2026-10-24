// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"supivpn/internal/controller"
)

// ProfileBackend implements the same SAML contract with independent,
// browser-initiated pending rows. It cannot create a VPN agent decision.
type ProfileBackend struct {
	*Store
	lifetime time.Duration
}

func NewProfileBackend(store *Store, lifetime time.Duration) *ProfileBackend {
	return &ProfileBackend{Store: store, lifetime: lifetime}
}

func validProfileTicket(ticket string) bool {
	return ((len(ticket) == 51 && strings.HasPrefix(ticket, "profile_")) || (len(ticket) == 55 && strings.HasPrefix(ticket, "profile_url_"))) && validTicket(ticket)
}

func (s *ProfileBackend) Start(ctx context.Context, ticket, requestID string, hash [32]byte) error {
	if !validProfileTicket(ticket) || requestID == "" || len(requestID) > 256 ||
		hash == [32]byte{} || s.lifetime < 30*time.Second || s.lifetime > 180*time.Second {
		return controller.ErrLoginExpired
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return publicError(err)
	}
	defer tx.Rollback(context.Background())
	// Serialize only admission. Bound anonymous pending state across Lambda
	// replicas; expiry is checked independently of scheduled cleanup.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7273182102)"); err != nil {
		return publicError(err)
	}
	// Reclaim expired entries during admission as well as scheduled cleanup.
	// Counting all remaining rows bounds storage even under continuous traffic.
	if _, err = tx.Exec(ctx, "DELETE FROM supivpn.profile_logins WHERE expires_at<=clock_timestamp()"); err != nil {
		return publicError(err)
	}
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM supivpn.profile_logins").Scan(&count); err != nil {
		return publicError(err)
	}
	if count >= 256 {
		return controller.ErrUnavailable
	}
	tag, err := tx.Exec(ctx, `
        INSERT INTO supivpn.profile_logins(ticket_hash,request_id,browser_hash,expires_at)
        VALUES ($1,$2,$3,clock_timestamp()+$4*interval '1 microsecond')
        ON CONFLICT DO NOTHING`, ticketHash(ticket), requestID, hash[:], s.lifetime.Microseconds())
	if err != nil {
		return publicError(err)
	}
	if tag.RowsAffected() != 1 {
		return controller.ErrLoginStarted
	}
	return publicError(tx.Commit(ctx))
}

func profileSnapshot(ctx context.Context, tx pgx.Tx, ticket string) (controller.Pending, bool, error) {
	p := controller.Pending{Ticket: ticket, Revision: 1}
	var hash []byte
	var consumed bool
	err := tx.QueryRow(ctx, `SELECT request_id,browser_hash,expires_at,consumed
        FROM supivpn.profile_logins WHERE ticket_hash=$1 FOR UPDATE`, ticketHash(ticket)).
		Scan(&p.RequestID, &hash, &p.ExpiresAt, &consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, false, controller.ErrLoginExpired
	}
	if err != nil || len(hash) != 32 {
		return p, false, controller.ErrUnavailable
	}
	copy(p.BrowserHash[:], hash)
	return p, consumed, nil
}

func (s *ProfileBackend) Lookup(ctx context.Context, ticket string, hash [32]byte) (controller.Pending, error) {
	if !validProfileTicket(ticket) {
		return controller.Pending{}, controller.ErrLoginExpired
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return controller.Pending{}, publicError(err)
	}
	defer tx.Rollback(context.Background())
	p, consumed, err := profileSnapshot(ctx, tx, ticket)
	if err != nil {
		return controller.Pending{}, publicError(err)
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return controller.Pending{}, publicError(err)
	}
	if consumed || !now.Before(p.ExpiresAt) || subtle.ConstantTimeCompare(hash[:], p.BrowserHash[:]) != 1 {
		return controller.Pending{}, controller.ErrLoginExpired
	}
	if err = tx.Commit(ctx); err != nil {
		return controller.Pending{}, publicError(err)
	}
	return p, nil
}

func (s *ProfileBackend) Complete(ctx context.Context, p controller.Pending, d controller.Authorization) error {
	if !validProfileTicket(p.Ticket) || p.Revision != 1 {
		return controller.ErrLoginExpired
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return publicError(err)
	}
	defer tx.Rollback(context.Background())
	current, consumed, err := profileSnapshot(ctx, tx, p.Ticket)
	if err != nil {
		return publicError(err)
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return publicError(err)
	}
	d = normalizeDecision(d)
	if consumed || !now.Before(current.ExpiresAt) || !validDecision(d, now) ||
		current.RequestID != p.RequestID || !current.ExpiresAt.Equal(p.ExpiresAt) ||
		subtle.ConstantTimeCompare(current.BrowserHash[:], p.BrowserHash[:]) != 1 {
		return controller.ErrLoginExpired
	}
	// The shared replay table covers both profile downloads and VPN logins.
	if err := consumeAssertion(ctx, tx, d); err != nil {
		return publicError(err)
	}
	tag, err := tx.Exec(ctx, `UPDATE supivpn.profile_logins SET consumed=true
        WHERE ticket_hash=$1 AND NOT consumed AND expires_at>clock_timestamp()
            AND clock_timestamp()>=$2 AND clock_timestamp()<$3
            AND ($5 OR clock_timestamp()<$4)`,
		ticketHash(p.Ticket), d.NotBefore, d.NotOnOrAfter, d.SessionExpiresAt, d.SessionUnlimited)
	if err != nil {
		return publicError(err)
	}
	if tag.RowsAffected() != 1 {
		return controller.ErrLoginExpired
	}
	if err = tx.Commit(ctx); err != nil {
		return publicError(err)
	}
	if d.DenialReason != "" {
		return controller.ErrGroupDenied
	}
	return nil
}
