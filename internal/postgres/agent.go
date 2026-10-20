// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"supivpn/internal/controller"
	"github.com/jackc/pgx/v5"
)

func (s *Store) connectionHash(ctx context.Context, a Agent, c Connection) ([]byte, error) {
	if s == nil || s.pool == nil {
		return nil, controller.ErrUnavailable
	}
	if !validAgent(a) || c.CID < 0 || c.KID < 0 {
		return nil, controller.ErrLoginExpired
	}
	var hash []byte
	err := s.pool.QueryRow(ctx, `SELECT ticket_hash FROM supivpn.logins
        WHERE node_id=$1 AND generation=$2 AND cid=$3 AND kid=$4`,
		a.NodeID, a.Generation, c.CID, c.KID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, controller.ErrLoginExpired
	}
	return hash, publicError(err)
}

// Fetch repeats the same result until ACK, without consuming or extending it.
func (s *Store) Fetch(ctx context.Context, a Agent, c Connection) (Decision, error) {
	var result Decision
	hash, err := s.connectionHash(ctx, a, c)
	if err != nil {
		return result, err
	}
	return s.fetchRecord(ctx, a, c, hash)
}

func (s *Store) fetchRecord(ctx context.Context, a Agent, c Connection, hash []byte) (Decision, error) {
    var result Decision
	err := s.withLogin(ctx, hash, &a, func(tx pgx.Tx, r record, now time.Time) error {
		if r.conn != c { return controller.ErrLoginExpired }
		if err := liveNode(ctx, tx, a); err != nil {
			return err
		}
		if !r.deliverable(now) {
			return ErrNoDecision
		}
		expiry := r.expires
		if r.notAfter.Before(expiry) {
			expiry = r.notAfter
		}
		if !r.sessionUnlimited && r.sessionExpires.Before(expiry) {
			expiry = r.sessionExpires
		}
		result = Decision{ID: r.decisionID, SessionUnlimited: r.sessionUnlimited, Agent: r.agent, Connection: r.conn,
			Username: r.username,
			GroupName: r.group, DenialReason: r.denial, ExpiresAt: expiry, SessionExpiresAt: r.sessionExpires}
        if len(r.subjectHash) == len(result.SubjectHash) {
            copy(result.SubjectHash[:], r.subjectHash)
        }
		return nil
	})
	if err == nil {
		logConnection(ctx, "agent.decision_delivered", hash, a, c)
	}
	return result, err
}

// Acknowledge records the real management result. Identical ACK retries succeed,
// including a lost response after commit. Conflicting outcomes never overwrite it.
func (s *Store) Acknowledge(ctx context.Context, a Agent, id string, outcome Outcome) error {
	if s == nil || s.pool == nil {
		return controller.ErrUnavailable
	}
	if !validAgent(a) || !validName(id) ||
		outcome != Applied && outcome != Denied && outcome != Failed {
		return ErrConflict
	}
	var hash []byte
	err := s.pool.QueryRow(ctx, `SELECT ticket_hash FROM supivpn.logins
        WHERE decision_id=$1 AND node_id=$2 AND generation=$3`, id, a.NodeID, a.Generation).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return controller.ErrLoginExpired
	}
	if err != nil {
		return publicError(err)
	}
	var connection Connection
	err = s.withLogin(ctx, hash, &a, func(tx pgx.Tx, r record, now time.Time) error {
		connection = r.conn
		if r.state == "acknowledged" {
			if r.ack == string(outcome) {
				return nil
			}
			return ErrConflict
		}
		if !r.deliverable(now) {
			return controller.ErrLoginExpired
		}
		if r.denial != "" && outcome == Applied {
			return ErrConflict
		}
		tag, err := tx.Exec(ctx, `UPDATE supivpn.logins SET state='acknowledged',ack_result=$2
            WHERE ticket_hash=$1 AND expires_at>clock_timestamp()
                AND not_after>clock_timestamp() AND (session_unlimited OR session_expires_at>clock_timestamp())`, hash, string(outcome))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return controller.ErrLoginExpired
		}
		return nil
	})
	if err == nil {
		logConnection(ctx, "agent.decision_acknowledged", hash, a, connection, slog.String("outcome", string(outcome)))
	}
	return err
}

// Cancel is called when the bound OpenVPN connection has closed. Any late SAML
// completion or delivery then fails closed. Cancellation itself is idempotent.
func (s *Store) Cancel(ctx context.Context, a Agent, c Connection) error {
	hash, err := s.connectionHash(ctx, a, c)
	if err != nil {
		return err
	}
	err = s.withLogin(ctx, hash, &a, func(tx pgx.Tx, r record, _ time.Time) error {
		if r.state == "cancelled" {
			return nil
		}
		_, err := tx.Exec(ctx, "UPDATE supivpn.logins SET state='cancelled',ack_result=NULL WHERE ticket_hash=$1", hash)
		return err
	})
	if err == nil {
		logConnection(ctx, "agent.connection_cancelled", hash, a, c)
	}
	return err
}

// Prune deletes a bounded batch. Expiry enforcement never depends on cleanup.
// Keep login tombstones for a day; assertion replay entries have their own TTL.
func (s *Store) Prune(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrConflict
	}
    if s.component != "" { return s.pruneIsolated(ctx, limit) }
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, publicError(err)
	}
	defer tx.Rollback(context.Background())
	logins, err := tx.Exec(ctx, `WITH expired AS (
        SELECT ticket_hash FROM supivpn.logins
        WHERE expires_at<clock_timestamp()-interval '24 hours'
          AND NOT (denial_reason='' AND state IN ('decided','acknowledged')
            AND (ack_result IS NULL OR ack_result='applied')
            AND EXISTS (SELECT 1 FROM supivpn.nodes n WHERE n.node_id=logins.node_id
              AND n.generation=logins.generation AND n.fence_state<>'stopped'))
        ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.logins USING expired WHERE logins.ticket_hash=expired.ticket_hash`, limit)
	if err != nil {
		return 0, publicError(err)
	}
	assertions, err := tx.Exec(ctx, `WITH expired AS (
        SELECT assertion_hash FROM supivpn.assertions
        WHERE expires_at<=clock_timestamp()
        ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.assertions USING expired WHERE assertions.assertion_hash=expired.assertion_hash`, limit)
	if err != nil {
		return 0, publicError(err)
	}
    profiles, err := tx.Exec(ctx, `WITH expired AS (
        SELECT ticket_hash FROM supivpn.profile_logins
        WHERE expires_at<=clock_timestamp()
        ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.profile_logins USING expired WHERE profile_logins.ticket_hash=expired.ticket_hash`, limit)
    if err != nil {
        return 0, publicError(err)
    }
    _, err = tx.Exec(ctx, `WITH expired AS (
        SELECT node_id,attempted_at FROM supivpn.node_recovery_starts
        WHERE attempted_at<clock_timestamp()-interval '24 hours'
        ORDER BY attempted_at LIMIT $1 FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.node_recovery_starts s USING expired e
      WHERE s.node_id=e.node_id AND s.attempted_at=e.attempted_at`, limit)
    if err != nil { return 0, publicError(err) }
    _, err = tx.Exec(ctx, `WITH expired AS (
        SELECT node_id,attempted_at FROM supivpn.node_recovery_stops
        WHERE attempted_at<clock_timestamp()-interval '24 hours'
        ORDER BY attempted_at LIMIT $1 FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.node_recovery_stops s USING expired e
      WHERE s.node_id=e.node_id AND s.attempted_at=e.attempted_at`, limit)
    if err != nil { return 0, publicError(err) }
    if err = tx.Commit(ctx); err != nil {
        return 0, publicError(err)
    }
	return logins.RowsAffected() + assertions.RowsAffected() + profiles.RowsAffected(), nil
}
