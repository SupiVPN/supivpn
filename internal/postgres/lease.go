// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"time"
	"github.com/jackc/pgx/v5"
)

// The agent stops its OpenVPN pair 40 seconds after request START; storage
// expires the node 60 seconds after renewal. Renewals never resurrect a lease.
// TTL detects failure. Slot reuse still requires confirmed fencing/disconnect.
func (s *Store) Heartbeat(ctx context.Context, a Agent) error {
	return s.HeartbeatStatus(ctx, a, false)
}

func (s *Store) HeartbeatStatus(ctx context.Context, a Agent, ready bool) error {
	if !validAgent(a) {
		return ErrGeneration
	}
	if s.component != "" {
        var ok bool
        err := s.pool.QueryRow(ctx, "SELECT supivpn.agent_heartbeat($1,$2,$3)", a.NodeID, a.Generation, ready).Scan(&ok)
        if err != nil { return publicError(err) }
        if !ok { return ErrGeneration }
        return nil
    }
	tx, err := s.begin(ctx)
	if err != nil {
		return publicError(err)
	}
	defer tx.Rollback(context.Background())
	tag, err := tx.Exec(ctx, `UPDATE supivpn.nodes
		SET lease_expires_at=clock_timestamp()+interval '60 seconds',
		    healthy_since=CASE WHEN $3 THEN COALESCE(healthy_since,clock_timestamp()) ELSE NULL END
		WHERE node_id=$1 AND generation=$2 AND lease_expires_at>clock_timestamp() AND fence_state='ready'`,
		a.NodeID, a.Generation, ready)
	if err != nil {
		return publicError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrGeneration
	}
	if err = tx.Commit(ctx); err != nil {
		return publicError(err)
	}
	// At most one bounded reconciliation per heartbeat. A fencing-service
	// outage must not invalidate this healthy node's successfully renewed lease.
	fenceCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = s.FenceExpired(fenceCtx)
	return nil
}

func liveNode(ctx context.Context, tx pgx.Tx, a Agent) error {
	var live bool
	err := tx.QueryRow(ctx, `SELECT lease_expires_at>clock_timestamp() AND fence_state='ready'
		FROM supivpn.nodes WHERE node_id=$1 AND generation=$2`, a.NodeID, a.Generation).Scan(&live)
	if err != nil {
		return err
	}
	if !live {
		return ErrGeneration
	}
	return nil
}
