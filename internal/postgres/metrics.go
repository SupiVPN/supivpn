// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"time"
)

type MetricsSnapshot struct {
	Nodes         [4]int64 // Ready lease, expired lease, stopping, stopped.
	Logins        [5]int64 // Pending, started, decided, acknowledged, cancelled retained rows.
	ReservedSlots int64
}

// Metrics reads aggregates only, with the existing public component's SELECT
// grants. Slots deliberately follow admission accounting: expiry alone is not
// proof that a tunnel disappeared. No identity or node identifier is returned.
func (s *Store) Metrics(ctx context.Context) (MetricsSnapshot, error) {
	var snapshot MetricsSnapshot
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	err := s.pool.QueryRow(ctx, `WITH node_counts AS (
 SELECT count(*) FILTER (WHERE fence_state='ready' AND lease_expires_at>statement_timestamp()) AS ready,
 count(*) FILTER (WHERE fence_state='ready' AND lease_expires_at<=statement_timestamp()) AS expired,
 count(*) FILTER (WHERE fence_state='stopping') AS stopping,
 count(*) FILTER (WHERE fence_state='stopped') AS stopped FROM supivpn.nodes
 ), login_counts AS (
 SELECT count(*) FILTER (WHERE state='pending') AS pending,
 count(*) FILTER (WHERE state='started') AS started,
 count(*) FILTER (WHERE state='decided') AS decided,
 count(*) FILTER (WHERE state='acknowledged') AS acknowledged,
 count(*) FILTER (WHERE state='cancelled') AS cancelled FROM supivpn.logins
 ), slots AS (
 SELECT count(*) AS reserved FROM supivpn.logins l JOIN supivpn.nodes n
 ON n.node_id=l.node_id AND n.generation=l.generation
 WHERE l.denial_reason='' AND l.state IN ('decided','acknowledged')
 AND (l.ack_result IS NULL OR l.ack_result='applied') AND n.fence_state<>'stopped'
 ) SELECT ready,expired,stopping,stopped,pending,started,decided,acknowledged,cancelled,reserved
 FROM node_counts CROSS JOIN login_counts CROSS JOIN slots`).Scan(
		&snapshot.Nodes[0], &snapshot.Nodes[1], &snapshot.Nodes[2], &snapshot.Nodes[3],
		&snapshot.Logins[0], &snapshot.Logins[1], &snapshot.Logins[2], &snapshot.Logins[3], &snapshot.Logins[4], &snapshot.ReservedSlots)
	return snapshot, publicError(err)
}
