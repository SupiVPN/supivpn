// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Called only after verified SAML, active profile ownership and an exhausted
// user limit, while holding the same per-subject admission lock. The immutable
// refusal is the cluster-wide retry budget, including after ACK, cancellation
// and node rotation. Never change the old session, its lease or its slot.
func transportRetryAllowed(ctx context.Context, tx pgx.Tx, cid int64, profileID string, subject [32]byte) (bool, error) {
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
        SELECT 1 FROM supivpn.logins l
        JOIN supivpn.nodes n ON n.node_id=l.node_id AND n.generation=l.generation
        JOIN supivpn.profile_bindings b ON b.ticket_hash=l.ticket_hash
        WHERE b.profile_id=$1 AND l.subject_hash=$2 AND l.denial_reason=''
          AND l.state IN ('decided','acknowledged')
          AND (l.ack_result IS NULL OR l.ack_result='applied')
          AND n.fence_state<>'stopped'
          AND l.cid/4611686018427387904 <> $3::bigint/4611686018427387904
    ) AND NOT EXISTS (
        SELECT 1 FROM supivpn.logins previous
        JOIN supivpn.profile_bindings b ON b.ticket_hash=previous.ticket_hash
        WHERE b.profile_id=$1 AND previous.subject_hash=$2
          AND previous.denial_reason='connection_limit_retry'
          AND previous.expires_at>clock_timestamp()-interval '5 minutes'
    )`, profileID, subject[:], cid).Scan(&allowed)
	return allowed, err
}
