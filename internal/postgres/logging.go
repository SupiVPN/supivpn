// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"log/slog"

	"supivpn/internal/logging"
	"supivpn/internal/tracecontext"
)

// Call only after a successful authorized operation/commit. Never log a bearer
// ticket, lookup hash, decision ID, raw error or uncommitted authorization.
func logConnection(ctx context.Context, event string, hash []byte, a Agent, c Connection, attrs ...slog.Attr) {
	ctx = tracecontext.WithID(ctx, tracecontext.ForLoginHash(hash))
	attrs = append(attrs, slog.String("node_id", a.NodeID), slog.String("generation", a.Generation),
		slog.Int64("cid", c.CID), slog.Int64("kid", c.KID))
	logging.Emit(ctx, event, attrs...)
}
