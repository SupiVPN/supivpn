// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
    "context"
    "time"
)

// Fencer observes power separately from requesting a stop. A successful Stop
// request is never evidence that the old VM can no longer forward packets.
// Implementations must honor context deadlines and refuse unmanaged mutations.
type Fencer interface {
    Managed(string) bool
    Power(context.Context, string) (string, error)
    Stop(context.Context, string) error
}

// RecoveryDriver enables Start, without changing fencing guards or budgets.
type RecoveryDriver interface {
    Fencer
    Start(context.Context, string) error
}

func (s *Store) FenceExpired(ctx context.Context) error {
    if s == nil || s.fencer == nil { return nil }
    ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
    defer cancel()
    return s.recoverExpired(ctx, s.fencer)
}
