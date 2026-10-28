// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"time"
)

// Readiness requires completed tunnel initialization and a responsive daemon.
// An open management socket alone would keep a frozen OpenVPN node in the NLB.
// Cache probes briefly because NLB sends checks from multiple AZs. No DB/API
// polling here: the independent heartbeat worker enforces the controller lease.
func (a *agent) loadBalancerReady(ctx context.Context) bool {
	a.mu.Lock()
	m := a.management
	ready := ctx.Err() == nil && a.readyLocked() && (a.remote == nil || a.now().Before(a.remote.leaseUntil))
	a.mu.Unlock()
	if !ready || !m.tunnelsInitialized() {
		return false
	}
	if time.Now().UnixNano() < m.healthUntil.Load() {
		return true
	}
	if !m.probeMu.TryLock() {
		return false
	}
	defer m.probeMu.Unlock()
	if err := m.command("pid"); err != nil {
		m.close()
		return false
	}
	if !m.tunnelsInitialized() || !a.Ready(ctx) {
		return false
	}
	m.healthUntil.Store(time.Now().Add(5 * time.Second).UnixNano())
	return true
}
