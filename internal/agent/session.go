// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
    "fmt"
    "time"
)

// Browser authentication belongs only to a new connection.
func (a *agent) requestBrowserLocked(c *connection, origin string) error {
    remaining := int(c.expires.Sub(a.now()).Seconds())
    if c.active || remaining <= 0 { return fmt.Errorf("browser authorization expired") }
    return a.commandLocked(fmt.Sprintf("client-pending-auth %d %d \"WEB_AUTH:external:%s/login/%s\" %d",
        c.cid, c.kid, origin, c.ticket, remaining))
}

func validSessionDecision(now, delivery, expires time.Time, unlimited bool, limit int) bool {
    if unlimited { return limit == 0 && expires.IsZero() }
    if expires.IsZero() || !now.Before(expires) || delivery.After(expires) { return false }
    return limit == 0 || !expires.After(now.Add(time.Duration(limit)*time.Second))
}

