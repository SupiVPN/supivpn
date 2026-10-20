// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"supivpn/internal/controller"
)

func TestLocalUserConnectionLimit(t *testing.T) {
	for _, limit := range []int{1, 2} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			now := time.Now()
			origin, _ := url.Parse("https://vpn.example.test")
			a := newAgent(groupConfig(), origin)
			a.config.SessionSeconds = 43200
			a.pools = newPoolAllocator(a.config)
			m, commands := fakeManagement(t)
			a.attach(m)
			decision := controller.Authorization{
				SubjectHash: sha256.Sum256([]byte("verified-issuer-and-user")),
				MaxConnections: limit, GroupName: coreGroup, NotBefore: now.Add(-time.Minute),
				NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(12*time.Hour),
			}
			admit := func(cid uint64) error {
				c := &connection{cid: cid, kid: 1, revision: cid, ticket: fmt.Sprint("ticket-", cid),
					expires: now.Add(time.Minute), requestID: fmt.Sprint("request-", cid),
					browserHash: sha256.Sum256([]byte("browser"))}
				a.connections[cid], a.tickets[c.ticket] = c, c
				return a.Complete(context.Background(), pendingSnapshot(c), decision)
			}
			for cid := uint64(1); cid <= uint64(limit); cid++ {
				if err := admit(cid); err != nil { t.Fatal(err) }
				<-commands
			}
			if len(a.pools.owners) != limit { t.Fatal("simultaneous devices shared an IP") }
			if !errors.Is(admit(3), controller.ErrConnectionLimit) { t.Fatal("extra connection accepted") }
			<-commands
			// Expiry/closing without DISCONNECT is not permission to reuse the slot.
			a.connections[1].closing = true
			if !errors.Is(admit(4), controller.ErrConnectionLimit) { t.Fatal("closing session released early") }
			<-commands
			a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 1})
			if err := admit(5); err != nil { t.Fatal("disconnect did not release user slot", err) }
			<-commands
			if len(a.pools.owners) != limit { t.Fatal("IP leaked after disconnect") }
		})
	}
}
