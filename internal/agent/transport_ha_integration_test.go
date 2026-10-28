// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"supivpn/internal/profile"
)

// Real signed SAML, HTTP agent API and PostgreSQL shared by two nodes. The
// management peer is simulated; native tests separately exercise both daemons.
func TestProfileHATransportAdmission(t *testing.T) {
	for _, pair := range [][2]int{{0, 0}, {0, 1}, {1, 0}, {1, 1}} {
		t.Run(fmt.Sprintf("transport-%d-to-%d", pair[0], pair[1]), func(t *testing.T) {
			ctx := context.Background()
			groups := lifecycleGroups[:1]
			f := newGroupLifecycleFixture(t, groups, groups, groups)
			for _, a := range f.agents {
				a.config.TCPManagementSocket = "/run/supivpn/management-tcp.sock"
				a.pools = newPoolAllocator(a.config)
			}
			proof, err := profile.NewCredential()
			if err != nil {
				t.Fatal(err)
			}
			owner := sha256.Sum256([]byte(assertionFor(f.app).Issuer.Value + "\x00ha-profile-owner"))
			if err := f.stores[0].CreateProfile(ctx, proof, profile.Owner{SubjectHash: owner}); err != nil {
				t.Fatal(err)
			}
			firstCID := uint64(pair[0])*transportCIDBit + 7
			secondCID := uint64(pair[1])*transportCIDBit + 7
			first := f.beginWithProof(t, 0, firstCID, "ha-profile-owner", proof, groups...)
			f.callback(t, first, http.StatusAccepted)
			f.deliver(t, first, groups[0])
			firstIP := f.agents[0].connections[firstCID].address

			// A different node/transport cannot invent a free session slot.
			limited := f.beginWithProof(t, 1, secondCID, "ha-profile-owner", proof, groups...)
			f.callback(t, limited, http.StatusForbidden)
			f.deliver(t, limited, "")
			f.disconnect(t, limited)
			if !f.agents[0].connections[firstCID].active {
				t.Fatal("other node disturbed the live tunnel")
			}
			// Neither an absent UDP snapshot nor a TCP retry proves that node A
			// disconnected. Only its own confirmed disconnect releases the slot.
			f.disconnect(t, first)
			replacement := f.beginWithProof(t, 1, secondCID+1, "ha-profile-owner", proof, groups...)
			f.callback(t, replacement, http.StatusAccepted)
			f.deliver(t, replacement, groups[0])
			if f.agents[1].connections[secondCID+1].address == firstIP {
				t.Fatal("HA failover reused another node's IP")
			}
			f.disconnect(t, replacement)

			mismatch := f.beginWithProof(t, 0, firstCID+2, "another-valid-saml-owner", proof, groups...)
			f.callback(t, mismatch, http.StatusForbidden)
			f.deliver(t, mismatch, "")
			f.disconnect(t, mismatch)
			if _, err := f.stores[1].SetProfileState(ctx, proof.ID, "blocked", 1); err != nil {
				t.Fatal(err)
			}
			for node, a := range f.agents {
				for transport := range 2 {
					cid := uint64(transport)*transportCIDBit + 20
					a.handleEvent(clientEvent{kind: "CONNECT", cid: cid, kid: 2, sso: "webauth", proof: proof})
					if command := f.nextCommand(t, node); !strings.HasPrefix(command, fmt.Sprintf("client-deny %d 2 ", cid)) {
						t.Fatal("blocked profile reached browser authentication on another node or transport")
					}
				}
			}
		})
	}
}
