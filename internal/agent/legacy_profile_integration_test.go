// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/logging"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
)

func TestLegacyRemoteSAMLAdmission(t *testing.T) {
	for _, scenario := range []string{"allowed", "denied"} {
		t.Run(scenario, func(t *testing.T) {
			allowed := scenario == "allowed"
			f := groupLifecycleWithLegacy(t, lifecycleGroups[:1], lifecycleGroups[:1], lifecycleGroups[:1], true)
			member, status, group := unrelatedGroup, http.StatusForbidden, ""
			if allowed {
				member, status, group = lifecycleGroups[0], http.StatusAccepted, lifecycleGroups[0]
			}
			login := f.beginWithProof(t, 0, 72, "legacy-user", profile.Credential{}, member)
			f.callback(t, login, status)
			f.deliver(t, login, group)
			if allowed {
				f.agents[0].handleEvent(clientEvent{kind: "REAUTH", cid: 72, kid: 3})
				if command := f.nextCommand(t, 0); command != "client-auth-nt 72 3" {
					t.Fatal("legacy rekey refused")
				}
			}
		})
	}
}

// The same lifecycle runs with the combined VM role and the separate Lambda
// public/agent roles. It never changes grants or uses a working database.
func testLegacyMigrationLifecycle(t *testing.T, public, agents *postgres.Store) {
	var audit bytes.Buffer
	ctx := logging.WithLogger(context.Background(), logging.New(&audit, "runtime"))
	for _, scenario := range []string{"allowed", "revoke-complete", "revoke-fetch", "revoke-ack", "no-group", "mixed-limit"} {
		t.Run(scenario, func(t *testing.T) {
			node := "legacy-" + rand.Text()
			pub, err := public.WithLegacyProfiles([]string{node})
			if err != nil {
				t.Fatal(err)
			}
			ag, err := agents.WithLegacyProfiles([]string{node})
			if err != nil {
				t.Fatal(err)
			}
			a := postgres.Agent{NodeID: node, Generation: "g1"}
			c := postgres.Connection{CID: 7, KID: 1}
			ticket := rand.Text() + rand.Text()
			// Match the protocol's 43-byte ticket alphabet.
			ticket = ticket[:43]
			if err := ag.RotateNode(ctx, node, "", a.Generation); err != nil {
				t.Fatal("rotate", err)
			}
			defer func() {
				if err := ag.RotateNode(ctx, node, a.Generation, "g2"); err != nil {
					t.Error("cleanup", err)
				}
			}()
			if agents.Register(ctx, a, c, ticket, time.Minute) == nil {
				t.Fatal("default admitted legacy")
			}
			proof, err := profile.NewCredential()
			if err != nil {
				t.Fatal(err)
			}
			if ag.RegisterProfile(ctx, a, c, ticket, time.Minute, proof) == nil {
				t.Fatal("legacy node accepted new protocol")
			}
			if err := ag.Register(ctx, a, c, ticket, time.Minute); err != nil {
				t.Fatal("register", err)
			}
			if err := ag.Register(ctx, a, c, ticket, time.Minute); err != nil {
				t.Fatal("idempotent register", err)
			}
			browser := sha256.Sum256([]byte(rand.Text()))
			if err := pub.Start(ctx, ticket, "request-"+node, browser); err != nil {
				t.Fatal("start", err)
			}
			pending, err := pub.Lookup(ctx, ticket, browser)
			if err != nil {
				t.Fatal("lookup", err)
			}
			now := time.Now()
			d := controller.Authorization{Username: "verified-user", SubjectHash: sha256.Sum256([]byte(node)), GroupName: coreGroup, MaxConnections: 1,
				AssertionHash: sha256.Sum256([]byte(rand.Text())), AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour)}
			if scenario == "revoke-complete" {
				pub = public
			}
			if scenario == "no-group" {
				d.GroupName, d.DenialReason = "", "no_vpn_group"
			}
			err = pub.Complete(ctx, pending, d)
			denied := scenario == "revoke-complete" || scenario == "no-group"
			if denied {
				if !errors.Is(err, controller.ErrGroupDenied) {
					t.Fatal("legacy bypassed policy", err)
				}
			} else if !errors.Is(err, controller.ErrDecisionPending) {
				t.Fatal("complete", err)
			}
			if scenario == "revoke-fetch" {
				ag = agents
			}
			decision, err := ag.Fetch(ctx, a, c)
			if scenario == "revoke-fetch" {
				if !errors.Is(err, controller.ErrLoginExpired) {
					t.Fatal("revoked fetch admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal("fetch", err)
			}
			if denied {
				if decision.DenialReason == "" || ag.Acknowledge(ctx, a, decision.ID, postgres.Applied) == nil {
					t.Fatal("denial became an authorization")
				}
				return
			}
			if decision.GroupName != coreGroup || decision.SubjectHash != d.SubjectHash || decision.DenialReason != "" {
				t.Fatal("legacy lost verified SAML policy")
			}
			if scenario == "revoke-ack" {
				ag = agents
			}
			err = ag.Acknowledge(ctx, a, decision.ID, postgres.Applied)
			if scenario == "revoke-ack" {
				if !errors.Is(err, controller.ErrLoginExpired) {
					t.Fatal("revoked acknowledgement admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal("ack", err)
			}
			if scenario == "mixed-limit" {
				bound := postgres.Agent{NodeID: "bound-" + rand.Text(), Generation: "g1"}
				if err := agents.RotateNode(ctx, bound.NodeID, "", "g1"); err != nil {
					t.Fatal(err)
				}
				defer agents.RotateNode(ctx, bound.NodeID, "g1", "g2")
				if err := pub.CreateProfile(ctx, proof, profile.Owner{SubjectHash: d.SubjectHash}); err != nil {
					t.Fatal(err)
				}
				if ag.Register(ctx, bound, c, ticket, time.Minute) == nil {
					t.Fatal("allowlist leaked to bound node")
				}
				second := (rand.Text() + rand.Text())[:43]
				if err := agents.RegisterProfile(ctx, bound, c, second, time.Minute, proof); err != nil {
					t.Fatal(err)
				}
				if err := pub.Start(ctx, second, "second-"+node, browser); err != nil {
					t.Fatal(err)
				}
				p, err := pub.Lookup(ctx, second, browser)
				if err != nil {
					t.Fatal(err)
				}
				d.AssertionHash = sha256.Sum256([]byte(rand.Text()))
				if !errors.Is(pub.Complete(ctx, p, d), controller.ErrConnectionLimit) {
					t.Fatal("legacy session did not consume global slot")
				}
				got, err := agents.Fetch(ctx, bound, c)
				if err != nil || got.DenialReason != "connection_limit" {
					t.Fatal("mixed-format limit bypass", err)
				}
			}
			if err := ag.Cancel(ctx, a, c); err != nil {
				t.Fatal("cancel", err)
			}
			if _, err := ag.Fetch(ctx, a, c); err == nil {
				t.Fatal("cancelled legacy session remained deliverable")
			}
		})
	}
	if !bytes.Contains(audit.Bytes(), []byte(`"event":"profile.legacy_login"`)) || !bytes.Contains(audit.Bytes(), []byte(`"level":"WARN"`)) {
		t.Fatal("legacy migration use is not observable")
	}
}
