// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"supivpn/internal/controller"
	"supivpn/internal/operatorapi"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"sync"
	"testing"
	"time"
)

func TestProfileOperatorLifecycle(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	s := postgres.New(pool)
	proof, _ := profile.NewCredential()
	if err := s.CreateProfile(ctx, proof, sha256.Sum256([]byte("operator-test-owner"))); err != nil {
		t.Fatal("issue", err)
	}
	request := func(action string, revision int64) (postgres.OperatorState, error) {
		return s.Operate(ctx, postgres.OperatorRequest{Action: action, ProfileID: proof.ID, ExpectedRevision: revision})
	}
	state, err := request("profile-status", 0)
	if err != nil || state.Profile == nil || state.Profile.State != "active" || state.Profile.Revision != 1 {
		t.Fatal("new profile status", err)
	}
	for _, bad := range []postgres.OperatorRequest{
		{Action: "profile-block", ProfileID: proof.ID},
		{Action: "profile-block", ProfileID: proof.ID, ExpectedRevision: 1, NodeID: "another-target"},
		{Action: "profile-status", ProfileID: proof.ID, ExpectedRevision: 1},
		{Action: "force-recover", ProfileID: proof.ID},
	} {
		if _, err := s.Operate(ctx, bad); !errors.Is(err, postgres.ErrConflict) {
			t.Fatal("ambiguous or incomplete operator request accepted", err)
		}
	}
	state, err = request("profile-block", 1)
	if err != nil || state.Profile.State != "blocked" || state.Profile.Revision != 2 {
		t.Fatal("profile block failed", err)
	}
	if _, err = request("profile-activate", 1); !errors.Is(err, postgres.ErrConflict) {
		t.Fatal("stale revision reactivated profile", err)
	}
	// Exercise the same JSON envelope used by recovery Lambda and the VM CLI.
	raw := []byte(`{"source":"supivpn.operator.v1","action":"profile-activate","profile_id":"` + proof.ID + `","expected_revision":2}`)
	reply, err := operatorapi.Handler(s)(ctx, raw)
	result, ok := reply.(operatorapi.Reply)
	if err != nil || !ok || !result.OK || result.State.Profile.State != "active" || result.State.Profile.Revision != 3 {
		t.Fatal("profile reactivation envelope failed", err)
	}
}

func TestRequiredProfileRemoteSAMLAdmission(t *testing.T) {
	for _, scenario := range []string{"owner", "wrong-owner", "blocked-before-SAML", "missing-proof", "changed-rekey-proof"} {
		t.Run(scenario, func(t *testing.T) {
			groups := lifecycleGroups[:1]
			f := newGroupLifecycleFixture(t, groups, groups, groups)
			a := f.agents[0]
			a.config.ProfileBinding = "required"
			proof, _ := profile.NewCredential()
			assertion := assertionFor(f.app)
			owner := sha256.Sum256([]byte(assertion.Issuer.Value + "\x00profile-owner"))
			if err := f.stores[0].CreateProfile(context.Background(), proof, owner); err != nil {
				t.Fatal("issue", err)
			}
			if scenario == "blocked-before-SAML" || scenario == "missing-proof" {
				if scenario == "blocked-before-SAML" {
					if _, err := f.stores[0].SetProfileState(context.Background(), proof.ID, "blocked", 1); err != nil {
						t.Fatal("block", err)
					}
				} else {
					proof = profile.Credential{}
				}
				a.handleEvent(clientEvent{kind: "CONNECT", cid: 72, kid: 2, sso: "webauth", proof: proof})
				if command := f.nextCommand(t, 0); !strings.HasPrefix(command, "client-deny 72 2 ") {
					t.Fatal("invalid profile reached browser authentication")
				}
				return
			}
			subject := "profile-owner"
			if scenario == "wrong-owner" {
				subject = "another-valid-saml-user"
			}
			login := f.beginWithProof(t, 0, 72, subject, proof, groups...)
			c := a.connections[72]
			if c.proof.Secret != "" || c.proof.ID != proof.ID {
				t.Fatal("registered connection retained plaintext or lost correlation")
			}
			if scenario == "wrong-owner" {
				f.callback(t, login, http.StatusForbidden)
				f.deliver(t, login, "")
				return
			}
			f.callback(t, login, http.StatusAccepted)
			f.deliver(t, login, groups[0])
			a.handleEvent(clientEvent{kind: "REAUTH", cid: 72, kid: 3, proof: proof})
			if command := f.nextCommand(t, 0); command != "client-auth-nt 72 3" {
				t.Fatal("same-profile rekey refused")
			}
			if scenario == "changed-rekey-proof" {
				other, _ := profile.NewCredential()
				a.handleEvent(clientEvent{kind: "REAUTH", cid: 72, kid: 4, proof: other})
				if command := f.nextCommand(t, 0); !strings.HasPrefix(command, "client-deny 72 4 ") || !c.closing {
					t.Fatal("changed proof retained a usable tunnel")
				}
			}
		})
	}
}

func TestProfileBindingAdmission(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	s := postgres.New(pool)
	for _, scenario := range []string{"owner", "wrong-owner", "bad-secret", "blocked-register", "blocked-complete", "blocked-fetch", "blocked-ack", "legacy", "downgrade", "upgrade"} {
		t.Run(scenario, func(t *testing.T) {
			if _, err := pool.Exec(ctx, "TRUNCATE supivpn.nodes,supivpn.assertions,supivpn.issued_profiles CASCADE"); err != nil {
				t.Fatal("reset")
			}
			actor := postgres.Agent{NodeID: "binding-test", Generation: "g1"}
			conn := postgres.Connection{CID: 7, KID: 2}
			if err := s.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil {
				t.Fatal("rotate", err)
			}
			proof, err := profile.NewCredential()
			if err != nil {
				t.Fatal(err)
			}
			owner := sha256.Sum256([]byte("verified issuer and subject"))
			if err = s.CreateProfile(ctx, proof, owner); err != nil {
				t.Fatal("issue", err)
			}
			block := func() {
				t.Helper()
				if _, e := s.SetProfileState(ctx, proof.ID, "blocked", 1); e != nil {
					t.Fatal("block", e)
				}
			}
			if scenario == "blocked-register" {
				block()
			}
			if scenario == "bad-secret" {
				other, _ := profile.NewCredential()
				proof.Secret = other.Secret
			}
			ticket := strings.Repeat("x", 43)
			browser := sha256.Sum256([]byte("browser"))
			if scenario == "legacy" || scenario == "upgrade" {
				err = s.Register(ctx, actor, conn, ticket, time.Minute)
			} else {
				err = s.RegisterProfile(ctx, actor, conn, ticket, time.Minute, proof)
			}
			if scenario == "bad-secret" || scenario == "blocked-register" {
				if err == nil {
					t.Fatal("invalid proof admitted")
				}
				return
			}
			if err != nil {
				t.Fatal("register", err)
			}
			if scenario == "downgrade" {
				if s.Register(ctx, actor, conn, ticket, time.Minute) == nil {
					t.Fatal("bound registration downgraded")
				}
				return
			}
			if scenario == "upgrade" {
				if s.RegisterProfile(ctx, actor, conn, ticket, time.Minute, proof) == nil {
					t.Fatal("legacy registration rebound")
				}
				return
			}
			if err = s.Start(ctx, ticket, "request", browser); err != nil {
				t.Fatal("start", err)
			}
			pending, err := s.Lookup(ctx, ticket, browser)
			if err != nil {
				t.Fatal("lookup", err)
			}
			now := time.Now()
			d := controller.Authorization{Username: "verified-user", SubjectHash: owner, GroupName: coreGroup, MaxConnections: 1, AssertionHash: sha256.Sum256([]byte("assertion")), AssertionExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute), SessionExpiresAt: now.Add(time.Hour)}
			if scenario == "wrong-owner" {
				d.SubjectHash = sha256.Sum256([]byte("another verified owner"))
			}
			if scenario == "blocked-complete" {
				block()
			}
			err = s.Complete(ctx, pending, d)
			if scenario == "wrong-owner" || scenario == "blocked-complete" {
				if !errors.Is(err, controller.ErrGroupDenied) {
					t.Fatal("owner check did not deny", err)
				}
				decision, e := s.Fetch(ctx, actor, conn)
				if e != nil || decision.DenialReason != "profile_refused" {
					t.Fatal("denial missing", e)
				}
				return
			}
			if !errors.Is(err, controller.ErrDecisionPending) {
				t.Fatal("complete", err)
			}
			if scenario == "blocked-fetch" {
				block()
			}
			decision, err := s.Fetch(ctx, actor, conn)
			if scenario == "blocked-fetch" {
				if err == nil {
					t.Fatal("blocked decision delivered")
				}
				return
			}
			if err != nil || decision.SubjectHash != owner {
				t.Fatal("fetch", err)
			}
			if scenario == "blocked-ack" {
				block()
			}
			err = s.Acknowledge(ctx, actor, decision.ID, postgres.Applied)
			if scenario == "blocked-ack" {
				if err == nil {
					t.Fatal("blocked unacknowledged admission completed")
				}
				return
			}
			if err != nil {
				t.Fatal("ack", err)
			}
		})
	}
}

func TestProfileImportSingleUseAndExpiry(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	s := postgres.New(pool)
	if _, e := pool.Exec(ctx, "TRUNCATE supivpn.profile_imports"); e != nil {
		t.Fatal("reset")
	}
	token := strings.Repeat("a", 43)
	owner := sha256.Sum256([]byte("owner"))
	if e := s.CreateImport(ctx, token, owner); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for range 8 {
		wg.Go(func() { got, e := s.ConsumeImport(ctx, token); results <- e == nil && got == owner })
	}
	wg.Wait()
	close(results)
	count := 0
	for ok := range results {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatal("handoff was not atomic")
	}
	if e := s.CreateImport(ctx, token, owner); e != nil {
		t.Fatal(e)
	}
	if _, e := pool.Exec(ctx, "UPDATE supivpn.profile_imports SET expires_at=clock_timestamp()-interval '1 second'"); e != nil {
		t.Fatal("expire")
	}
	if _, e := s.ConsumeImport(ctx, token); e == nil {
		t.Fatal("expired handoff admitted")
	}
}
