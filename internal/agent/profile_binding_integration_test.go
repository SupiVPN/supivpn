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
	"net/url"
	"os"
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
	if err := s.CreateProfile(ctx, proof, profile.Owner{SubjectHash: sha256.Sum256([]byte("operator-test-owner"))}); err != nil {
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
			if err := f.stores[0].CreateProfile(context.Background(), proof, profile.Owner{SubjectHash: owner}); err != nil {
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
	// Match the combined VM runtime role: table DML, no owner membership and
	// no EXECUTE grant on the isolated Lambda components' security-definer API.
	sql, err := os.ReadFile("../postgres/testdata/runtime-role.sql")
	if err != nil {
		t.Fatal("runtime bootstrap missing")
	}
	if _, err = pool.Exec(ctx, string(sql)); err != nil {
		t.Fatal("runtime role bootstrap failed")
	}
	defer func() {
		if _, e := pool.Exec(ctx, "DROP OWNED BY supivpn_runtime; DROP ROLE supivpn_runtime"); e != nil {
			t.Error("runtime role cleanup failed")
		}
	}()
	u, _ := url.Parse(os.Getenv("SUPIVPN_TEST_POSTGRES_URL"))
	u.User = url.User("supivpn_runtime")
	runtime, err := postgres.Open(ctx, u.String())
	if err != nil {
		t.Fatal("restricted runtime pool unavailable")
	}
	defer runtime.Close()
	var canExecute bool
	if runtime.QueryRow(ctx, "SELECT has_function_privilege(current_user,'supivpn.profile_proof_valid(text,bytea)','EXECUTE')").Scan(&canExecute) != nil || canExecute {
		t.Fatal("combined VM fixture unexpectedly has isolated function privileges")
	}
	s := postgres.New(runtime)
	t.Run("legacy-migration", func(t *testing.T) { testLegacyMigrationLifecycle(t, s, s) })
	s, err = s.WithLegacyProfiles([]string{"separate-legacy-node"})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"owner", "wrong-owner", "bad-secret", "unknown-profile", "blocked-register", "blocked-complete", "blocked-fetch", "blocked-ack", "legacy", "downgrade", "upgrade", "label-lock-contention", "existing-label"} {
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
			label := ""
			if scenario == "existing-label" {
				label = "original-owner-label"
			}
			if err = s.CreateProfile(ctx, proof, profile.Owner{SubjectHash: owner, Username: label}); err != nil {
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
			if scenario == "unknown-profile" {
				other, _ := profile.NewCredential()
				proof.ID = other.ID
			}
			ticket := strings.Repeat("x", 43)
			browser := sha256.Sum256([]byte("browser"))
			if scenario == "legacy" || scenario == "upgrade" {
				err = s.Register(ctx, actor, conn, ticket, time.Minute)
				if !errors.Is(err, postgres.ErrConflict) {
					t.Fatal("unbound registration accepted", err)
				}
				if scenario == "legacy" {
					return
				}
				// Historical registrations have no profile binding. A retry with
				// a valid new proof must not attach it to somebody else's ticket.
				hash := sha256.Sum256([]byte(ticket))
				if _, err = pool.Exec(ctx, `INSERT INTO supivpn.logins(ticket_hash,node_id,generation,cid,kid,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 minute')`, hash[:], actor.NodeID, actor.Generation, conn.CID, conn.KID); err != nil {
					t.Fatal("historical login fixture", err)
				}
			} else {
				err = s.RegisterProfile(ctx, actor, conn, ticket, time.Minute, proof)
			}
			if scenario == "bad-secret" || scenario == "unknown-profile" || scenario == "blocked-register" {
				if !errors.Is(err, controller.ErrLoginExpired) {
					t.Fatal("invalid proof was not rejected by the credential check", err)
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
			if scenario == "label-lock-contention" {
				tx, e := pool.Begin(ctx)
				if e != nil {
					t.Fatal("metadata contention fixture")
				}
				defer tx.Rollback(ctx)
				if _, e = tx.Exec(ctx, "SELECT profile_id FROM supivpn.issued_profiles WHERE profile_id=$1 FOR SHARE", proof.ID); e != nil {
					t.Fatal("metadata contention lock")
				}
			}
			completeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			err = s.Complete(completeCtx, pending, d)
			p, lookupErr := s.ProfileState(ctx, proof.ID)
			if lookupErr != nil {
				t.Fatal("profile label lookup failed")
			}
			wantOwner := "verified-user"
			if scenario == "wrong-owner" || scenario == "blocked-complete" || scenario == "legacy" || scenario == "label-lock-contention" {
				wantOwner = ""
			}
			if scenario == "existing-label" {
				wantOwner = label
			}
			if p.OwnerUsername != wantOwner {
				t.Fatal("existing profile label did not follow verified owner admission")
			}
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
	if e := s.CreateImport(ctx, token, profile.Owner{SubjectHash: owner, Username: "import-owner"}); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for range 8 {
		wg.Go(func() {
			got, e := s.ConsumeImport(ctx, token)
			results <- e == nil && (got.SubjectHash == owner && got.Username == "import-owner")
		})
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
	if e := s.CreateImport(ctx, token, profile.Owner{SubjectHash: owner, Username: "import-owner"}); e != nil {
		t.Fatal(e)
	}
	if _, e := pool.Exec(ctx, "UPDATE supivpn.profile_imports SET expires_at=clock_timestamp()-interval '1 second'"); e != nil {
		t.Fatal("expire")
	}
	if _, e := s.ConsumeImport(ctx, token); e == nil {
		t.Fatal("expired handoff admitted")
	}
}

// Expiry must be checked after waiting for a database row lock, not merely
// against the snapshot seen before that wait.
func TestProfileImportExpiryAfterRowLock(t *testing.T) {
	pool, other := integrationDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := postgres.New(pool)
	token := strings.Repeat("l", 43)
	owner := sha256.Sum256([]byte("locked-import-owner"))
	if s.CreateImport(ctx, token, profile.Owner{SubjectHash: owner, Username: "import-owner"}) != nil {
		t.Fatal("import fixture unavailable")
	}
	hash := sha256.Sum256([]byte(token))
	var expiry time.Time
	if err := pool.QueryRow(ctx, "UPDATE supivpn.profile_imports SET expires_at=clock_timestamp()+interval '1 second' WHERE token_hash=$1 RETURNING expires_at", hash[:]).Scan(&expiry); err != nil {
		t.Fatal("fixture expiry unavailable")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal("fixture lock transaction failed")
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT token_hash FROM supivpn.profile_imports WHERE token_hash=$1 FOR UPDATE", hash[:]); err != nil {
		t.Fatal("fixture row lock failed")
	}
	result := make(chan error, 1)
	go func() {
		_, e := postgres.New(other).ConsumeImport(ctx, token)
		result <- e
	}()
	// Confirm the consumer actually reached the row lock before expiry.
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for _, query := range []string{
		"SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
		"SELECT clock_timestamp()>=$1",
	} {
		var arg any = int32(tx.Conn().PgConn().PID())
		if strings.Contains(query, "clock_timestamp") {
			arg = expiry
		}
		for {
			var ready bool
			if pool.QueryRow(ctx, query, arg).Scan(&ready) != nil {
				t.Fatal("cannot observe disposable lock or expiry")
			}
			if ready {
				break
			}
			select {
			case <-result:
				t.Fatal("consumer returned before lock release")
			case <-ctx.Done():
				t.Fatal("fixture did not reach lock or expiry")
			case <-tick.C:
			}
		}
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("fixture unlock failed")
	}
	if err = <-result; !errors.Is(err, controller.ErrLoginExpired) {
		t.Fatal("expired import accepted after a database lock wait")
	}
}
