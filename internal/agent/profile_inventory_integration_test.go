// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"supivpn/internal/controller"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
	"testing"
	"time"
)

func TestProfileOperatorInventory(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	s := postgres.New(pool)
	if _, err := pool.Exec(ctx, "TRUNCATE supivpn.issued_profiles CASCADE"); err != nil {
		t.Fatal("fixture reset")
	}
	owner := sha256.Sum256([]byte("inventory-owner"))
	for _, suffix := range []string{"1", "2", "3"} {
		p, _ := profile.NewCredential()
		p.ID = "svp1_" + strings.Repeat("0", 31) + suffix
		if s.CreateProfile(ctx, p, profile.Owner{SubjectHash: owner, Username: "inventory-user"}) != nil {
			t.Fatal("fixture issue")
		}
	}
	q := postgres.OperatorRequest{Action: "profile-list", Limit: 2}
	first, err := s.ListProfiles(ctx, q)
	if err != nil || len(first.Profiles) != 2 || first.NextCursor != first.Profiles[1].ID {
		t.Fatal("first inventory page")
	}
	for _, p := range first.Profiles {
		if p.OwnerUsername != "inventory-user" {
			t.Fatal("inventory lost the verified owner label")
		}
	}
	q.AfterID = first.NextCursor
	last, err := s.ListProfiles(ctx, q)
	if err != nil || len(last.Profiles) != 1 || last.NextCursor != "" || last.Profiles[0].ID <= q.AfterID {
		t.Fatal("cursor page")
	}
	b, _ := json.Marshal(first)
	for _, field := range []string{"subject_hash", "secret_hash"} {
		if strings.Contains(string(b), field) {
			t.Fatal("inventory disclosed private field")
		}
	}
	for _, bad := range []postgres.OperatorRequest{
		{Action: "profile-list", Limit: 101}, {Action: "profile-list", Limit: 0},
		{Action: "profile-list", Limit: 1, AfterID: "' OR TRUE--"},
		{Action: "profile-list", Limit: 1, ExpectedRevision: 1},
		{Action: "profile-list", Limit: 1, ProfileID: first.Profiles[0].ID},
	} {
		if _, err := s.ListProfiles(ctx, bad); !errors.Is(err, postgres.ErrConflict) {
			t.Fatal("unsafe inventory query")
		}
	}
	if _, err = s.Operate(ctx, q); !errors.Is(err, postgres.ErrConflict) {
		t.Fatal("inventory available through recovery protocol")
	}
	id := first.Profiles[0].ID
	var revision int64
	err = pool.QueryRow(ctx, `UPDATE supivpn.issued_profiles SET state='blocked',revision=revision+1
 WHERE profile_id=$1 AND revision=$2 RETURNING revision`, id, int64(1)).Scan(&revision)
	if err != nil || revision != 2 {
		t.Fatal("documented block failed")
	}
	result, err := pool.Exec(ctx, `UPDATE supivpn.issued_profiles SET state='active',revision=revision+1 WHERE profile_id=$1 AND revision=$2`, id, int64(1))
	if err != nil || result.RowsAffected() != 0 {
		t.Fatal("stale SQL reactivated a profile")
	}
	state, err := s.ProfileState(ctx, id)
	if err != nil || state.State != "blocked" || state.Revision != 2 {
		t.Fatal("blocked state not preserved")
	}
}

// Exercise the documented Lambda SQL procedure with exactly its column grants.
// The role cannot read proof/owner digests or change ownership/credentials.
func TestProfileLimitedDatabaseOperator(t *testing.T) {
	admin, _ := integrationDatabase(t)
	ctx := context.Background()
	if _, err := admin.Exec(ctx, `CREATE ROLE supivpn_profile_operator_test LOGIN;
 GRANT CONNECT ON DATABASE supivpn_test TO supivpn_profile_operator_test;
 GRANT USAGE ON SCHEMA supivpn TO supivpn_profile_operator_test;
 GRANT SELECT(profile_id,state,revision,created_at,owner_username),UPDATE(state,revision)
 ON supivpn.issued_profiles TO supivpn_profile_operator_test`); err != nil {
		t.Fatal("operator fixture grants failed")
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP OWNED BY supivpn_profile_operator_test; DROP ROLE supivpn_profile_operator_test"); err != nil {
			t.Error("operator fixture cleanup failed")
		}
	}()
	u, err := url.Parse(os.Getenv("SUPIVPN_TEST_POSTGRES_URL"))
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	u.User = url.User("supivpn_profile_operator_test")
	limited, err := postgres.Open(ctx, u.String())
	if err != nil {
		t.Fatal("operator fixture connection failed")
	}
	defer limited.Close()
	proof, err := profile.NewCredential()
	if err != nil || postgres.New(admin).CreateProfile(ctx, proof, profile.Owner{SubjectHash: sha256.Sum256([]byte("sql-operator-owner"))}) != nil {
		t.Fatal("operator profile fixture failed")
	}
	s := postgres.New(limited)
	if _, err = s.ProfileState(ctx, proof.ID); err != nil {
		t.Fatal("documented column SELECT refused")
	}
	for _, query := range []string{
		"SELECT secret_hash FROM supivpn.issued_profiles",
		"SELECT subject_hash FROM supivpn.issued_profiles",
		"UPDATE supivpn.issued_profiles SET subject_hash=subject_hash",
		"UPDATE supivpn.issued_profiles SET secret_hash=secret_hash",
		"DELETE FROM supivpn.issued_profiles WHERE false",
	} {
		if _, err = limited.Exec(ctx, query); err == nil {
			t.Fatal("column-restricted operator exceeded scope")
		}
	}
	tx, err := limited.Begin(ctx)
	if err != nil {
		t.Fatal("operator transaction failed")
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='5s'"); err != nil {
		t.Fatal("operator timeouts failed")
	}
	var revision int64
	if err = tx.QueryRow(ctx, `UPDATE supivpn.issued_profiles SET state='blocked',revision=revision+1
 WHERE profile_id=$1 AND revision=1 RETURNING revision`, proof.ID).Scan(&revision); err != nil || revision != 2 {
		t.Fatal("documented limited block failed")
	}
	// An admission started while the operator holds the update lock must wait,
	// then fail closed on its deadline; it cannot read the previous active row.
	a := postgres.Agent{NodeID: "operator-race", Generation: "g1"}
	store := postgres.New(admin)
	if store.RotateNode(ctx, a.NodeID, "", a.Generation) != nil {
		t.Fatal("admission race fixture failed")
	}
	bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	err = store.RegisterProfile(bounded, a, postgres.Connection{CID: 1, KID: 1}, strings.Repeat("r", 43), time.Minute, proof)
	cancel()
	if err == nil {
		t.Fatal("admission bypassed concurrent block lock")
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("documented block commit failed")
	}
	if _, err = s.SetProfileState(ctx, proof.ID, "active", 1); !errors.Is(err, postgres.ErrConflict) {
		t.Fatal("stale operator revision reactivated a blocked profile")
	}
	state, err := s.ProfileState(ctx, proof.ID)
	if err != nil || state.State != "blocked" || state.Revision != 2 {
		t.Fatal("post-commit status failed")
	}
	var pending int
	if admin.QueryRow(ctx, "SELECT count(*) FROM supivpn.logins WHERE node_id='operator-race'").Scan(&pending) != nil || pending != 0 {
		t.Fatal("timed-out admission persisted partial state")
	}
	if err = store.RegisterProfile(ctx, a, postgres.Connection{CID: 1, KID: 1}, strings.Repeat("r", 43), time.Minute, proof); !errors.Is(err, controller.ErrLoginExpired) {
		t.Fatal("committed block did not deny admission")
	}
	if _, err = s.SetProfileState(ctx, proof.ID, "active", 2); err != nil {
		t.Fatal("explicit current-revision activation refused")
	}
	if err = store.RegisterProfile(ctx, a, postgres.Connection{CID: 1, KID: 1}, strings.Repeat("r", 43), time.Minute, proof); err != nil {
		t.Fatal("reactivated fixture cannot register")
	}
}
