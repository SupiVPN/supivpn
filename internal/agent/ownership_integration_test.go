// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
 "github.com/jackc/pgx/v5/pgxpool"
	"context"
    "crypto/sha256"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"supivpn/internal/postgres"
)

func TestMigrationOwnerAndDefaultPrivileges(t *testing.T) {
	admin, _ := integrationDatabase(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, err := admin.Exec(ctx, `
            ALTER DATABASE supivpn_test OWNER TO CURRENT_USER;
            DROP SCHEMA IF EXISTS supivpn CASCADE;
            DROP TABLE IF EXISTS public.supivpn_schema_migrations;
            DROP OWNED BY supivpn_runtime, supivpn_owner, supivpn_test_migrator, supivpn_test_admin;
            DROP ROLE supivpn_runtime, supivpn_owner, supivpn_test_migrator, supivpn_test_admin;
        `)
		if err != nil {
			t.Error("cannot clean up disposable ownership fixture")
		}
	})
	openAs := func(user string) *pgxpool.Pool {
		t.Helper()
		u, err := url.Parse(os.Getenv("SUPIVPN_TEST_POSTGRES_URL"))
		if err != nil {
			t.Fatal("invalid local test URL")
		}
		u.User = url.User(user)
		p, err := postgres.Open(ctx, u.String())
		if err != nil {
			t.Fatal("cannot open local role connection")
		}
		t.Cleanup(p.Close)
		return p
	}
	// Superuser only prepares the disposable DB and its RDS-like administrator.
	// All application roles and privileges below are created without SUPERUSER.
	_, err := admin.Exec(ctx, `
        DROP SCHEMA supivpn CASCADE;
        DROP TABLE public.supivpn_schema_migrations;
        CREATE ROLE supivpn_test_admin LOGIN INHERIT NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION;
        ALTER DATABASE supivpn_test OWNER TO supivpn_test_admin;
    `)
	if err != nil {
		t.Fatal("cannot prepare disposable non-superuser administrator")
	}
	bootstrap := openAs("supivpn_test_admin")
	for _, query := range []string{
		"CREATE ROLE supivpn_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
		"CREATE ROLE supivpn_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20",
		"CREATE ROLE supivpn_test_migrator LOGIN NOINHERIT",
		// cyrilgdn/postgresql 1.27.0 revokes before granting membership.
		"REVOKE supivpn_owner FROM supivpn_test_admin",
		"GRANT supivpn_owner TO supivpn_test_admin",
		"REVOKE supivpn_owner FROM supivpn_test_admin",
		"GRANT supivpn_owner TO supivpn_test_admin",
		"GRANT supivpn_owner TO supivpn_test_migrator",
		"REVOKE ALL ON DATABASE supivpn_test FROM PUBLIC",
		"GRANT CONNECT, CREATE ON DATABASE supivpn_test TO supivpn_owner",
		"GRANT CONNECT ON DATABASE supivpn_test TO supivpn_runtime, supivpn_test_migrator",
		"REVOKE CREATE ON SCHEMA public FROM PUBLIC",
		"GRANT USAGE, CREATE ON SCHEMA public TO supivpn_owner",
		"CREATE SCHEMA supivpn AUTHORIZATION supivpn_owner",
		"GRANT USAGE ON SCHEMA supivpn TO supivpn_runtime",
		"ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO supivpn_runtime",
		"ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn GRANT USAGE, SELECT ON SEQUENCES TO supivpn_runtime",
		"ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA public GRANT SELECT ON TABLES TO supivpn_runtime",
	} {
		if _, err = bootstrap.Exec(ctx, query); err != nil {
			t.Fatalf("non-superuser bootstrap failed for %s: %v", query, err)
		}
	}
	var canSetOwner, isSuperuser bool
	if err = bootstrap.QueryRow(ctx, `SELECT pg_has_role(current_user, 'supivpn_owner', 'SET'),
        (SELECT rolsuper FROM pg_roles WHERE rolname=current_user)`).Scan(&canSetOwner, &isSuperuser); err != nil || !canSetOwner || isSuperuser {
		t.Fatal("bootstrap must be a non-superuser with SET access to the owner")
	}
	deployer := openAs("supivpn_test_migrator")
	runtime := openAs("supivpn_runtime")
	for range 2 {
		if err := postgres.MigrateAsOwner(ctx, deployer); err != nil {
			t.Fatal("owner migration failed or was not repeatable")
		}
	}
	var wrongOwners int
	err = admin.QueryRow(ctx, `
        SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE (n.nspname='supivpn' OR
               (n.nspname='public' AND c.relname='supivpn_schema_migrations'))
          AND c.relowner <> 'supivpn_owner'::regrole
    `).Scan(&wrongOwners)
	if err != nil || wrongOwners != 0 {
		t.Fatal("tables, indexes or sequences belong to the deployment login")
	}
	var currentRole string
	if err = deployer.QueryRow(ctx, "SELECT current_user").Scan(&currentRole); err != nil || currentRole != "supivpn_test_migrator" {
		t.Fatal("migration role leaked outside its transaction")
	}
	store := postgres.New(runtime)
	if !store.Ready(ctx) {
		t.Fatal("runtime cannot read migration metadata")
	}
    profiles := postgres.NewProfileBackend(store, time.Minute)
    ticket := "profile_" + strings.Repeat("p", 43)
    browser := sha256.Sum256([]byte("owner-test-browser"))
    if profiles.Start(ctx, ticket, "owner-profile-request", browser) != nil {
        t.Fatal("runtime cannot insert into the new profile table")
    }
    if _, err := profiles.Lookup(ctx, ticket, browser); err != nil {
        t.Fatal("runtime cannot lock/read the new profile table")
    }
	if err = store.RotateNode(ctx, "owner-test-node", "", "g1"); err != nil {
		t.Fatal("runtime cannot write under default table privileges")
	}
	if err = store.Register(ctx, postgres.Agent{NodeID: "owner-test-node", Generation: "g1"},
		postgres.Connection{CID: 1, KID: 1}, strings.Repeat("o", 43), time.Minute); err != nil {
		t.Fatal("runtime cannot use the migrated identity sequence")
	}
	for _, query := range []string{
		"SET ROLE supivpn_owner",
		"CREATE TABLE supivpn.forbidden (id integer)",
		"CREATE TABLE public.forbidden (id integer)",
		"CREATE TEMP TABLE forbidden (id integer)",
		"ALTER TABLE supivpn.nodes ADD COLUMN forbidden integer",
		"DROP TABLE supivpn.assertions",
		"UPDATE public.supivpn_schema_migrations SET version=version",
		"CREATE ROLE supivpn_forbidden",
	} {
		if _, err := runtime.Exec(ctx, query); err == nil {
			t.Fatalf("runtime unexpectedly allowed operation: %s", query)
		}
	}
	if err := postgres.MigrateAsOwner(ctx, runtime); err == nil {
		t.Fatal("runtime assumed migration ownership")
	}
	tx, err := deployer.Begin(ctx)
	if err != nil {
		t.Fatal("cannot begin future migration")
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `
        SET LOCAL ROLE supivpn_owner;
        CREATE TABLE supivpn.future_table (id bigint GENERATED ALWAYS AS IDENTITY, value text);
    `); err != nil {
		t.Fatal("cannot create future owner table")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("future migration commit failed")
	}
	var id int64
	if err = runtime.QueryRow(ctx, "INSERT INTO supivpn.future_table(value) VALUES ('test') RETURNING id").Scan(&id); err != nil || id != 1 {
		t.Fatal("new tables or identity sequences lost runtime privileges")
	}
	if _, err = admin.Exec(ctx, "CREATE TABLE supivpn.wrong_owner (id integer)"); err != nil {
		t.Fatal("cannot create ownership conflict fixture")
	}
	if err = postgres.MigrateAsOwner(ctx, deployer); err == nil {
		t.Fatal("migration accepted mixed object ownership")
	}
	var unchanged bool
	if err = admin.QueryRow(ctx, "SELECT relowner=current_user::regrole FROM pg_class WHERE oid='supivpn.wrong_owner'::regclass").Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("migration silently reassigned existing objects")
	}
}
