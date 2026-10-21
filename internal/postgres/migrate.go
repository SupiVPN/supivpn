// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package postgres implements shared SAML state and an agent decision mailbox.
// It performs no migrations on startup and does not access OpenVPN or AWS.
package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate is an explicit deployment operation using a separate schema-owner
// connection. Runtime credentials must not be granted DDL permissions.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	return migrate(ctx, pool, false)
}

// MigrateAsOwner keeps object ownership independent of the deployment login.
// The login must be allowed to SET ROLE; runtime has no such membership.
func MigrateAsOwner(ctx context.Context, pool *pgxpool.Pool) error {
	return migrate(ctx, pool, true)
}

func migrate(ctx context.Context, pool *pgxpool.Pool, asOwner bool) error {
	if pool == nil {
		return errors.New("migration database unavailable")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errors.New("cannot begin migration")
	}
	defer tx.Rollback(context.Background())
	// Bound DDL lock waits so a blocked deploy cannot starve lease heartbeats.
	if _, err = tx.Exec(ctx, "SET LOCAL lock_timeout = '3s'; SET LOCAL statement_timeout = '10s'"); err != nil {
		return errors.New("cannot set migration timeouts")
	}
	// Serializes migration runners, including the initial metadata table.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7273182101)"); err != nil {
		return errors.New("cannot lock migrations")
	}
	if asOwner {
		if _, err = tx.Exec(ctx, "SET LOCAL ROLE supivpn_owner"); err != nil {
			return errors.New("migration login cannot assume supivpn_owner")
		}
		var conflictingOwner bool
		err = tx.QueryRow(ctx, `
            SELECT EXISTS (
                SELECT 1 FROM pg_namespace
                WHERE nspname = 'supivpn' AND nspowner <> current_user::regrole
                UNION ALL
                SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE (n.nspname = 'supivpn' OR
                       (n.nspname = 'public' AND c.relname = 'supivpn_schema_migrations'))
                  AND c.relowner <> current_user::regrole
                UNION ALL
                SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='supivpn' AND p.proowner<>current_user::regrole
            )
        `).Scan(&conflictingOwner)
		if err != nil {
			return errors.New("cannot verify migration ownership")
		}
		if conflictingOwner {
			return errors.New("existing SupiVPN objects require explicit ownership migration")
		}
	}
	if _, err = tx.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS public.supivpn_schema_migrations (
            version integer PRIMARY KEY, checksum bytea NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
        );
        REVOKE ALL ON public.supivpn_schema_migrations FROM PUBLIC
    `); err != nil {
		return errors.New("cannot initialize migration metadata")
	}
	files := []string{"001_auth.sql", "002_profiles.sql", "003_sessions.sql", "004_renewals.sql", "005_recovery.sql", "006_session_expiry.sql", "007_safe_recovery.sql", "008_audit_username.sql", "009_component_isolation.sql", "010_runtime_queries.sql"}
	rows, err := tx.Query(ctx, "SELECT version, checksum FROM public.supivpn_schema_migrations ORDER BY version")
	if err != nil {
		return errors.New("cannot read migration metadata")
	}
	var recorded [][]byte
	for rows.Next() {
		var version int
		var checksum []byte
		if rows.Scan(&version, &checksum) != nil || version != len(recorded)+1 || version > len(files) {
			rows.Close()
			return errors.New("unsupported or modified schema migration")
		}
		recorded = append(recorded, checksum)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return errors.New("cannot read migration metadata")
	}
	rows.Close()
	for i, name := range files {
		data, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return errors.New("migration file unavailable")
		}
		checksum := sha256.Sum256(data)
		if i < len(recorded) {
			if string(recorded[i]) != string(checksum[:]) {
				return errors.New("unsupported or modified schema migration")
			}
			continue
		}
		if _, err = tx.Exec(ctx, string(data)); err != nil {
			var databaseError *pgconn.PgError
			if errors.As(err, &databaseError) {
				return fmt.Errorf("schema migration %d failed (SQLSTATE %s)", i+1, databaseError.Code)
			}
			return fmt.Errorf("schema migration %d failed", i+1)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO public.supivpn_schema_migrations(version, checksum) VALUES ($1, $2)", i+1, checksum[:]); err != nil {
			return errors.New("cannot record migration")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.New("migration commit outcome unknown; retry with the same migrations")
	}
	return nil
}
