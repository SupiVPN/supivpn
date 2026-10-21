// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"testing"

	"supivpn/internal/postgres"
)

func TestPostgresPrunePreservesAuthorizationState(t *testing.T) {
	pool, _ := integrationDatabase(t)
	ctx := context.Background()
	store := postgres.New(pool)
	for _, mode := range []string{"legacy", "isolated-function"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Exec(ctx, `TRUNCATE supivpn.logins,supivpn.assertions,supivpn.profile_logins,supivpn.nodes RESTART IDENTITY CASCADE;
                INSERT INTO supivpn.nodes(node_id,generation) VALUES ('node-a','generation-a');
                INSERT INTO supivpn.logins(ticket_hash,node_id,generation,cid,kid,expires_at)
                    SELECT decode(lpad(to_hex(n),64,'0'),'hex'),'node-a','generation-a',n,1,
                        clock_timestamp()-interval '25 hours' FROM generate_series(1,4) n;
                UPDATE supivpn.logins SET state='decided',request_id='request-'||cid,
                    browser_hash=decode(repeat('02',32),'hex'),decision_id='decision-'||cid,
                    group_name='admins-vpn',subject_hash=decode(repeat('03',32),'hex'),
                    not_before=clock_timestamp()-interval '26 hours',not_after=clock_timestamp()-interval '25 hours',
                    session_unlimited=(cid=2),session_expires_at=CASE WHEN cid=1 THEN clock_timestamp()-interval '1 hour' END
                    WHERE cid IN (1,2);
                INSERT INTO supivpn.assertions(assertion_hash,expires_at)
                    SELECT decode(lpad(to_hex(n),64,'0'),'hex'),
                        clock_timestamp()+CASE WHEN n=3 THEN interval '1 hour' ELSE interval '-1 hour' END
                    FROM generate_series(1,3) n;
                INSERT INTO supivpn.profile_logins(ticket_hash,request_id,browser_hash,expires_at)
                    SELECT decode(lpad(to_hex(n),64,'0'),'hex'),'profile-'||n,decode(repeat('04',32),'hex'),
                        clock_timestamp()+CASE WHEN n=3 THEN interval '1 hour' ELSE interval '-1 hour' END
                    FROM generate_series(1,3) n`); err != nil {
				t.Fatal("cannot initialize disposable cleanup fixture")
			}
			prune := func() int64 {
				t.Helper()
				var count int64
				var err error
				if mode == "legacy" {
					count, err = store.Prune(ctx, 1)
				} else {
					err = pool.QueryRow(ctx, "SELECT supivpn.prune_auth(1)").Scan(&count)
				}
				if err != nil {
					t.Fatal("cannot prune disposable state")
				}
				return count
			}
			for range 2 {
				if prune() != 3 {
					t.Fatal("cleanup did not delete one expired row per authentication table")
				}
			}
			if prune() != 0 {
				t.Fatal("cleanup deleted live replay/profile state or an unfenced grant")
			}
			var grants, replay, profiles int
			if err := pool.QueryRow(ctx, `SELECT
                (SELECT count(*) FROM supivpn.logins WHERE state='decided'),
                (SELECT count(*) FROM supivpn.assertions),
                (SELECT count(*) FROM supivpn.profile_logins)`).Scan(&grants, &replay, &profiles); err != nil ||
				grants != 2 || replay != 1 || profiles != 1 {
				t.Fatal("cleanup lost finite/unlimited reservations or live one-use state")
			}
			if _, err := pool.Exec(ctx, "UPDATE supivpn.nodes SET fence_state='stopped'"); err != nil {
				t.Fatal("cannot confirm synthetic node stop")
			}
			if prune() != 1 || prune() != 1 || prune() != 0 {
				t.Fatal("confirmed fencing did not permit bounded grant cleanup")
			}
		})
	}
}
