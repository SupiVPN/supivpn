// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Component string

const (
	Public   Component = "public"
	AgentAPI Component = "agent"
	Recovery Component = "recovery"
)

type privileges struct {
	tables    map[string][]string
	columns   map[string]map[string][]string
	functions []string
	sequences []string
}

// This is both the deployment grant contract and the startup allowlist.
// No runtime may own objects, assume another role, create objects or grant access.
func componentPrivileges(c Component) (privileges, bool) {
	p := privileges{tables: map[string][]string{"public.supivpn_schema_migrations": {"SELECT"}}, columns: map[string]map[string][]string{}}
	switch c {
	case Public:
		p.tables["supivpn.nodes"] = []string{"SELECT"}
		p.tables["supivpn.logins"] = []string{"SELECT"}
		p.tables["supivpn.assertions"] = []string{"SELECT", "INSERT"}
		p.tables["supivpn.profile_logins"] = []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
		p.tables["supivpn.issued_profiles"] = []string{"SELECT", "INSERT"}
		p.tables["supivpn.profile_bindings"] = []string{"SELECT"}
		p.tables["supivpn.profile_imports"] = []string{"SELECT", "INSERT", "DELETE"}
		p.columns["supivpn.logins"] = map[string][]string{"UPDATE": {
			"request_id", "browser_hash", "state", "decision_id", "group_name", "denial_reason",
			"not_before", "not_after", "session_expires_at", "subject_hash", "session_unlimited", "username"}}
		p.functions = []string{"supivpn.lock_node(text)", "supivpn.profile_owner_active(text,bytea)"}
	case AgentAPI:
		p.tables["supivpn.profile_bindings"] = []string{"SELECT", "INSERT"}
		p.tables["supivpn.nodes"] = []string{"SELECT"}
		p.tables["supivpn.logins"] = []string{"SELECT"}
		p.columns["supivpn.logins"] = map[string][]string{
			"INSERT": {"ticket_hash", "node_id", "generation", "cid", "kid", "expires_at"},
			"UPDATE": {"state", "ack_result"}}
		p.functions = []string{"supivpn.lock_node(text)", "supivpn.agent_rotate(text,text,text)", "supivpn.agent_heartbeat(text,text,boolean)", "supivpn.profile_proof_valid(text,bytea)", "supivpn.profile_is_active(text)"}
		p.sequences = []string{"supivpn.logins_revision_seq"}
	case Recovery:
		p.tables["supivpn.issued_profiles"] = []string{"SELECT"}
		p.columns["supivpn.issued_profiles"] = map[string][]string{"UPDATE": {"state", "revision"}}
		p.tables["supivpn.nodes"] = []string{"SELECT"}
		p.columns["supivpn.nodes"] = map[string][]string{"UPDATE": {"fence_state", "fence_retry_at", "healthy_since"}}
		for _, table := range []string{"node_recovery", "node_recovery_stops", "node_recovery_starts", "node_maintenance", "operator_requests"} {
			p.tables["supivpn."+table] = []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
		}
		p.functions = []string{"supivpn.prune_auth(integer)"}
	default:
		return p, false
	}
	return p, true
}

// NewIsolated refuses shared/admin credentials before accepting requests.
func NewIsolated(ctx context.Context, pool *pgxpool.Pool, c Component, f Fencer) (*Store, error) {
	if c != Recovery && f != nil {
		return nil, errors.New("only recovery may have a fencing driver")
	}
	if err := CheckPrivileges(ctx, pool, c); err != nil {
		return nil, err
	}
	return &Store{pool: pool, component: c, fencer: f}, nil
}

func CheckPrivileges(ctx context.Context, pool *pgxpool.Pool, c Component) error {
	refused := errors.New("database component privileges invalid; require schema 11 and separate restricted roles")
	policy, ok := componentPrivileges(c)
	if !ok || pool == nil {
		return refused
	}
	var version int
	if pool.QueryRow(ctx, "SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&version) != nil || version != 11 {
		return refused
	}
	var unsafe bool
	err := pool.QueryRow(ctx, `SELECT
        (SELECT rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_roles WHERE rolname=current_user)
        OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname<>current_user AND pg_has_role(current_user,oid,'MEMBER'))
        OR has_database_privilege(current_user,current_database(),'CREATE,TEMP')
        OR has_schema_privilege(current_user,'supivpn','CREATE')
        OR has_schema_privilege(current_user,'public','CREATE')`).Scan(&unsafe)
	if err != nil || unsafe {
		return refused
	}
	// Check all effective table/column privileges in one round trip. Per-column
	// pool queries make cold-start admission depend on hundreds of network RTTs.
	rows, err := pool.Query(ctx, `WITH targets AS (
        SELECT c.oid,n.nspname||'.'||c.relname AS name
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relkind IN ('r','p','v','m','f') AND (n.nspname='supivpn' OR
        (n.nspname='public' AND c.relname='supivpn_schema_migrations')))
        SELECT t.name,'' AS col,right_name,
            has_table_privilege(current_user,t.oid,right_name),
            has_table_privilege(current_user,t.oid,right_name||' WITH GRANT OPTION')
        FROM targets t CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']) AS right_name
        UNION ALL
        SELECT t.name,a.attname,right_name,
            has_column_privilege(current_user,t.oid,a.attnum,right_name),
            has_column_privilege(current_user,t.oid,a.attnum,right_name||' WITH GRANT OPTION')
        FROM targets t JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
        CROSS JOIN unnest(ARRAY['SELECT','INSERT','UPDATE','REFERENCES']) AS right_name`)
	if err != nil {
		return refused
	}
	seen := map[string]bool{}
	seenColumns := map[string]map[string]bool{}
	var table, column, right string
	var held, grantable bool
	_, err = pgx.ForEachRow(rows, []any{&table, &column, &right, &held, &grantable}, func() error {
		seen[table] = true
		want := slices.Contains(policy.tables[table], right)
		if column != "" {
			want = want || slices.Contains(policy.columns[table][right], column)
			if seenColumns[table] == nil {
				seenColumns[table] = map[string]bool{}
			}
			seenColumns[table][column] = true
		}
		if held != want || grantable {
			return refused
		}
		return nil
	})
	if err != nil {
		return refused
	}
	for table := range policy.tables {
		if !seen[table] {
			return refused
		}
	}
	for table, rights := range policy.columns {
		for _, columns := range rights {
			for _, column := range columns {
				if !seenColumns[table][column] {
					return refused
				}
			}
		}
	}
	for _, kind := range []string{"function", "sequence"} {
		query := `SELECT n.nspname||'.'||p.proname||'('||replace(oidvectortypes(p.proargtypes),' ','')||')',has_function_privilege(current_user,p.oid,'EXECUTE'),has_function_privilege(current_user,p.oid,'EXECUTE WITH GRANT OPTION') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='supivpn'`
		if kind == "sequence" {
			query = `SELECT n.nspname||'.'||c.relname,has_sequence_privilege(current_user,c.oid,'USAGE'),has_sequence_privilege(current_user,c.oid,'SELECT,UPDATE,USAGE WITH GRANT OPTION') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='supivpn' AND c.relkind='S'`
		}
		rows, err := pool.Query(ctx, query)
		if err != nil {
			return refused
		}
		found := map[string]bool{}
		allowed := policy.functions
		if kind == "sequence" {
			allowed = policy.sequences
		}
		var name string
		var held, extra bool
		_, err = pgx.ForEachRow(rows, []any{&name, &held, &extra}, func() error {
			found[name] = true
			if held != slices.Contains(allowed, name) || extra {
				return refused
			}
			return nil
		})
		if err != nil {
			return refused
		}
		for _, name := range allowed {
			if !found[name] {
				return refused
			}
		}
	}
	return nil
}

// RuntimeRoles are pre-created LOGIN roles with no memberships. The migrator
// grants object access as supivpn_owner; it never creates logins or passwords.
type RuntimeRoles struct {
	Public   string `json:"public"`
	Agent    string `json:"agent"`
	Recovery string `json:"recovery"`
}

func (r RuntimeRoles) Empty() bool { return r == (RuntimeRoles{}) }
func (r RuntimeRoles) Validate() error {
	if r.Empty() {
		return nil
	}
	seen := map[string]bool{}
	for _, name := range []string{r.Public, r.Agent, r.Recovery} {
		if !validName(name) || len(name) > 63 || strings.HasPrefix(name, "pg_") || name == "supivpn_owner" || seen[name] {
			return errors.New("three distinct restricted runtime roles are required")
		}
		seen[name] = true
	}
	return nil
}

func GrantRuntimeRoles(ctx context.Context, pool *pgxpool.Pool, roles RuntimeRoles) error {
	if err := roles.Validate(); err != nil {
		return err
	}
	if roles.Empty() {
		return nil
	}
	refused := errors.New("cannot grant isolated runtime privileges; inspect pre-created roles and ownership")
	tx, err := pool.Begin(ctx)
	if err != nil {
		return refused
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE supivpn_owner; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='10s'"); err != nil {
		return refused
	}
	// Table-level REVOKE does not remove previously granted column privileges.
	rows, err := tx.Query(ctx, `SELECT n.nspname,c.relname,array_agg(a.attname::text ORDER BY a.attnum)
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
        WHERE c.relkind IN ('r','p','v','m','f') AND (n.nspname='supivpn' OR
        (n.nspname='public' AND c.relname='supivpn_schema_migrations')) GROUP BY n.nspname,c.relname`)
	if err != nil {
		return refused
	}
	columnRevokes := []string{}
	var schema, table string
	var columns []string
	_, err = pgx.ForEachRow(rows, []any{&schema, &table, &columns}, func() error {
		for i, column := range columns {
			columns[i] = pgx.Identifier{column}.Sanitize()
		}
		columnRevokes = append(columnRevokes, "REVOKE ALL ("+strings.Join(columns, ",")+") ON "+pgx.Identifier{schema, table}.Sanitize()+" FROM ")
		return nil
	})
	if err != nil {
		return refused
	}
	for component, name := range map[Component]string{Public: roles.Public, AgentAPI: roles.Agent, Recovery: roles.Recovery} {
		var safe bool
		if tx.QueryRow(ctx, `SELECT rolcanlogin AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
            AND NOT EXISTS (SELECT 1 FROM pg_roles x WHERE x.oid<>r.oid AND pg_has_role(r.oid,x.oid,'MEMBER'))
            FROM pg_roles r WHERE rolname=$1`, name).Scan(&safe) != nil || !safe {
			return refused
		}
		role := pgx.Identifier{name}.Sanitize()
		for _, stmt := range columnRevokes {
			if _, err = tx.Exec(ctx, stmt+role); err != nil {
				return refused
			}
		}
		for _, stmt := range []string{
			"REVOKE ALL ON ALL TABLES IN SCHEMA supivpn FROM " + role,
			"REVOKE ALL ON ALL SEQUENCES IN SCHEMA supivpn FROM " + role,
			"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA supivpn FROM " + role,
			"REVOKE ALL ON public.supivpn_schema_migrations FROM " + role,
			"GRANT USAGE ON SCHEMA supivpn,public TO " + role,
		} {
			if _, err = tx.Exec(ctx, stmt); err != nil {
				return refused
			}
		}
		policy, _ := componentPrivileges(component)
		for table, rights := range policy.tables {
			if _, err = tx.Exec(ctx, "GRANT "+strings.Join(rights, ",")+" ON "+table+" TO "+role); err != nil {
				return refused
			}
		}
		for table, grants := range policy.columns {
			for right, columns := range grants {
				if _, err = tx.Exec(ctx, "GRANT "+right+" ("+strings.Join(columns, ",")+") ON "+table+" TO "+role); err != nil {
					return refused
				}
			}
		}
		for _, f := range policy.functions {
			if _, err = tx.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+f+" TO "+role); err != nil {
				return refused
			}
		}
		for _, seq := range policy.sequences {
			if _, err = tx.Exec(ctx, "GRANT USAGE ON SEQUENCE "+seq+" TO "+role); err != nil {
				return refused
			}
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return refused
	}
	return nil
}

func (s *Store) pruneIsolated(ctx context.Context, limit int) (int64, error) {
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, publicError(err)
	}
	defer tx.Rollback(context.Background())
	var total int64
	if err = tx.QueryRow(ctx, "SELECT supivpn.prune_auth($1)", limit).Scan(&total); err != nil {
		return 0, publicError(err)
	}
	if err = pruneRecoveryAttempts(ctx, tx, limit); err != nil {
		return 0, publicError(err)
	}
	return total, publicError(tx.Commit(ctx))
}

func pruneRecoveryAttempts(ctx context.Context, tx pgx.Tx, limit int) error {
	for _, table := range []string{"node_recovery_starts", "node_recovery_stops"} {
		_, err := tx.Exec(ctx, `WITH expired AS (SELECT node_id,attempted_at FROM supivpn.`+table+`
            WHERE attempted_at<(SELECT clock_timestamp()-interval '24 hours') ORDER BY attempted_at LIMIT $1 FOR UPDATE SKIP LOCKED)
            DELETE FROM supivpn.`+table+` s USING expired e WHERE s.node_id=e.node_id AND s.attempted_at=e.attempted_at`, limit)
		if err != nil {
			return err
		}
	}
	return nil
}
