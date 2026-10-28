// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/controller"
	"supivpn/internal/profile"
)

var (
	ErrConflict   = errors.New("conflicting registration or acknowledgement")
	ErrGeneration = errors.New("agent generation is no longer current")
	ErrNoDecision = errors.New("decision not available")
)

type Agent struct{ NodeID, Generation string }
type Connection struct{ CID, KID int64 }
type Outcome string

const (
	Applied Outcome = "applied"
	Denied  Outcome = "denied"
	Failed  Outcome = "failed"
)

// Decision is returned only through an authenticated agent adapter. The adapter
// must derive NodeID from that identity, never from an untrusted request body.
// The agent deduplicates ID and checks generation, CID/KID and time bounds before
// applying anything; database commit is not an OpenVPN acknowledgement.
type Decision struct {
	Username                    string
	SubjectHash                 [32]byte
	SessionUnlimited            bool
	ID                          string
	Agent                       Agent
	Connection                  Connection
	GroupName, DenialReason     string
	ExpiresAt, SessionExpiresAt time.Time
}

type Store struct {
	pool      *pgxpool.Pool
	fencer    Fencer
	component Component
}

var _ controller.Backend = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func NewWithFencer(pool *pgxpool.Pool, f Fencer) *Store { return &Store{pool: pool, fencer: f} }

// All database/driver errors are deliberately opaque: they may contain query
// arguments, connection credentials or user data. Callers must not log raw errors.
func publicError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrConflict, ErrGeneration, ErrNoDecision,
		controller.ErrLoginExpired, controller.ErrLoginStarted,
		controller.ErrDecisionPending, controller.ErrGroupDenied, controller.ErrConnectionLimit, controller.ErrConnectionRetry} {
		if errors.Is(err, known) {
			return known
		}
	}
	return controller.ErrUnavailable
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func validAgent(a Agent) bool         { return validName(a.NodeID) && validName(a.Generation) }
func validTicket(s string) bool       { return len(s) >= 32 && validName(s) }
func ticketHash(ticket string) []byte { h := sha256.Sum256([]byte(ticket)); return h[:] }

func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	if s == nil || s.pool == nil {
		return nil, controller.ErrUnavailable
	}
	return s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

func (s *Store) Ready(ctx context.Context) bool {
	if s == nil || s.pool == nil {
		return false
	}
	var version int
	return s.pool.QueryRow(ctx, "SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&version) == nil &&
		((s.component == "" && (version == 7 || version == 8 || version == 9 || version == 10 || version == 11 || version == 12)) || (s.component != "" && version == 12))
}

// RotateNode is a compare-and-swap performed by the authenticated node bootstrap
// adapter. Empty previous creates the first generation; retries of the same
// transition succeed. An old generation cannot replace a newer one by replay.
// Rotation also fences all outstanding requests of the previous generation.
func (s *Store) RotateNode(ctx context.Context, nodeID, previous, next string) error {
	if !validName(nodeID) || !validName(next) || previous != "" && !validName(previous) || previous == next {
		return ErrConflict
	}
	if s.component != "" {
		var ok bool
		err := s.pool.QueryRow(ctx, "SELECT supivpn.agent_rotate($1,$2,$3)", nodeID, previous, next).Scan(&ok)
		if err != nil {
			return publicError(err)
		}
		if !ok {
			return ErrGeneration
		}
		return nil
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return publicError(err)
	}
	defer tx.Rollback(context.Background())
	tag, err := tx.Exec(ctx, `
        INSERT INTO supivpn.nodes(node_id, generation)
        SELECT $1, $3 WHERE $2 = '' ON CONFLICT DO NOTHING
    `, nodeID, previous, next)
	if err != nil {
		return publicError(err)
	}
	created := tag.RowsAffected() == 1
	var current, fenceState string
	err = tx.QueryRow(ctx, "SELECT generation,fence_state FROM supivpn.nodes WHERE node_id=$1 FOR UPDATE", nodeID).Scan(&current, &fenceState)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrGeneration
	}
	if err != nil {
		return publicError(err)
	}
	if fenceState == "stopping" || fenceState == "stopped" && current == next {
		return ErrGeneration
	}
	if !created && current == next {
		return publicError(tx.Commit(ctx))
	}
	if !created && current != previous {
		return ErrGeneration
	}
	tag, err = tx.Exec(ctx, `INSERT INTO supivpn.node_generations(node_id,generation)
        VALUES ($1,$2) ON CONFLICT DO NOTHING`, nodeID, next)
	if err != nil {
		return publicError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrGeneration
	}
	if _, err = tx.Exec(ctx, "UPDATE supivpn.nodes SET generation=$2,lease_expires_at=clock_timestamp()+interval '60 seconds',fence_state='ready',fence_retry_at='epoch',healthy_since=NULL WHERE node_id=$1", nodeID, next); err != nil {
		return publicError(err)
	}
	return publicError(tx.Commit(ctx))
}

func (s *Store) lockNode(ctx context.Context, tx pgx.Tx, nodeID string) (string, error) {
	var generation string
	query := "SELECT generation FROM supivpn.nodes WHERE node_id=$1 FOR SHARE"
	if s.component != "" {
		query = "SELECT generation FROM supivpn.lock_node($1) AS generation WHERE generation IS NOT NULL"
	}
	err := tx.QueryRow(ctx, query, nodeID).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrGeneration
	}
	return generation, err
}

// Register refuses the removed unbound protocol, including callers using an
// older API adapter. RegisterProfile is the only supported admission path.
func (s *Store) Register(ctx context.Context, a Agent, c Connection, ticket string, lifetime time.Duration) error {
	return ErrConflict
}

func (s *Store) register(ctx context.Context, a Agent, c Connection, ticket string, lifetime time.Duration, proof *profile.Credential) error {
	if !validAgent(a) || !validTicket(ticket) || c.CID < 0 || c.KID < 0 ||
		lifetime < 30*time.Second || lifetime > 180*time.Second {
		return ErrConflict
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return publicError(err)
	}
	defer tx.Rollback(context.Background())
	generation, err := s.lockNode(ctx, tx, a.NodeID)
	if err != nil {
		return publicError(err)
	}
	if generation != a.Generation {
		return ErrGeneration
	}
	if err = liveNode(ctx, tx, a); err != nil {
		return publicError(err)
	}
	hash := ticketHash(ticket)
	inserted, err := tx.Exec(ctx, `
        INSERT INTO supivpn.logins(ticket_hash,node_id,generation,cid,kid,expires_at)
        VALUES ($1,$2,$3,$4,$5,clock_timestamp()+$6*interval '1 microsecond')
        ON CONFLICT DO NOTHING
    `, hash, a.NodeID, a.Generation, c.CID, c.KID, lifetime.Microseconds())
	if err != nil {
		return publicError(err)
	}
	r, err := loadRecord(ctx, tx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return publicError(err)
	}
	if r.agent != a || r.conn != c {
		return ErrConflict
	}
	profileID := ""
	if proof != nil {
		digest, e := proof.Digest()
		if e != nil {
			return ErrConflict
		}
		var valid bool
		query := "SELECT state='active' AND secret_hash=$2 FROM supivpn.issued_profiles WHERE profile_id=$1 FOR SHARE"
		if s.component != "" {
			query = "SELECT supivpn.profile_proof_valid($1,$2)"
		}
		err = tx.QueryRow(ctx, query, proof.ID, digest[:]).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) {
			return controller.ErrLoginExpired
		}
		if err != nil {
			return publicError(err)
		}
		if !valid {
			return controller.ErrLoginExpired
		}
		profileID = proof.ID
	}
	if profileID != "" && inserted.RowsAffected() == 1 {
		if _, err = tx.Exec(ctx, "INSERT INTO supivpn.profile_bindings(ticket_hash,profile_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", hash, profileID); err != nil {
			return publicError(err)
		}
	}
	// Do not allow an idempotent retry to change the profile or downgrade it.
	if bound, e := loginProfile(ctx, tx, hash); e != nil {
		return publicError(e)
	} else if bound != profileID {
		return ErrConflict
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return publicError(err)
	}
	if !r.pending(now) {
		return controller.ErrLoginExpired
	}
	if err = tx.Commit(ctx); err != nil {
		return publicError(err)
	}
	logConnection(ctx, "agent.login_registered", hash, a, c)
	return nil
}

type record struct {
	username                              string
	subjectHash                           []byte
	sessionUnlimited                      bool
	agent                                 Agent
	conn                                  Connection
	revision                              int64
	expires                               time.Time
	requestID                             string
	browserHash                           []byte
	state, decisionID, group, denial, ack string
	notBefore, notAfter, sessionExpires   time.Time
}

func (r record) pending(now time.Time) bool {
	return (r.state == "pending" || r.state == "started") && now.Before(r.expires)
}
func (r record) deliverable(now time.Time) bool {
	return r.state == "decided" && now.Before(r.expires) && !now.Before(r.notBefore) &&
		now.Before(r.notAfter) && ((r.sessionUnlimited && r.sessionExpires.IsZero()) || (!r.sessionUnlimited && now.Before(r.sessionExpires)))
}
func (r record) snapshot(ticket string) controller.Pending {
	var hash [32]byte
	copy(hash[:], r.browserHash)
	return controller.Pending{Ticket: ticket, RequestID: r.requestID, BrowserHash: hash,
		ExpiresAt: r.expires, Revision: uint64(r.revision)}
}
func (r record) matches(p controller.Pending) bool {
	return r.revision > 0 && uint64(r.revision) == p.Revision &&
		r.expires.Equal(p.ExpiresAt) && r.requestID == p.RequestID &&
		len(r.browserHash) == 32 && subtle.ConstantTimeCompare(r.browserHash, p.BrowserHash[:]) == 1
}
func dbNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now)
	return now, err
}
func loadRecord(ctx context.Context, tx pgx.Tx, hash []byte) (record, error) {
	var r record
	var sessionExpires *time.Time
	err := tx.QueryRow(ctx, `
        SELECT node_id,generation,cid,kid,revision,expires_at,
               coalesce(request_id,''),coalesce(browser_hash,''::bytea),state,
               coalesce(decision_id,''),group_name,denial_reason,coalesce(ack_result,''),
               coalesce(not_before,'epoch'::timestamptz),
               coalesce(not_after,'epoch'::timestamptz),
                session_expires_at, session_unlimited, subject_hash, coalesce(to_jsonb(logins)->>'username','')
        FROM supivpn.logins WHERE ticket_hash=$1 FOR UPDATE
    `, hash).Scan(&r.agent.NodeID, &r.agent.Generation, &r.conn.CID, &r.conn.KID, &r.revision,
		&r.expires, &r.requestID, &r.browserHash, &r.state, &r.decisionID, &r.group, &r.denial,
		&r.ack, &r.notBefore, &r.notAfter, &sessionExpires, &r.sessionUnlimited, &r.subjectHash, &r.username)
	if sessionExpires != nil {
		r.sessionExpires = *sessionExpires
	}
	return r, err
}

// Every operation locks node -> login, then reads database time AFTER waiting.
// Rotation cannot race past an operation; parallel callbacks serialize on login.
func (s *Store) withLogin(ctx context.Context, hash []byte, actor *Agent,
	fn func(pgx.Tx, record, time.Time) error) error {
	tx, err := s.begin(ctx)
	if err != nil {
		return publicError(err)
	}
	defer tx.Rollback(context.Background())
	var nodeID string
	if actor != nil {
		// Agent operations already have an authenticated node identity. The
		// locked record below must still match that identity and generation.
		nodeID = actor.NodeID
	} else {
		if err = tx.QueryRow(ctx, "SELECT node_id FROM supivpn.logins WHERE ticket_hash=$1", hash).Scan(&nodeID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return controller.ErrLoginExpired
			}
			return publicError(err)
		}
	}
	generation, err := s.lockNode(ctx, tx, nodeID)
	if err != nil {
		return publicError(err)
	}
	r, err := loadRecord(ctx, tx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return controller.ErrLoginExpired
	}
	if err != nil {
		return publicError(err)
	}
	if r.agent.Generation != generation || actor != nil && r.agent != *actor {
		return controller.ErrLoginExpired
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return publicError(err)
	}
	result := fn(tx, r, now)
	if result != nil && !errors.Is(result, controller.ErrDecisionPending) && !errors.Is(result, controller.ErrGroupDenied) && !errors.Is(result, controller.ErrConnectionLimit) && !errors.Is(result, controller.ErrConnectionRetry) {
		return publicError(result)
	}
	if err = tx.Commit(ctx); err != nil {
		return publicError(err)
	}
	return result
}

func (s *Store) Start(ctx context.Context, ticket, requestID string, hash [32]byte) error {
	if !validTicket(ticket) || requestID == "" || len(requestID) > 256 || hash == [32]byte{} {
		return controller.ErrLoginExpired
	}
	return s.withLogin(ctx, ticketHash(ticket), nil, func(tx pgx.Tx, r record, now time.Time) error {
		if !r.pending(now) {
			return controller.ErrLoginExpired
		}
		if r.state == "started" {
			return controller.ErrLoginStarted
		}
		tag, err := tx.Exec(ctx, `UPDATE supivpn.logins SET request_id=$2,browser_hash=$3,state='started'
            WHERE ticket_hash=$1 AND expires_at>clock_timestamp()`, ticketHash(ticket), requestID, hash[:])
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return controller.ErrLoginExpired
		}
		return nil
	})
}
func (s *Store) Lookup(ctx context.Context, ticket string, hash [32]byte) (controller.Pending, error) {
	var pending controller.Pending
	if !validTicket(ticket) {
		return pending, controller.ErrLoginExpired
	}
	err := s.withLogin(ctx, ticketHash(ticket), nil, func(_ pgx.Tx, r record, now time.Time) error {
		if r.state != "started" || !r.pending(now) || len(r.browserHash) != 32 ||
			subtle.ConstantTimeCompare(hash[:], r.browserHash) != 1 {
			return controller.ErrLoginExpired
		}
		pending = r.snapshot(ticket)
		return nil
	})
	return pending, err
}

func normalizeDecision(d controller.Authorization) controller.Authorization {
	// PostgreSQL timestamp precision is microseconds. Round admission start up,
	// and deadlines down, so serialization never widens a validity interval.
	start := d.NotBefore.Truncate(time.Microsecond)
	if start.Before(d.NotBefore) {
		start = start.Add(time.Microsecond)
	}
	d.NotBefore = start
	d.NotOnOrAfter = d.NotOnOrAfter.Truncate(time.Microsecond)
	d.SessionExpiresAt = d.SessionExpiresAt.Truncate(time.Microsecond)
	d.AssertionExpiresAt = d.AssertionExpiresAt.Truncate(time.Microsecond)
	return d
}
func validDecision(d controller.Authorization, now time.Time) bool {
	if d.SubjectHash == [32]byte{} || d.MaxConnections < 1 || d.MaxConnections > 16 ||
		!controller.ValidLogUsername(d.Username) ||
		d.AssertionHash == [32]byte{} || !d.ValidAt(now) ||
		d.AssertionExpiresAt.Before(d.NotOnOrAfter) ||
		len(d.GroupName) > 128 ||
		strings.ContainsAny(d.GroupName, "\r\n\x00") {
		return false
	}
	switch d.DenialReason {
	case "":
		return d.GroupName != "" && strings.TrimSpace(d.GroupName) == d.GroupName
	case "invalid_groups_claim", "no_vpn_group":
		return d.GroupName == ""
	default:
		return false
	}
}

// Both login purposes consume assertions in their existing decision transaction.
// A conflict is a replay, and a failed decision rolls this insert back too.
func consumeAssertion(ctx context.Context, tx pgx.Tx, d controller.Authorization) error {
	tag, err := tx.Exec(ctx, `INSERT INTO supivpn.assertions(assertion_hash,expires_at)
        VALUES ($1,$2) ON CONFLICT DO NOTHING`, d.AssertionHash[:], d.AssertionExpiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return controller.ErrLoginExpired
	}
	return nil
}

func (s *Store) Complete(ctx context.Context, p controller.Pending, d controller.Authorization) error {
	if !validTicket(p.Ticket) || p.Revision > math.MaxInt64 {
		return controller.ErrLoginExpired
	}
	d = normalizeDecision(d)
	hash := ticketHash(p.Ticket)
	return s.withLogin(ctx, hash, nil, func(tx pgx.Tx, r record, now time.Time) error {
		if r.state != "started" || !r.pending(now) || !r.matches(p) || !validDecision(d, now) {
			return controller.ErrLoginExpired
		}
		if err := liveNode(ctx, tx, r.agent); err != nil {
			return err
		}
		// The replay entry and immutable decision are committed together.
		if err := consumeAssertion(ctx, tx, d); err != nil {
			return err
		}
		id, err := loginProfile(ctx, tx, hash)
		if err != nil {
			return err
		} else if id == "" {
			// Also reject pending unbound logins created before the upgrade.
			d.GroupName, d.DenialReason = "", "profile_refused"
		} else {
			ok, err := s.profileOwnerActive(ctx, tx, id, d.SubjectHash)
			if err != nil {
				return err
			}
			if !ok {
				d.GroupName, d.DenialReason = "", "profile_refused"
			}
		}
		if d.DenialReason == "" {
			// Version-2 grants have no subject identity. Until their node is
			// drained/restarted or fenced, admitting anyone could bypass a limit.
			var legacy bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM supivpn.logins l JOIN supivpn.nodes n
				  ON n.node_id=l.node_id AND n.generation=l.generation
				WHERE l.subject_hash IS NULL AND l.denial_reason=''
				  AND l.state IN ('decided','acknowledged')
				  AND (l.ack_result IS NULL OR l.ack_result='applied')
				  AND n.fence_state<>'stopped')`).Scan(&legacy); err != nil {
				return err
			}
			if legacy {
				return controller.ErrUnavailable
			}
			// Serialize admission across controller replicas and ALL nodes/groups.
			// A 64-bit hash collision only serializes unrelated users.
			if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)",
				int64(binary.BigEndian.Uint64(d.SubjectHash[:8]))); err != nil {
				return err
			}
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM supivpn.logins l
				JOIN supivpn.nodes n ON n.node_id=l.node_id AND n.generation=l.generation
				WHERE l.subject_hash=$1 AND l.denial_reason=''
				  AND l.state IN ('decided','acknowledged')
				  AND (l.ack_result IS NULL OR l.ack_result='applied')
				  AND n.fence_state<>'stopped'`, d.SubjectHash[:]).Scan(&count); err != nil {
				return err
			}
			if count >= d.MaxConnections {
				d.GroupName, d.DenialReason = "", "connection_limit"
				retry, err := transportRetryAllowed(ctx, tx, r.conn.CID, id, d.SubjectHash)
				if err != nil {
					return err
				}
				if retry {
					d.DenialReason = controller.ConnectionRetryReason
				}
			}
		}
		profileID := id
		id = rand.Text()
		var sessionExpires any
		if !d.SessionUnlimited {
			sessionExpires = d.SessionExpiresAt
		}
		tag, err := tx.Exec(ctx, `UPDATE supivpn.logins
            SET state='decided',decision_id=$2,group_name=$3,denial_reason=$4,
                not_before=$5,not_after=$6,session_expires_at=$7,subject_hash=$8,session_unlimited=$9
            WHERE ticket_hash=$1 AND expires_at>clock_timestamp()
                AND clock_timestamp()>=$5 AND clock_timestamp()<$6 AND ($9 OR clock_timestamp()<$7)`,
			hash, id, d.GroupName, d.DenialReason, d.NotBefore, d.NotOnOrAfter, sessionExpires, d.SubjectHash[:], d.SessionUnlimited)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return controller.ErrLoginExpired
		}
		// loadRecord already holds a table lock until commit: migration 8 cannot
		// commit between this schema check and the optional audit-field write.
		var version int
		if err = tx.QueryRow(ctx, "SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&version); err != nil {
			return err
		}
		if version != 7 && version != 8 && version != 9 && version != 10 && version != 11 && version != 12 {
			return controller.ErrUnavailable
		}
		if version >= 8 {
			if _, err = tx.Exec(ctx, "UPDATE supivpn.logins SET username=$2 WHERE ticket_hash=$1", hash, d.Username); err != nil {
				return err
			}
		}
		if d.DenialReason == controller.ConnectionRetryReason {
			return controller.ErrConnectionRetry
		}
		if d.DenialReason == "connection_limit" {
			return controller.ErrConnectionLimit
		}
		if d.DenialReason != "" {
			return controller.ErrGroupDenied
		}
		if version >= 12 && profileID != "" && d.Username != "" {
			if err := recordProfileOwner(ctx, tx, profileID, d); err != nil {
				return err
			}
		}
		return controller.ErrDecisionPending
	})
}
