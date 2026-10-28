// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"supivpn/internal/controller"
	"supivpn/internal/profile"
	"time"
)

type ProfileState struct {
	ID            string    `json:"profile_id"`
	State         string    `json:"state"`
	Revision      int64     `json:"revision"`
	CreatedAt     time.Time `json:"created_at"`
	OwnerUsername string    `json:"owner_username"`
}

// ProfileSchemaReady gates runtime admission, which requires the persistent
// owner registry and owner labels. Historical migrations retain older schemas.
func (s *Store) ProfileSchemaReady(ctx context.Context) bool {
	if s == nil || s.pool == nil {
		return false
	}
	var version int
	return s.pool.QueryRow(ctx, "SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&version) == nil && version == 12
}

func (s *Store) ProfileState(ctx context.Context, id string) (ProfileState, error) {
	var p ProfileState
	if !profile.ValidProfileID(id) {
		return p, ErrConflict
	}
	if s == nil || s.pool == nil {
		return p, controller.ErrUnavailable
	}
	err := s.pool.QueryRow(ctx, `SELECT profile_id,state,revision,created_at,owner_username FROM supivpn.issued_profiles WHERE profile_id=$1`, id).Scan(&p.ID, &p.State, &p.Revision, &p.CreatedAt, &p.OwnerUsername)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrConflict
	}
	return p, publicError(err)
}

func (s *Store) operateProfile(ctx context.Context, q OperatorRequest) (OperatorState, error) {
	var out OperatorState
	if q.AfterID != "" || q.Limit != 0 {
		return out, ErrConflict
	}
	if !profile.ValidProfileID(q.ProfileID) || q.NodeID != "" || q.ExpectedGeneration != "" || q.RecoveryID != "" || q.MaintenanceID != "" || q.RequestID != "" || q.Reason != "" {
		return out, ErrConflict
	}
	switch q.Action {
	case "profile-status":
		if q.ExpectedRevision != 0 {
			return out, ErrConflict
		}
	case "profile-block", "profile-activate":
		state := "blocked"
		if q.Action == "profile-activate" {
			state = "active"
		}
		if _, err := s.SetProfileState(ctx, q.ProfileID, state, q.ExpectedRevision); err != nil {
			return out, err
		}
	default:
		return out, ErrConflict
	}
	p, err := s.ProfileState(ctx, q.ProfileID)
	if err != nil {
		return out, err
	}
	out.Profile = &p
	out.Exists = true
	out.SchemaVersion = 12
	return out, nil
}

// ListProfiles is a bounded local operator query. It deliberately excludes
// ownership and proof hashes, but includes the verified owner label. The
// primary-key cursor avoids unbounded offsets.
// It is not dispatched by Operate (the recovery Lambda protocol).
func (s *Store) ListProfiles(ctx context.Context, q OperatorRequest) (OperatorState, error) {
	var out OperatorState
	if q.Action != "profile-list" || q.Limit < 1 || q.Limit > 100 ||
		q.AfterID != "" && !profile.ValidProfileID(q.AfterID) || q.ProfileID != "" ||
		q.NodeID != "" || q.ExpectedGeneration != "" || q.RecoveryID != "" ||
		q.ExpectedRevision != 0 || q.MaintenanceID != "" || q.RequestID != "" || q.Reason != "" {
		return out, ErrConflict
	}
	if s == nil || s.pool == nil {
		return out, controller.ErrUnavailable
	}
	rows, err := s.pool.Query(ctx, `SELECT profile_id,state,revision,created_at,owner_username
		FROM supivpn.issued_profiles WHERE profile_id>$1 ORDER BY profile_id LIMIT $2`, q.AfterID, q.Limit+1)
	if err != nil {
		return out, publicError(err)
	}
	defer rows.Close()
	out.SchemaVersion = 12
	for rows.Next() {
		var p ProfileState
		if err = rows.Scan(&p.ID, &p.State, &p.Revision, &p.CreatedAt, &p.OwnerUsername); err != nil {
			return OperatorState{}, publicError(err)
		}
		if len(out.Profiles) == q.Limit {
			out.NextCursor = out.Profiles[len(out.Profiles)-1].ID
			break
		}
		out.Profiles = append(out.Profiles, p)
	}
	return out, publicError(rows.Err())
}

func (s *Store) CreateProfile(ctx context.Context, c profile.Credential, owner profile.Owner) error {
	digest, err := c.Digest()
	if err != nil || !owner.Valid() {
		return ErrConflict
	}
	if s == nil || s.pool == nil {
		return controller.ErrUnavailable
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO supivpn.issued_profiles(profile_id,secret_hash,subject_hash,owner_username) VALUES ($1,$2,$3,$4)`, c.ID, digest[:], owner.SubjectHash[:], owner.Username)
	return publicError(err)
}

func (s *Store) RegisterProfile(ctx context.Context, a Agent, c Connection, ticket string, lifetime time.Duration, proof profile.Credential) error {
	if !proof.Valid() {
		return ErrConflict
	}
	return s.register(ctx, a, c, ticket, lifetime, &proof)
}

func loginProfile(ctx context.Context, tx pgx.Tx, hash []byte) (string, error) {
	var version int
	if err := tx.QueryRow(ctx, "SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&version); err != nil {
		return "", err
	}
	if version < 11 {
		return "", nil
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT profile_id FROM supivpn.profile_bindings WHERE ticket_hash=$1`, hash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (s *Store) activeLoginProfile(ctx context.Context, tx pgx.Tx, hash []byte) error {
	id, err := loginProfile(ctx, tx, hash)
	if err != nil {
		return err
	}
	if id == "" {
		return controller.ErrLoginExpired
	}
	var active bool
	// The combined VM role uses its existing table privileges. Isolated
	// components retain the narrow security-definer API and its row locking.
	query := "SELECT state='active' FROM supivpn.issued_profiles WHERE profile_id=$1 FOR SHARE"
	if s.component != "" {
		query = "SELECT supivpn.profile_is_active($1)"
	}
	err = tx.QueryRow(ctx, query, id).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return controller.ErrLoginExpired
	}
	if err != nil {
		return err
	}
	if !active {
		return controller.ErrLoginExpired
	}
	return nil
}

func (s *Store) profileOwnerActive(ctx context.Context, tx pgx.Tx, id string, subject [32]byte) (bool, error) {
	var active bool
	query := "SELECT state='active' AND subject_hash=$2 FROM supivpn.issued_profiles WHERE profile_id=$1 FOR SHARE"
	if s.component != "" {
		query = "SELECT supivpn.profile_owner_active($1,$2)"
	}
	err := tx.QueryRow(ctx, query, id, subject[:]).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return active, err
}

// Recover the label of an existing profile only after its owner passed SAML and
// admission policy. Never replace an existing label, proof, owner or revision.
// Admission already holds a shared row lock. SKIP LOCKED avoids a lock-upgrade
// deadlock with concurrent admissions; a later login can retry the audit label.
func recordProfileOwner(ctx context.Context, tx pgx.Tx, id string, d controller.Authorization) error {
	_, err := tx.Exec(ctx, `WITH target AS (
        SELECT profile_id FROM supivpn.issued_profiles
        WHERE profile_id=$1 AND subject_hash=$2 AND owner_username='' AND state='active'
        FOR UPDATE SKIP LOCKED
    ) UPDATE supivpn.issued_profiles p SET owner_username=$3
      FROM target t WHERE p.profile_id=t.profile_id`, id, d.SubjectHash[:], d.Username)
	return err
}

// SetProfileState is an operator compare-and-swap. Blocking prevents admission;
// existing tunnels are handled by the existing session termination operation.
func (s *Store) SetProfileState(ctx context.Context, id, state string, revision int64) (int64, error) {
	if !profile.ValidProfileID(id) || state != "active" && state != "blocked" || revision < 1 {
		return 0, ErrConflict
	}
	if s == nil || s.pool == nil {
		return 0, controller.ErrUnavailable
	}
	var next int64
	err := s.pool.QueryRow(ctx, `UPDATE supivpn.issued_profiles SET state=$2,revision=revision+1 WHERE profile_id=$1 AND revision=$3 RETURNING revision`, id, state, revision).Scan(&next)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrConflict
	}
	return next, publicError(err)
}
