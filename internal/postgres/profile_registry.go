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
	ID        string    `json:"profile_id"`
	State     string    `json:"state"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
}

// ProfileSchemaReady gates opt-in profile features even in a VM deployment
// whose legacy authorization can still run against an older supported schema.
func (s *Store) ProfileSchemaReady(ctx context.Context) bool {
	if s == nil || s.pool == nil {
		return false
	}
	var version int
	return s.pool.QueryRow(ctx, "SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&version) == nil && version == 11
}

func (s *Store) ProfileState(ctx context.Context, id string) (ProfileState, error) {
	var p ProfileState
	if !profile.ValidProfileID(id) {
		return p, ErrConflict
	}
	if s == nil || s.pool == nil {
		return p, controller.ErrUnavailable
	}
	err := s.pool.QueryRow(ctx, `SELECT profile_id,state,revision,created_at FROM supivpn.issued_profiles WHERE profile_id=$1`, id).Scan(&p.ID, &p.State, &p.Revision, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrConflict
	}
	return p, publicError(err)
}

func (s *Store) operateProfile(ctx context.Context, q OperatorRequest) (OperatorState, error) {
	var out OperatorState
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
	out.SchemaVersion = 11
	return out, nil
}

func (s *Store) CreateProfile(ctx context.Context, c profile.Credential, subject [32]byte) error {
	digest, err := c.Digest()
	if err != nil || subject == [32]byte{} {
		return ErrConflict
	}
	if s == nil || s.pool == nil {
		return controller.ErrUnavailable
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO supivpn.issued_profiles(profile_id,secret_hash,subject_hash) VALUES ($1,$2,$3)`, c.ID, digest[:], subject[:])
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

func activeLoginProfile(ctx context.Context, tx pgx.Tx, hash []byte) error {
	id, err := loginProfile(ctx, tx, hash)
	if err != nil || id == "" {
		return err
	}
	var active bool
	if err = tx.QueryRow(ctx, "SELECT supivpn.profile_is_active($1)", id).Scan(&active); err != nil {
		return err
	}
	if !active {
		return controller.ErrLoginExpired
	}
	return nil
}

func profileOwnerActive(ctx context.Context, tx pgx.Tx, id string, subject [32]byte) (bool, error) {
	var active bool
	err := tx.QueryRow(ctx, `SELECT supivpn.profile_owner_active($1,$2)`, id, subject[:]).Scan(&active)
	return active, err
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
