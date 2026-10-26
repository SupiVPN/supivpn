// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/jackc/pgx/v5"
	"supivpn/internal/controller"
	"supivpn/internal/profile"
	"time"
)

func (s *Store) CreateImport(ctx context.Context, token string, owner profile.Owner) error {
	if len(token) != 43 || !validTicket(token) || !owner.Valid() {
		return ErrConflict
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return publicError(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7273182103)"); err != nil {
		return publicError(err)
	}
	if _, err = tx.Exec(ctx, "DELETE FROM supivpn.profile_imports WHERE expires_at<=clock_timestamp()"); err != nil {
		return publicError(err)
	}
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM supivpn.profile_imports").Scan(&count); err != nil {
		return publicError(err)
	}
	if count >= 256 {
		return controller.ErrUnavailable
	}
	hash := sha256.Sum256([]byte(token))
	_, err = tx.Exec(ctx, `INSERT INTO supivpn.profile_imports(token_hash,subject_hash,owner_username,expires_at) VALUES ($1,$2,$3,clock_timestamp()+interval '60 seconds')`, hash[:], owner.SubjectHash[:], owner.Username)
	if err != nil {
		return publicError(err)
	}
	return publicError(tx.Commit(ctx))
}

func (s *Store) ConsumeImport(ctx context.Context, token string) (profile.Owner, error) {
	var subject profile.Owner
	if s == nil || s.pool == nil {
		return subject, controller.ErrUnavailable
	}
	if len(token) != 43 || !validTicket(token) {
		return subject, controller.ErrLoginExpired
	}
	hash := sha256.Sum256([]byte(token))
	tx, err := s.begin(ctx)
	if err != nil {
		return subject, publicError(err)
	}
	defer tx.Rollback(context.Background())
	var raw []byte
	var expires time.Time
	// DELETE acquires the row lock without expanding the public role's grants.
	// Its predicate may be evaluated before a lock wait: check a fresh database
	// clock afterwards, then commit before disclosing the subject to the issuer.
	err = tx.QueryRow(ctx, `DELETE FROM supivpn.profile_imports WHERE token_hash=$1 RETURNING subject_hash,expires_at,owner_username`, hash[:]).Scan(&raw, &expires, &subject.Username)
	if errors.Is(err, pgx.ErrNoRows) {
		return subject, controller.ErrLoginExpired
	}
	if err != nil || len(raw) != 32 {
		return subject, controller.ErrUnavailable
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return subject, controller.ErrUnavailable
	}
	if !now.Before(expires) {
		return subject, controller.ErrLoginExpired
	}
	if err = tx.Commit(ctx); err != nil {
		return subject, controller.ErrUnavailable
	}
	copy(subject.SubjectHash[:], raw)
	if !subject.Valid() {
		return profile.Owner{}, controller.ErrUnavailable
	}
	return subject, nil
}
