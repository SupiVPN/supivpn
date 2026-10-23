// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"context"
	"errors"
	"net/url"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/operatorapi"
	"supivpn/internal/postgres"
)

func OpenAgent(ctx context.Context, c Config, dsn string, password func(context.Context) (string, error)) (*Application, error) {
	if c.PendingSeconds < 30 || c.PendingSeconds > 180 || c.Gateway == nil || c.Profile != nil || c.IDPMetadata != "" || len(c.Groups) != 0 || c.VM != nil || c.AssertionEncryption != nil {
		return nil, errors.New("agent component requires only gateway, public URL, pending limit and database TLS configuration")
	}
	origin, err := url.Parse(c.PublicURL)
	if err != nil {
		return nil, errors.New("invalid public origin")
	}
	pool, err := postgres.OpenWithTLS(ctx, dsn, password, c.DatabaseTLS)
	if err != nil {
		return nil, err
	}
	store, err := postgres.NewIsolated(ctx, pool, postgres.AgentAPI, nil)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &Application{Agents: Bounded(agentapi.New(store, time.Duration(c.PendingSeconds)*time.Second)), Origin: origin, pool: pool, store: store}, nil
}

// Recovery has no HTTP gateway, SAML metadata, profile issuer or wrapping key.
func OpenRecovery(ctx context.Context, dsn string, password func(context.Context) (string, error), tls *postgres.TLSConfig, f postgres.Fencer) (*Application, error) {
	if f == nil {
		return nil, errors.New("recovery requires a power observer")
	}
	pool, err := postgres.OpenWithTLS(ctx, dsn, password, tls)
	if err != nil {
		return nil, err
	}
	store, err := postgres.NewIsolated(ctx, pool, postgres.Recovery, f)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &Application{Operations: operatorapi.Handler(store), pool: pool, store: store}, nil
}

func (a *Application) Reconcile(ctx context.Context) error {
	// Recovery never waits for authentication cleanup to decide whether a node
	// is eligible. Each invocation advances at most one bounded recovery step.
	if err := a.store.FenceExpired(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := a.store.Prune(ctx, 100)
	return err
}
