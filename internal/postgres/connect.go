// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a small bounded pool for either Lambda or a VM. The DSN is supplied
// by the deployment adapter and must never be printed. There is no RDS-specific
// extension, proxy or secret retrieval here. Non-loopback TCP requires TLS;
// sslmode=require deliberately permits encryption without server verification.
// Connections are established on demand, so a temporary outage at startup does
// not permanently discard the pool. Ready must gate admission before serving.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	return OpenWithPassword(ctx, dsn, nil)
}

// OpenWithPassword retrieves credentials only when establishing a physical
// connection. This also covers replacement connections after failure/rotation.
func OpenWithPassword(ctx context.Context, dsn string, password func(context.Context) (string, error)) (*pgxpool.Pool, error) {
	return OpenWithTLS(ctx, dsn, password, nil)
}

// OpenWithTLS applies the same TLS policy to initial and replacement connections.
// server_name changes certificate verification/SNI, never the DNS/dial address.
func OpenWithTLS(ctx context.Context, dsn string, password func(context.Context) (string, error), options *TLSConfig) (*pgxpool.Pool, error) {
	config, err := poolConfigWithTLS(dsn, options)
	if err != nil {
		return nil, err
	}
	if password != nil {
		config.BeforeConnect = func(ctx context.Context, c *pgx.ConnConfig) error {
			value, err := password(ctx)
			if err != nil || value == "" {
				return errors.New("database credential unavailable")
			}
			c.Password = value
			return nil
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("cannot create PostgreSQL pool")
	}
	return pool, nil
}
func poolConfig(dsn string) (*pgxpool.Config, error) {
	return poolConfigWithTLS(dsn, nil)
}

func poolConfigWithTLS(dsn string, options *TLSConfig) (*pgxpool.Config, error) {
	if dsn == "" {
		return nil, errors.New("database configuration required")
	}
	dsn, err := options.connectionString(dsn)
	if err != nil {
		return nil, err
	}
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	// Test databases use a literal loopback address. Hostnames (even localhost)
	// and Unix sockets do not silently opt out of production TLS requirements.
	ip := net.ParseIP(c.ConnConfig.Host)
	loopback := ip != nil && ip.IsLoopback()
	tlsConfig := c.ConnConfig.TLSConfig
	if !loopback && tlsConfig == nil {
		return nil, errors.New("PostgreSQL requires TLS")
	}
	if len(c.ConnConfig.Fallbacks) != 0 {
		return nil, errors.New("PostgreSQL connection fallbacks are disabled")
	}
	if tlsConfig != nil {
		tlsConfig.MinVersion = tls.VersionTLS12
		if options != nil && options.ServerName != "" {
			tlsConfig.ServerName = options.ServerName
		}
	}
	if options != nil && (tlsConfig == nil ||
		(options.mode() == "verify-full" && (tlsConfig.InsecureSkipVerify || tlsConfig.ServerName == ""))) {
		return nil, errors.New("database TLS configuration did not enforce the selected mode")
	}
	c.MaxConns = 4
	c.MinConns = 0
	c.MinIdleConns = 0
	c.MaxConnLifetime = 30 * time.Minute
	c.MaxConnLifetimeJitter = 5 * time.Minute
	c.MaxConnIdleTime = time.Minute
	c.HealthCheckPeriod = 15 * time.Second
	c.ConnConfig.ConnectTimeout = 5 * time.Second
	// Each physical connection resolves the configured hostname afresh. Never
	// cache a writer IP here. Reject a reachable server that cannot accept writes.
	c.ConnConfig.ValidateConnect = pgconn.ValidateConnectTargetSessionAttrsReadWrite
	// PrepareConn performs a bounded round trip even for recently used sockets.
	// A dead/read-only socket is discarded BEFORE any application SQL is sent;
	// pgxpool then tries another/new connection (at most MaxConns+1 attempts).
	// Do not wrap Query/Exec/Commit in retries: their outcome may be unknown.
	c.ShouldPing = func(context.Context, pgxpool.ShouldPingParams) bool { return false }
	c.PrepareConn = func(ctx context.Context, conn *pgx.Conn) (bool, error) {
		check, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var readOnly string
		err := conn.QueryRow(check, "SHOW transaction_read_only").Scan(&readOnly)
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return err == nil && readOnly == "off", nil
	}
	c.ConnConfig.RuntimeParams["statement_timeout"] = "5000"
	c.ConnConfig.RuntimeParams["lock_timeout"] = "2000"
	c.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "5000"
	c.ConnConfig.RuntimeParams["application_name"] = "supivpn-controller"
	return c, nil
}
