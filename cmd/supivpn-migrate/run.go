// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"supivpn/internal/awsruntime"
	"supivpn/internal/postgres"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// Contains identifiers only. Credentials are retrieved into memory by the SDK.
type migrationConfig struct {
    RuntimeRoles postgres.RuntimeRoles `json:"runtime_roles,omitempty"`
	DatabaseTLS *postgres.TLSConfig `json:"database_tls,omitempty"`
	Region    string `json:"region"`
	Host      string `json:"host"`
	Port      string `json:"port"`
	Database  string `json:"database"`
	SecretARN string `json:"secret_arn"`
}

func readConfig(path string) (migrationConfig, error) {
	var c migrationConfig
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("Migration configuration unavailable.")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, errors.New("Invalid migration configuration.")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || c.Region == "" ||
		!strings.HasPrefix(c.SecretARN, "arn:aws:secretsmanager:"+c.Region+":") {
		return c, errors.New("Invalid migration configuration.")
	}
	if _, err = awsruntime.MigrationDSN(c.Host, c.Port, c.Database); err != nil {
		return c, errors.New("Invalid migration database endpoint.")
	}
	if err = c.DatabaseTLS.Validate(); err != nil {
		return c, err
	}
    if err=c.RuntimeRoles.Validate();err!=nil{return c,err}
	return c, nil
}

func run(ctx context.Context, path, expectedDigest, dsn string,roleOptions ...postgres.RuntimeRoles) error {
    var roles postgres.RuntimeRoles
    if len(roleOptions)>1{return errors.New("Multiple runtime role configurations.")}
    if len(roleOptions)==1{roles=roleOptions[0]}
    if err:=roles.Validate();err!=nil{return err}
	// Check before retrieving secrets or opening any database connection.
	if expectedDigest != "" && expectedDigest != postgres.MigrationDigest() {
		return errors.New("Migration binary is stale; rebuild supivpn-migrate from the current SQL sources.")
	}
	var password func(context.Context) (string, error)
	var databaseTLS *postgres.TLSConfig
	if path != "" {
		if dsn != "" {
			return errors.New("Use either migration configuration or SUPIVPN_DATABASE_URL, not both.")
		}
		c, err := readConfig(path)
		if err != nil {
			return err
		}
		databaseTLS = c.DatabaseTLS
        if !c.RuntimeRoles.Empty(){if !roles.Empty(){return errors.New("Use one runtime role configuration.")};roles=c.RuntimeRoles}
		dsn, err = awsruntime.MigrationDSN(c.Host, c.Port, c.Database)
		if err != nil {
			return errors.New("Invalid migration database endpoint.")
		}
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(c.Region), config.WithRetryMaxAttempts(2))
		if err != nil {
			return errors.New("AWS migration configuration unavailable.")
		}
		password = awsruntime.MigrationPassword(secretsmanager.NewFromConfig(cfg), c.SecretARN)
	}
	pool, err := postgres.OpenWithTLS(ctx, dsn, password, databaseTLS)
	if err != nil {
		return errors.New("Migration database configuration invalid.")
	}
	defer pool.Close()
	// IAM propagation and initial DB connectivity may lag provisioning. Retry
	// only connection checks; never silently retry a migration/ambiguous commit.
	readyCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err = awaitDatabase(readyCtx, pool.Ping, 2*time.Second); err != nil {
		return err
	}
	migrationCtx, migrationCancel := context.WithTimeout(ctx, 60*time.Second)
	defer migrationCancel()
	if err = postgres.MigrateAsOwner(migrationCtx, pool); err != nil {
		return errors.New("Database migration failed; check SET ROLE supivpn_owner, existing object owners and migration version.")
	}
	return postgres.GrantRuntimeRoles(migrationCtx,pool,roles)
}

func awaitDatabase(ctx context.Context, ping func(context.Context) error, interval time.Duration) error {
	for {
		attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := ping(attempt)
		cancel()
		if err == nil {
			return nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("Migration database unavailable; check network, TLS and migration-secret permissions.")
		case <-timer.C:
		}
	}
}
