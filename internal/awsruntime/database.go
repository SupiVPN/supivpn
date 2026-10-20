// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package awsruntime supplies AWS-only deployment adapters. Core authentication,
// VM serving and PostgreSQL storage do not depend on Secrets Manager.
package awsruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const DatabaseUser = "supivpn_runtime"
const MigrationUser = "supivpn_migrator"

type SecretAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

func DatabaseDSN(host, port, name string) (string, error) {
	return databaseDSN(host, port, name, DatabaseUser)
}

var databaseRole = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// ComponentDSN pins the login independently of the secret payload. The runtime
// additionally verifies its effective PostgreSQL privileges before serving.
func ComponentDSN(host, port, name, user string) (string, error) {
	if !databaseRole.MatchString(user) || strings.HasPrefix(user, "pg_") || user == DatabaseUser || user == MigrationUser || user == "supivpn_owner" || user == "postgres" {
		return "", errors.New("restricted component database user required")
	}
	return databaseDSN(host, port, name, user)
}

func ComponentPassword(api SecretAPI, arn, user string) func(context.Context) (string, error) {
	return passwordForUser(api, arn, user)
}

func MigrationDSN(host, port, name string) (string, error) {
	return databaseDSN(host, port, name, MigrationUser)
}

func databaseDSN(host, port, name, user string) (string, error) {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || host == "" || name == "" ||
		strings.ContainsAny(host, "/:@?# \t\r\n") || strings.ContainsAny(name, "/?# \t\r\n") {
		return "", errors.New("invalid database endpoint")
	}
	u := url.URL{Scheme: "postgres", User: url.User(user), Host: net.JoinHostPort(host, port), Path: "/" + name}
	u.RawQuery = "sslmode=require"
	return u.String(), nil
}

// Password reads AWSCURRENT on every physical connection, including reconnects.
// No caching on disk, secret logging, administrative credentials or SQL retries.
func Password(api SecretAPI, arn string) func(context.Context) (string, error) {
	return passwordForUser(api, arn, DatabaseUser)
}

// MigrationPassword is used only by the deployment CLI, never the controller.
func MigrationPassword(api SecretAPI, arn string) func(context.Context) (string, error) {
	return passwordForUser(api, arn, MigrationUser)
}

func passwordForUser(api SecretAPI, arn, expectedUser string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if api == nil || !strings.HasPrefix(arn, "arn:aws:secretsmanager:") {
			return "", errors.New("database credential configuration invalid")
		}
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		out, err := api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(arn), VersionStage: aws.String("AWSCURRENT"),
		})
		if err != nil || out == nil || out.SecretString == nil || len(*out.SecretString) > 8192 {
			return "", errors.New("database credential unavailable")
		}
		var value struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if json.Unmarshal([]byte(*out.SecretString), &value) != nil ||
			value.User != expectedUser || value.Pass == "" || strings.ContainsAny(value.Pass, "\x00\r\n") {
			return "", errors.New("invalid database credential")
		}
		return value.Pass, nil
	}
}
