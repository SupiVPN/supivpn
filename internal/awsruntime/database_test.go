// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeSecrets struct {
	value string
	err   error
	calls int
}

func (s *fakeSecrets) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	s.calls++
	if _, ok := ctx.Deadline(); !ok || aws.ToString(in.VersionStage) != "AWSCURRENT" {
		panic("unbounded/noncurrent secret request")
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: &s.value}, s.err
}
func TestPasswordRotationAndFailure(t *testing.T) {
	api := &fakeSecrets{value: `{"user":"supivpn_runtime","pass":"test-only-first"}`}
	get := Password(api, "arn:aws:secretsmanager:eu-central-1:123456789012:secret:example")
	p, err := get(context.Background())
	if err != nil || p != "test-only-first" {
		t.Fatal("initial credential")
	}
	api.value = `{"user":"supivpn_runtime","pass":"test-only-second"}`
	p, err = get(context.Background())
	if err != nil || p != "test-only-second" || api.calls != 2 {
		t.Fatal("rotation not reloaded")
	}
	for _, value := range []string{`{"user":"postgres","pass":"test-only"}`, `{"user":"supivpn_runtime","pass":""}`, `not json`} {
		api.value = value
		if p, err = get(context.Background()); err == nil || p != "" {
			t.Fatal("invalid credential accepted")
		}
	}
	api.err = errors.New("upstream-error-with-sensitive-details")
	if _, err = get(context.Background()); err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("provider error escaped")
	}
}
func TestDatabaseDSNTLSAndUser(t *testing.T) {
	dsn, err := DatabaseDSN("db.example.test", "5432", "supivpn")
	u, _ := url.Parse(dsn)
	if err != nil || u.Query().Get("sslmode") != "require" || u.User.Username() != DatabaseUser {
		t.Fatal("runtime DSN")
	}
	if _, ok := u.User.Password(); ok {
		t.Fatal("password embedded in DSN")
	}
	for _, host := range []string{"", "host/other", "host?sslmode=disable", "host@attacker"} {
		if _, err = DatabaseDSN(host, "5432", "supivpn"); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
}

func TestComponentCredentialsStayBoundToOneLogin(t *testing.T) {
	for _, user := range []string{"supivpn_public", "supivpn_agent", "supivpn_recovery"} {
		dsn, err := ComponentDSN("db.example.test", "5432", "supivpn", user)
		u, _ := url.Parse(dsn)
		if err != nil || u.User.Username() != user {
			t.Fatal("component DSN lost identity")
		}
		api := &fakeSecrets{value: `{"user":"` + user + `","pass":"test-only"}`}
		get := ComponentPassword(api, "arn:aws:secretsmanager:eu-central-1:123456789012:secret:example", user)
		if _, err := get(context.Background()); err != nil {
			t.Fatal("matching credential refused")
		}
		api.value = `{"user":"supivpn_runtime","pass":"test-only"}`
		if _, err := get(context.Background()); err == nil {
			t.Fatal("shared credential accepted")
		}
	}
	for _, user := range []string{"", "postgres", "supivpn_runtime", "supivpn_migrator", "supivpn_owner", "pg_signal_backend", "a?sslmode=disable"} {
		if _, err := ComponentDSN("db.example.test", "5432", "supivpn", user); err == nil {
			t.Fatal("unsafe component login")
		}
	}
}

func TestMigrationCredentialsAreSeparateFromRuntime(t *testing.T) {
	dsn, err := MigrationDSN("db.example.test", "5432", "supivpn")
	u, _ := url.Parse(dsn)
	if err != nil || u.Query().Get("sslmode") != "require" || u.User.Username() != MigrationUser {
		t.Fatal("invalid migrator TLS/login configuration")
	}
	if _, ok := u.User.Password(); ok {
		t.Fatal("migration password embedded in configuration")
	}
	api := &fakeSecrets{value: `{"user":"supivpn_migrator","pass":"test-only-migration"}`}
	arn := "arn:aws:secretsmanager:eu-central-1:123456789012:secret:migration"
	if _, err = MigrationPassword(api, arn)(context.Background()); err != nil {
		t.Fatal("migrator secret refused")
	}
	if _, err = Password(api, arn)(context.Background()); err == nil {
		t.Fatal("runtime accepted migrator credentials")
	}
	for _, value := range []string{
		`{"user":"supivpn_runtime","pass":"test-only-runtime"}`,
		`{"user":"postgres","pass":"test-only-admin"}`,
	} {
		api.value = value
		if _, err = MigrationPassword(api, arn)(context.Background()); err == nil {
			t.Fatal("migrator accepted another login")
		}
	}
}
