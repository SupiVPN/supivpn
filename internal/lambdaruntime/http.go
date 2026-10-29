// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package lambdaruntime wires fixed-purpose Lambda executables. There is no
// environment switch that can turn a public/agent executable into recovery.
package lambdaruntime

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"supivpn/internal/awsruntime"
	"supivpn/internal/controlruntime"
	"supivpn/internal/gateway"
	"supivpn/internal/logging"
	"supivpn/internal/metrics"
)

func MainPublic() { logging.Configure("public"); exitOnError(runHTTP(true)) }
func MainAgent()  { logging.Configure("agent_api"); exitOnError(runHTTP(false)) }
func exitOnError(err error) {
	if err != nil {
		logging.Emit(context.Background(), "component.initialization_failed")
		os.Exit(1)
	}
}

func database(ctx context.Context, defaultUser string) (string, func(context.Context) (string, error), error) {
	dsn := os.Getenv("SUPIVPN_DATABASE_URL")
	arn := os.Getenv("SUPIVPN_DATABASE_SECRET_ARN")
	if arn == "" {
		return dsn, nil, nil
	}
	if dsn != "" {
		return "", nil, errors.New("multiple database credential sources")
	}
	user := os.Getenv("SUPIVPN_DATABASE_USER")
	if user == "" {
		user = defaultUser
	}
	dsn, err := awsruntime.ComponentDSN(os.Getenv("SUPIVPN_DATABASE_HOST"), os.Getenv("SUPIVPN_DATABASE_PORT"), os.Getenv("SUPIVPN_DATABASE_NAME"), user)
	if err != nil {
		return "", nil, err
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRetryMaxAttempts(2))
	if err != nil {
		return "", nil, errors.New("AWS configuration unavailable")
	}
	return dsn, awsruntime.ComponentPassword(secretsmanager.NewFromConfig(cfg), arn, user), nil
}

func runHTTP(public bool) error {
	// Stale monolithic deployment flags must not silently leave recovery idle.
	for _, key := range []string{"SUPIVPN_EC2_FENCING", "SUPIVPN_EC2_RECOVERY", "SUPIVPN_PRUNE_RULE_ARN", "SUPIVPN_OPERATOR_CONTROL"} {
		if v := os.Getenv(key); v != "" && v != "0" {
			return errors.New("move recovery settings to the recovery function")
		}
	}
	var c controlruntime.Config
	var err error
	if value := os.Getenv("SUPIVPN_CONTROLLER_JSON"); value != "" {
		c, err = controlruntime.ParseConfig(value)
	} else {
		path := os.Getenv("SUPIVPN_CONTROLLER_CONFIG")
		if path == "" {
			path = "/var/task/controller.json"
		}
		c, err = controlruntime.ReadConfig(path)
	}
	if err != nil {
		return err
	}
	if c.Gateway == nil || c.VM != nil {
		return errors.New("gateway configuration required")
	}
	if !public && c.Metrics.IsEnabled() {
		return errors.New("agent Lambda must not receive metrics configuration")
	}
	component := "agent_api"
	if public {
		component = "public"
	}
	closeLogs, err := logging.Setup(component, c.Logging)
	if err != nil {
		return err
	}
	defer closeLogs()
	if !public && os.Getenv("SUPIVPN_TLS_CRYPT_V2_SECRET_ARN") != "" {
		return errors.New("agent must not receive a profile key")
	}
	if !public && c.AssertionEncryption != nil {
		return errors.New("agent must not receive SAML encryption configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var metricsDigest [32]byte
	if c.Metrics.IsEnabled() {
		metricsDigest, err = awsruntime.MetricsTokenDigest(ctx, c.Metrics.BearerTokenSecretARN)
		if err != nil {
			return err
		}
	}
	user := "supivpn_agent"
	if public {
		user = "supivpn_public"
	}
	dsn, password, err := database(ctx, user)
	if err != nil {
		return err
	}
	var app *controlruntime.Application
	if public {
		var key func(context.Context) ([]byte, error)
		if c.Profile != nil {
			arn := os.Getenv("SUPIVPN_TLS_CRYPT_V2_SECRET_ARN")
			store, e := awsruntime.NewSecretsManagerStore(ctx, arn)
			if e != nil {
				return e
			}
			key = func(ctx context.Context) ([]byte, error) { return store.Get(ctx, arn) }
		}
		app, err = controlruntime.OpenPublicWithEncryptionKey(ctx, c, dsn, password, key, awsruntime.SAMLPrivateKey)
	} else {
		app, err = controlruntime.OpenAgent(ctx, c, dsn, password)
	}
	if err != nil {
		return err
	}
	defer app.Close()
	var adapter *gateway.Adapter
	if public {
		var endpoint http.Handler
		if c.Metrics.IsEnabled() {
			endpoint = metrics.Protect(metricsDigest, app.Metrics)
		}
		adapter, err = gateway.NewPublic(*c.Gateway, app.Origin, metrics.PublicRoute(app.Origin.Path, app.Public, endpoint))
	} else {
		adapter, err = gateway.NewAgent(*c.Gateway, app.Origin, app.Agents)
	}
	if err != nil {
		return err
	}
	switch os.Getenv("SUPIVPN_GATEWAY_FORMAT") {
	case "rest":
		lambda.Start(withInvocation(awsruntime.HTTPHandler(adapter.HandleREST)))
	case "", "http-v2":
		lambda.Start(withInvocation(adapter.Handle))
	default:
		return errors.New("unsupported gateway format")
	}
	return nil
}
