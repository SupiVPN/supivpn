// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package lambdaruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"supivpn/internal/awsruntime"
	"supivpn/internal/controlruntime"
	"supivpn/internal/postgres"
	"supivpn/internal/logging"
)

type recoveryConfig struct {
    Logging *logging.Config `json:"logging,omitempty"`
	DatabaseTLS       *postgres.TLSConfig `json:"database_tls,omitempty"`
	NodeIDs           []string            `json:"node_ids"`
	AutomaticRecovery bool                `json:"automatic_recovery"`
}

func parseRecovery(value string) (recoveryConfig, error) {
	var c recoveryConfig
	if len(value) > 64<<10 {
		return c, errors.New("recovery configuration too large")
	}
	d := json.NewDecoder(strings.NewReader(value))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, errors.New("invalid recovery configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing recovery configuration")
	}
    if err := c.Logging.Validate("recovery"); err != nil { return c, err }
	if err := c.DatabaseTLS.Validate(); err != nil {
		return c, err
	}
	return c, nil
}
func MainRecovery() { logging.Configure("recovery"); exitOnError(runRecovery()) }
func runRecovery() error {
	if os.Getenv("SUPIVPN_CONTROLLER_JSON") != "" || os.Getenv("SUPIVPN_TLS_CRYPT_V2_SECRET_ARN") != "" {
		return errors.New("recovery must not receive public controller configuration")
	}
	rule := os.Getenv("SUPIVPN_RECOVERY_RULE_ARN")
	if !strings.HasPrefix(rule, "arn:aws:events:") || !strings.Contains(rule, ":rule/") {
		return errors.New("exact recovery schedule ARN required")
	}
	c, err := parseRecovery(os.Getenv("SUPIVPN_RECOVERY_JSON"))
	if err != nil {
		return err
	}
    closeLogs, err := logging.Setup("recovery", c.Logging)
    if err != nil { return err }
    defer closeLogs()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dsn, password, err := database(ctx, "supivpn_recovery")
	if err != nil {
		return err
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRetryMaxAttempts(1))
	if err != nil {
		return errors.New("AWS recovery configuration unavailable")
	}
	var driver postgres.Fencer
	if c.AutomaticRecovery {
		driver, err = awsruntime.NewEC2Recovery(ec2.NewFromConfig(cfg), c.NodeIDs)
	} else {
		driver, err = awsruntime.NewEC2Fencer(ec2.NewFromConfig(cfg), c.NodeIDs)
	}
	if err != nil {
		return err
	}
	app, err := controlruntime.OpenRecovery(ctx, dsn, password, c.DatabaseTLS, driver)
	if err != nil {
		return err
	}
	defer app.Close()
	operator := app.Operations
	if os.Getenv("SUPIVPN_OPERATOR_CONTROL") != "1" {
		operator = nil
	}
	lambda.Start(withInvocation(awsruntime.RecoveryHandler(app.Reconcile, rule, operator)))
	return nil
}
