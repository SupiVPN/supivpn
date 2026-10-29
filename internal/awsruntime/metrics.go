// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"supivpn/internal/metrics"
)

// MetricsTokenDigest loads only the dedicated public-Lambda metrics token at
// initialization. Only its hash survives; no secret is persisted or logged.
func MetricsTokenDigest(ctx context.Context, id string) ([32]byte, error) {
	region, err := samlSecretRegion(id)
	if err != nil {
		return [32]byte{}, errors.New("metrics require a complete Secrets Manager ARN")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region), awsconfig.WithRetryMaxAttempts(2))
	if err != nil {
		return [32]byte{}, errors.New("metrics credential unavailable")
	}
	return readMetricsToken(ctx, secretsmanager.NewFromConfig(cfg), id)
}

func readMetricsToken(ctx context.Context, api SecretAPI, id string) ([32]byte, error) {
	if _, err := samlSecretRegion(id); err != nil {
		return [32]byte{}, errors.New("invalid metrics secret ARN")
	}
	if api == nil || ctx.Err() != nil {
		return [32]byte{}, errors.New("metrics credential unavailable")
	}
	out, err := api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(id), VersionStage: aws.String("AWSCURRENT")})
	if err != nil || ctx.Err() != nil || out == nil {
		return [32]byte{}, errors.New("metrics credential unavailable")
	}
	if aws.ToString(out.ARN) != id || !slices.Contains(out.VersionStages, "AWSCURRENT") || out.SecretString == nil || len(*out.SecretString) != 43 || len(out.SecretBinary) != 0 {
		return [32]byte{}, errors.New("invalid metrics credential")
	}
	return metrics.TokenDigest([]byte(*out.SecretString))
}
