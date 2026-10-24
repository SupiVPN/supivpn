// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var samlSecretARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$`)

func samlSecretRegion(id string) (string, error) {
	if len(id) > 2048 || !samlSecretARN.MatchString(id) {
		return "", errors.New("SAML encryption requires a complete Secrets Manager ARN")
	}
	parsed, err := arn.Parse(id)
	if err != nil {
		return "", errors.New("SAML encryption requires a complete Secrets Manager ARN")
	}
	return parsed.Region, nil
}

// SAMLPrivateKey is used only during public Lambda initialization. The caller
// owns and clears the returned PEM buffer. No secret is written to disk, logged,
// created or rotated. PEM/certificate validation belongs to the shared loader.
func SAMLPrivateKey(ctx context.Context, id string) ([]byte, error) {
	region, err := samlSecretRegion(id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region), awsconfig.WithRetryMaxAttempts(2))
	if err != nil {
		return nil, errors.New("SAML encryption credential unavailable")
	}
	return readSAMLPrivateKey(ctx, secretsmanager.NewFromConfig(cfg), id)
}

func readSAMLPrivateKey(ctx context.Context, api SecretAPI, id string) ([]byte, error) {
	if _, err := samlSecretRegion(id); err != nil {
		return nil, err
	}
	if api == nil || ctx.Err() != nil {
		return nil, errors.New("SAML encryption credential unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(id), VersionStage: aws.String("AWSCURRENT"),
	})
	if err != nil || ctx.Err() != nil || out == nil {
		return nil, errors.New("SAML encryption credential unavailable")
	}
	if aws.ToString(out.ARN) != id || !slices.Contains(out.VersionStages, "AWSCURRENT") ||
		out.SecretString == nil || len(*out.SecretString) == 0 || len(*out.SecretString) > 64<<10 ||
		len(out.SecretBinary) != 0 || strings.TrimSpace(*out.SecretString) == "" {
		return nil, errors.New("invalid SAML encryption credential")
	}
	return []byte(*out.SecretString), nil
}
