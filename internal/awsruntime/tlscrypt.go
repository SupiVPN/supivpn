// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"supivpn/internal/profile"
)

// This ID is stable across nodes, retries and releases. Versions are immutable:
// different proposals with this token cannot replace the elected wrapping key.
// Changing it is NOT a rotation mechanism.
const tlsCryptBootstrapVersion = "supivpn-tls-crypt-v2-bootstrap-v1"

type wrappingSecretAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(context.Context, *secretsmanager.PutSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}

type SecretsManagerStore struct {
	client wrappingSecretAPI
}

var _ profile.SecretStore = (*SecretsManagerStore)(nil)

func NewSecretsManagerStore(ctx context.Context, secretARN string) (*SecretsManagerStore, error) {
	id, err := arn.Parse(secretARN)
	if err != nil || id.Service != "secretsmanager" || id.Region == "" || id.AccountID == "" || !strings.HasPrefix(id.Resource, "secret:") {
		return nil, errors.New("a complete Secrets Manager ARN is required")
	}
	// Provisioning runs under sudo; no developer AWS profile/region is needed.
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(id.Region))
	if err != nil {
		return nil, errors.New("AWS configuration unavailable")
	}
	return &SecretsManagerStore{client: secretsmanager.NewFromConfig(cfg)}, nil
}

func (s *SecretsManagerStore) Get(ctx context.Context, id string) ([]byte, error) {
	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(id), VersionStage: aws.String("AWSCURRENT"),
	})
	if err != nil {
		var missing *smtypes.ResourceNotFoundException
		if errors.As(err, &missing) {
			return nil, profile.ErrSecretNotFound
		}
		return nil, errors.New("cannot read tls-crypt-v2 secret")
	}
	if out == nil || out.SecretString == nil || len(*out.SecretString) == 0 || len(*out.SecretString) > 8192 || len(out.SecretBinary) != 0 {
		return nil, errors.New("invalid secret value")
	}
	return []byte(*out.SecretString), nil
}

func (s *SecretsManagerStore) CreateIfAbsent(ctx context.Context, id string, value []byte) ([]byte, error) {
	// Preserve a key seeded before this initializer, too.
	if existing, err := s.Get(ctx, id); err == nil {
		return existing, nil
	} else if !errors.Is(err, profile.ErrSecretNotFound) {
		return nil, err
	}
	if len(value) == 0 || len(value) > 8192 {
		return nil, errors.New("invalid secret value")
	}
	_, err := s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId: aws.String(id), SecretString: aws.String(string(value)),
		ClientRequestToken: aws.String(tlsCryptBootstrapVersion),
	})
	if err != nil {
		var conflict *smtypes.ResourceExistsException
		if !errors.As(err, &conflict) {
			return nil, errors.New("cannot initialize tls-crypt-v2 secret")
		}
	}
	// Both the winner and loser read the authoritative value. A lost response or
	// delayed visibility never causes publication of the unconfirmed proposal.
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		winner, err := s.Get(readCtx, id)
		if err == nil {
			return winner, nil
		}
		if !errors.Is(err, profile.ErrSecretNotFound) {
			return nil, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-readCtx.Done():
			timer.Stop()
			return nil, errors.New("tls-crypt-v2 secret is not readable after initialization")
		case <-timer.C:
		}
	}
}
