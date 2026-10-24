// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const testSAMLSecretARN = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:saml-recipient-Ab12Cd"

type samlSecretAPI func(context.Context, *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)

func (f samlSecretAPI) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return f(ctx, in)
}

func TestSAMLSecretReadBoundaries(t *testing.T) {
	for _, name := range []string{"valid", "nil", "error", "missing-string", "empty", "whitespace", "oversized", "binary", "both", "wrong-arn", "wrong-stage", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			api := samlSecretAPI(func(ctx context.Context, in *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 5*time.Second || aws.ToString(in.SecretId) != testSAMLSecretARN || aws.ToString(in.VersionStage) != "AWSCURRENT" || in.VersionId != nil {
					t.Fatal("unbounded or unpinned secret request")
				}
				out := &secretsmanager.GetSecretValueOutput{ARN: aws.String(testSAMLSecretARN), VersionStages: []string{"AWSCURRENT"}, SecretString: aws.String("synthetic-PEM-parser-input")}
				switch name {
				case "nil":
					return nil, nil
				case "error":
					return out, errors.New("provider-sensitive-details")
				case "missing-string":
					out.SecretString = nil
				case "empty":
					out.SecretString = aws.String("")
				case "whitespace":
					out.SecretString = aws.String(" \n")
				case "oversized":
					out.SecretString = aws.String(strings.Repeat("x", (64<<10)+1))
				case "binary":
					out.SecretString = nil
					out.SecretBinary = []byte("synthetic")
				case "both":
					out.SecretBinary = []byte("synthetic")
				case "wrong-arn":
					out.ARN = aws.String(testSAMLSecretARN + "other")
				case "wrong-stage":
					out.VersionStages = []string{"AWSPREVIOUS"}
				case "cancelled":
					cancel()
				}
				return out, nil
			})
			value, err := readSAMLPrivateKey(ctx, api, testSAMLSecretARN)
			defer clear(value)
			if calls != 1 || (err == nil) != (name == "valid") {
				t.Fatal("secret source policy was not enforced")
			}
			if err != nil && (value != nil || strings.Contains(err.Error(), "sensitive")) {
				t.Fatal("provider error or payload escaped")
			}
			if name == "valid" && string(value) != "synthetic-PEM-parser-input" {
				t.Fatal("secret value changed before PEM parsing")
			}
		})
	}
}

func TestSAMLSecretConfigurationFailsBeforeNetwork(t *testing.T) {
	api := samlSecretAPI(func(context.Context, *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		t.Fatal("invalid configuration contacted secret service")
		return nil, nil
	})
	for _, id := range []string{"", "saml-recipient", strings.TrimSuffix(testSAMLSecretARN, "-Ab12Cd"), strings.ReplaceAll(testSAMLSecretARN, "123456789012", "123"), strings.ReplaceAll(testSAMLSecretARN, "secretsmanager", "ssm"), testSAMLSecretARN + "\n", testSAMLSecretARN + "*"} {
		if _, err := readSAMLPrivateKey(context.Background(), api, id); err == nil {
			t.Fatal("invalid ARN accepted")
		}
		if _, err := SAMLPrivateKey(context.Background(), id); err == nil {
			t.Fatal("public adapter accepted invalid ARN")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readSAMLPrivateKey(ctx, api, testSAMLSecretARN); err == nil {
		t.Fatal("cancelled read accepted")
	}
	if _, err := readSAMLPrivateKey(context.Background(), nil, testSAMLSecretARN); err == nil {
		t.Fatal("missing client accepted")
	}
	region, err := samlSecretRegion(testSAMLSecretARN)
	if err != nil || region != "eu-west-1" {
		t.Fatal("secret region was not selected from ARN")
	}
}
