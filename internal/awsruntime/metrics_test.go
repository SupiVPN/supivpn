// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"supivpn/internal/metrics"
)

func TestMetricsSecretBoundaries(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	want, err := metrics.TokenDigest([]byte(token))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"valid", "error", "nil", "binary", "stage", "arn", "missing", "length", "newline", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			api := samlSecretAPI(func(ctx context.Context, in *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
				if aws.ToString(in.SecretId) != testSAMLSecretARN || aws.ToString(in.VersionStage) != "AWSCURRENT" {
					t.Fatal("wrong secret selection")
				}
				out := &secretsmanager.GetSecretValueOutput{ARN: aws.String(testSAMLSecretARN), VersionStages: []string{"AWSCURRENT"}, SecretString: aws.String(token)}
				switch name {
				case "error":
					return nil, errors.New("sensitive-provider-details")
				case "nil":
					return nil, nil
				case "binary":
					out.SecretBinary = []byte{1}
				case "stage":
					out.VersionStages = []string{"AWSPREVIOUS"}
				case "arn":
					out.ARN = aws.String(testSAMLSecretARN + "other")
				case "missing":
					out.SecretString = nil
				case "length":
					out.SecretString = aws.String("short")
				case "newline":
					out.SecretString = aws.String(token + "\n")
				case "cancelled":
					cancel()
				}
				return out, nil
			})
			got, err := readMetricsToken(ctx, api, testSAMLSecretARN)
			if (err == nil) != (name == "valid") {
				t.Fatal("incorrect secret acceptance")
			}
			if err == nil && got != want {
				t.Fatal("wrong digest")
			}
			if err != nil && (got != [32]byte{} || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), token)) {
				t.Fatal("secret/provider error leaked")
			}
		})
	}
	if _, err := MetricsTokenDigest(context.Background(), "not-an-arn"); err == nil {
		t.Fatal("invalid ARN accepted")
	}
}
