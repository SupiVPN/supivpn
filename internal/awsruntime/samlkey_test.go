// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const testSAMLSecretARN = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:saml-recipient-Ab12Cd"

// Exercise the SDK retry middleware, not only the SecretAPI mock.
func TestSAMLSecretSDKFailureBoundaries(t *testing.T) {
	for _, name := range []string{"retry-limit", "access-denied", "deadline"} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				if name == "deadline" {
					select {
					case <-r.Context().Done():
					case <-time.After(2 * time.Second):
					}
					return
				}
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				if name == "access-denied" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"provider-sensitive-details"}`))
					return
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"__type":"InternalServiceError","message":"provider-sensitive-details"}`))
			}))
			defer server.Close()
			client := secretsmanager.NewFromConfig(aws.Config{
				Region: "eu-west-1", Credentials: aws.AnonymousCredentials{},
				HTTPClient: server.Client(), RetryMaxAttempts: 2,
			}, func(o *secretsmanager.Options) { o.BaseEndpoint = aws.String(server.URL) })
			timeout := 5 * time.Second
			if name == "deadline" {
				timeout = 200 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			value, err := readSAMLPrivateKey(ctx, client, testSAMLSecretARN)
			if value != nil || err == nil || err.Error() != "SAML encryption credential unavailable" {
				t.Fatal("SDK failure escaped the fail-closed secret boundary")
			}
			want := int32(1)
			if name == "retry-limit" {
				want = 2
			}
			if calls.Load() != want || (name == "deadline" && ctx.Err() != context.DeadlineExceeded) {
				t.Fatalf("unexpected retry/deadline behavior: calls=%d, context=%v", calls.Load(), ctx.Err())
			}
		})
	}
}

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
