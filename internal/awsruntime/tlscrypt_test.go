// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"supivpn/internal/profile"
)

// Models immutable Secrets Manager versions, including two stale initial reads.
type wrappingSecretsFake struct {
	mu       sync.Mutex
	barrier  *sync.WaitGroup
	reads    int
	puts     int
	versions map[string]string
	current  string
	getErr   error
	putErr   error
}

func (f *wrappingSecretsFake) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.mu.Lock()
	f.reads++
	initial := f.barrier != nil && f.reads <= 2
	value, ok := f.versions[f.current]
	err := f.getErr
	f.mu.Unlock()
	if initial {
		f.barrier.Done()
		f.barrier.Wait()
	}
	if err != nil {
		return nil, err
	}
	if aws.ToString(in.VersionStage) != "AWSCURRENT" {
		return nil, errors.New("current version must be explicit")
	}
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{}
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(value)}, nil
}

func (f *wrappingSecretsFake) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	if f.putErr != nil {
		return nil, f.putErr
	}
	token, candidate := aws.ToString(in.ClientRequestToken), aws.ToString(in.SecretString)
	if len(token) < 32 || len(token) > 64 {
		return nil, errors.New("missing valid idempotency token")
	}
	if value, ok := f.versions[token]; ok {
		if value != candidate {
			return nil, &smtypes.ResourceExistsException{}
		}
		return &secretsmanager.PutSecretValueOutput{}, nil
	}
	if f.versions == nil {
		f.versions = make(map[string]string)
	}
	f.versions[token] = candidate
	f.current = token
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func TestWrappingSecretConcurrentCreationElectsOneVersion(t *testing.T) {
	var barrier sync.WaitGroup
	barrier.Add(2)
	api := &wrappingSecretsFake{barrier: &barrier}
	store := &SecretsManagerStore{client: api}
	type result struct {
		value []byte
		err   error
	}
	results := make(chan result, 2)
	for _, candidate := range []string{"synthetic-candidate-one", "synthetic-candidate-two"} {
		go func(value string) {
			winner, err := store.CreateIfAbsent(context.Background(), "cluster", []byte(value))
			results <- result{winner, err}
		}(candidate)
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || !bytes.Equal(first.value, second.value) {
		t.Fatal("concurrent bootstrap did not converge")
	}
	if len(api.versions) != 1 || api.puts != 2 {
		t.Fatal("concurrent proposals created multiple versions or did not exercise the conflict")
	}
	// A later initialization must not publish a new version.
	api.barrier = nil
	if _, err := store.CreateIfAbsent(context.Background(), "cluster", []byte("third")); err != nil || api.puts != 2 {
		t.Fatal("existing wrapping key was changed")
	}
}

func TestWrappingSecretFailuresAndLegacyValue(t *testing.T) {
	t.Run("preserve-preexisting-version", func(t *testing.T) {
		api := &wrappingSecretsFake{versions: map[string]string{"legacy": "synthetic-old-key"}, current: "legacy"}
		store := &SecretsManagerStore{client: api}
		got, err := store.CreateIfAbsent(context.Background(), "cluster", []byte("replacement"))
		if err != nil || string(got) != "synthetic-old-key" || api.puts != 0 {
			t.Fatal("preexisting version was replaced")
		}
	})
	for _, operation := range []string{"read", "write"} {
		t.Run(operation+"-denied", func(t *testing.T) {
			api := &wrappingSecretsFake{}
			if operation == "read" {
				api.getErr = errors.New("sensitive-provider-response")
			} else {
				api.putErr = errors.New("sensitive-provider-response")
			}
			store := &SecretsManagerStore{client: api}
			got, err := store.CreateIfAbsent(context.Background(), "cluster", []byte("proposal"))
			if err == nil || got != nil || strings.Contains(err.Error(), "sensitive-provider-response") {
				t.Fatal("unconfirmed proposal or provider details escaped")
			}
			if operation == "read" && api.puts != 0 {
				t.Fatal("read denial attempted to write")
			}
		})
	}
	t.Run("missing-version", func(t *testing.T) {
		store := &SecretsManagerStore{client: &wrappingSecretsFake{}}
		if _, err := store.Get(context.Background(), "cluster"); !errors.Is(err, profile.ErrSecretNotFound) {
			t.Fatal("missing version not translated to store contract")
		}
	})
	t.Run("empty-value", func(t *testing.T) {
		api := &wrappingSecretsFake{versions: map[string]string{"v": ""}, current: "v"}
		store := &SecretsManagerStore{client: api}
		if _, err := store.CreateIfAbsent(context.Background(), "cluster", []byte("proposal")); err == nil || api.puts != 0 {
			t.Fatal("malformed remote value was treated as uninitialized")
		}
	})
}
