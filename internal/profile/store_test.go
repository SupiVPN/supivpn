// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type memorySecretStore struct {
	mu      sync.Mutex
	value   []byte
	getErr  error
	putErr  error
	creates int
	barrier *sync.WaitGroup
}

func (s *memorySecretStore) Get(context.Context, string) ([]byte, error) {
	s.mu.Lock()
	value, err := bytes.Clone(s.value), s.getErr
	s.mu.Unlock()
	if s.barrier != nil {
		s.barrier.Done()
		s.barrier.Wait()
	}
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, ErrSecretNotFound
	}
	return value, nil
}

func (s *memorySecretStore) CreateIfAbsent(_ context.Context, _ string, candidate []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates++
	if s.putErr != nil {
		return nil, s.putErr
	}
	if s.value == nil {
		s.value = bytes.Clone(candidate)
	}
	return bytes.Clone(s.value), nil
}

func TestSharedKeyConcurrentBootstrapAndReplacement(t *testing.T) {
	for _, sameHost := range []bool{false, true} {
		name := "different-nodes"
		if sameHost {
			name = "same-node"
		}
		t.Run(name, func(t *testing.T) {
			const workers = 8
			var barrier, done sync.WaitGroup
			barrier.Add(workers)
			store := &memorySecretStore{barrier: &barrier}
			dir := t.TempDir()
			paths := make([]string, workers)
			for n := range paths {
				parent := dir
				if !sameHost {
					parent = t.TempDir()
				}
				if err := os.Chmod(parent, 0700); err != nil {
					t.Fatal(err)
				}
				paths[n] = filepath.Join(parent, "server.key")
				done.Add(1)
				go func(path string) {
					defer done.Done()
					if err := fakeIssuer().EnsureServerKeyInStore(context.Background(), path, "cluster", store); err != nil {
						t.Error(err)
					}
				}(paths[n])
			}
			done.Wait()
			store.barrier = nil
			for _, path := range paths {
				got, err := readPrivateKey(path, serverType)
				if err != nil || !bytes.Equal(got, store.value) {
					t.Fatal("nodes did not receive the same private wrapping key")
				}
			}
			// Simulates a replacement EC2: no local key, same cluster secret.
			replacement := filepath.Join(t.TempDir(), "private", "server.key")
			creates := store.creates
			if err := fakeIssuer().EnsureServerKeyInStore(context.Background(), replacement, "cluster", store); err != nil {
				t.Fatal(err)
			}
			got, err := readPrivateKey(replacement, serverType)
			if err != nil || !bytes.Equal(got, store.value) || creates != store.creates {
				t.Fatal("replacement generated or changed the cluster key")
			}
		})
	}
}

func TestSharedKeyAdoptsExistingLocalAndRefusesMismatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "server.key")
	original := testKey(serverType)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	store := &memorySecretStore{}
	issuer := fakeIssuer()
	if err := issuer.EnsureServerKeyInStore(context.Background(), path, "cluster", store); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(store.value, original) || store.creates != 1 {
		t.Fatal("existing key was not preserved during migration")
	}
	if err := issuer.EnsureServerKeyInStore(context.Background(), path, "cluster", store); err != nil || store.creates != 1 {
		t.Fatal("repeat bootstrap attempted to rotate the key")
	}
	otherPath := filepath.Join(dir, "other.key")
	if err := issuer.EnsureServerKey(context.Background(), otherPath); err != nil {
		t.Fatal(err)
	}
	store.value, _ = os.ReadFile(otherPath)
	if issuer.EnsureServerKeyInStore(context.Background(), path, "cluster", store) == nil {
		t.Fatal("local/remote mismatch was accepted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, original) {
		t.Fatal("mismatch overwrote the local key")
	}
}

func TestSharedKeyFailuresNeverPublishCandidate(t *testing.T) {
	for _, name := range []string{"read-error", "write-error", "malformed-remote", "public-directory", "relative-path"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "server.key")
			store := &memorySecretStore{}
			switch name {
			case "read-error":
				store.getErr = errors.New("sensitive-store-response")
			case "write-error":
				store.putErr = errors.New("sensitive-store-response")
			case "malformed-remote":
				store.value = []byte("invalid")
			case "public-directory":
				store.value = testKey(serverType)
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "relative-path":
				path = "must-not-be-created.key"
			}
			err := fakeIssuer().EnsureServerKeyInStore(context.Background(), path, "cluster", store)
			if err == nil || strings.Contains(err.Error(), "sensitive-store-response") {
				t.Fatal("bootstrap failure was not safely reported")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed bootstrap published a key")
			}
			if name != "write-error" && store.creates != 0 {
				t.Fatal("invalid local state or store failure attempted initialization")
			}
		})
	}
}
