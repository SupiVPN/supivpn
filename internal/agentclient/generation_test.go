// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"supivpn/internal/agentapi"
)

type apiFunc func(context.Context, string, Request) (*agentapi.Decision, error)

func (f apiFunc) Call(ctx context.Context, op string, q Request) (*agentapi.Decision, error) {
	return f(ctx, op, q)
}
func journal(t *testing.T, dir string) *Journal {
	t.Helper()
	j, err := OpenJournal(dir, "node-1", "https://agents.example.test")
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func TestGenerationRecoveryFencesPreviousProcess(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	current := ""
	api := apiFunc(func(_ context.Context, op string, q Request) (*agentapi.Decision, error) {
		if op != "rotate" {
			t.Fatal(op)
		}
		if q.Generation == current {
			return nil, nil
		}
		if q.Previous != current {
			return nil, &Error{409}
		}
		current = q.Generation
		return nil, nil
	})
	j := journal(t, dir)
	first, err := j.Begin(context.Background(), api)
	if err != nil || first == "" {
		t.Fatal("initial rotation failed", err)
	}
	if _, err := OpenJournal(dir, "node-1", "https://agents.example.test"); err == nil {
		t.Fatal("second agent acquired lock")
	}
	// Simulate a committed rotation whose HTTP reply/local checkpoint was lost.
	j.state.Next = "interrupted-generation"
	if err := j.save(); err != nil {
		t.Fatal(err)
	}
	current = j.state.Next
	j.Close()
	j = journal(t, dir)
	second, err := j.Begin(context.Background(), api)
	if err != nil || second == first || second == "interrupted-generation" || second != current {
		t.Fatal("recovery reused a generation", err)
	}
	j.Close()
	j = journal(t, dir)
	third, err := j.Begin(context.Background(), api)
	if err != nil || third == second {
		t.Fatal("restart reused generation", err)
	}
	j.Close()
	info, err := os.Stat(filepath.Join(dir, "generation.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe state permissions")
	}
	if _, err := OpenJournal(dir, "other-node", "https://agents.example.test"); err == nil {
		t.Fatal("accepted another node's state")
	}
}
func TestGenerationFailureRetainsRecoverableCAS(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	j := journal(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	api := apiFunc(func(context.Context, string, Request) (*agentapi.Decision, error) { cancel(); return nil, &Error{503} })
	if _, err := j.Begin(ctx, api); err == nil {
		t.Fatal("started without rotation ACK")
	}
	pending := j.state.Next
	j.Close()
	j = journal(t, dir)
	defer j.Close()
	if pending == "" || j.state.Next != pending {
		t.Fatal("lost pending CAS")
	}
	if _, err := j.Begin(context.Background(), apiFunc(func(context.Context, string, Request) (*agentapi.Decision, error) { return nil, &Error{409} })); Status(err) != 409 {
		t.Fatal("generation conflict hidden")
	}
}
