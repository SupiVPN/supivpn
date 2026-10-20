// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"supivpn/internal/agentapi"
	"golang.org/x/sys/unix"
)

type generationState struct {
	Node     string `json:"node"`
	Endpoint string `json:"endpoint"`
	Current  string `json:"current"`
	Next     string `json:"next,omitempty"`
}
type Journal struct {
	dir   string
	lock  *os.File
	state generationState
}

// OpenJournal holds an exclusive process lock. The containing directory must
// survive service restarts; runtime/socket directories must not be used.
func OpenJournal(dir, node, endpoint string) (*Journal, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !agentapi.ValidNode(node) {
		return nil, errors.New("agent state directory must exist with mode 0700")
	}
	fd, err := unix.Open(filepath.Join(dir, "generation.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot open agent generation lock")
	}
	lock := os.NewFile(uintptr(fd), "generation.lock")
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("agent state is already in use")
	}
	j := &Journal{dir: dir, lock: lock, state: generationState{Node: node, Endpoint: endpoint}}
	f, err := os.Open(filepath.Join(dir, "generation.json"))
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		j.Close()
		return nil, errors.New("cannot read agent generation")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4096))
	d.DisallowUnknownFields()
	if d.Decode(&j.state) != nil || d.Decode(new(any)) != io.EOF ||
		j.state.Node != node || j.state.Endpoint != endpoint ||
		(j.state.Current != "" && !agentapi.ValidNode(j.state.Current)) ||
		(j.state.Next != "" && !agentapi.ValidNode(j.state.Next)) ||
		(j.state.Current == "" && j.state.Next == "") || j.state.Next == j.state.Current {
		j.Close()
		return nil, errors.New("agent generation state invalid or belongs to another node/controller")
	}
	return j, nil
}
func (j *Journal) Close() { j.lock.Close() }
func (j *Journal) save() error {
	f, err := os.CreateTemp(j.dir, ".generation-")
	if err != nil {
		return errors.New("cannot persist agent generation")
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(j.state)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(j.dir, "generation.json"))
	}
	if err == nil {
		var dir *os.File
		dir, err = os.Open(j.dir)
		if err == nil {
			err = dir.Sync()
			dir.Close()
		}
	}
	if err != nil {
		return errors.New("cannot persist agent generation")
	}
	return nil
}

func (j *Journal) commit(ctx context.Context, api API) error {
	for {
		_, err := api.Call(ctx, "rotate", Request{Generation: j.state.Next, Previous: j.state.Current})
		if err == nil {
			break
		}
		if !Retryable(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.New("controller unavailable during generation rotation")
		case <-time.After(time.Second):
		}
	}
	j.state.Current, j.state.Next = j.state.Next, ""
	return j.save()
}

// Recover an interrupted CAS using the same next value, then always rotate once
// more. A recovered generation may have served clients before the previous crash.
func (j *Journal) Begin(ctx context.Context, api API) (string, error) {
	if j.state.Next != "" {
		if err := j.commit(ctx, api); err != nil {
			return "", err
		}
	}
	j.state.Next = rand.Text()
	if err := j.save(); err != nil {
		return "", err
	}
	if err := j.commit(ctx, api); err != nil {
		return "", err
	}
	return j.state.Current, nil
}
