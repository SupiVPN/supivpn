// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testKey(kind string) []byte {
	size := 128
	if kind == clientType {
		size = 600
	}
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: []byte(strings.Repeat("x", size))})
}

func fakeIssuer() Issuer {
	return Issuer{run: func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "--version" {
			return []byte("OpenVPN 2.7.8 test"), nil
		}
		kind := serverType
		size := 128
		if args[0] == "--tls-crypt-v2" {
			kind, size = clientType, 600
		}
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(args[len(args)-1], pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), 0600)
	}}
}

func TestPrivateProfilesAndPersistentServerKey(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	key := filepath.Join(dir, "server.key")
	i := fakeIssuer()
	ctx := context.Background()
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := i.EnsureServerKey(ctx, key); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	before, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := i.EnsureServerKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(key)
	if !bytes.Equal(before, after) {
		t.Fatal("initialization rotated the wrapping key")
	}
	template := []byte("client\n<tls-crypt-v2>\n" + Placeholder + "\n</tls-crypt-v2>\n")
	first, second := filepath.Join(dir, "first.ovpn"), filepath.Join(dir, "second.ovpn")
	for _, path := range []string{first, second} {
		if err := i.Issue(ctx, key, template, path); err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(path)
		data, _ := os.ReadFile(path)
		if info.Mode().Perm() != 0600 || bytes.Contains(data, before) || bytes.Contains(data, []byte(serverType)) {
			t.Fatal("profile permissions or wrapping-key isolation failed")
		}
	}
	a, _ := os.ReadFile(first)
	b, _ := os.ReadFile(second)
	if bytes.Equal(a, b) {
		t.Fatal("profiles shared their key")
	}
	if err := i.Issue(ctx, key, template, first); err == nil {
		t.Fatal("existing profile overwritten")
	}
	unchanged, _ := os.ReadFile(first)
	if !bytes.Equal(a, unchanged) {
		t.Fatal("profile changed after refused overwrite")
	}
}

func TestInitializationRefusesInvalidExistingKey(t *testing.T) {
	for _, name := range []string{"corrupt", "public", "symlink"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			key := filepath.Join(dir, "server.key")
			data := testKey(serverType)
			mode := os.FileMode(0600)
			switch name {
			case "corrupt":
				data = []byte("invalid test-only data")
			case "public":
				mode = 0644
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "missing"), key); err != nil {
					t.Fatal(err)
				}
			}
			if name != "symlink" {
				if err := os.WriteFile(key, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			if fakeIssuer().EnsureServerKey(context.Background(), key) == nil {
				t.Fatal("unsafe existing key accepted or replaced")
			}
		})
	}
}

func TestRenderRejectsWrappingKeyAndMalformedTemplate(t *testing.T) {
	template := "<tls-crypt-v2>\n" + Placeholder + "\n</tls-crypt-v2>"
	if _, err := Render([]byte(template), testKey(serverType)); err == nil {
		t.Fatal("server key included in profile")
	}
	for _, source := range []string{"client", Placeholder, template + template, template + Placeholder} {
		if _, err := Render([]byte(source), testKey(clientType)); err == nil {
			t.Fatal("invalid inline slot accepted")
		}
	}
}

func TestGeneratorFailureLeavesNoFileOrSecrets(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	i := Issuer{run: func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "--version" {
			return []byte("OpenVPN 2.7.8 test"), nil
		}
		return nil, errors.New("sensitive-generator-output")
	}}
	err := i.EnsureServerKey(context.Background(), filepath.Join(dir, "key"))
	if err == nil || strings.Contains(err.Error(), "sensitive-generator-output") {
		t.Fatal("generator failure was not safely reported")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("failed generation left a partial key")
	}
}

func TestWrongOpenVPNVersionRefused(t *testing.T) {
	for _, version := range []string{"2.6.14", "2.7.7", "2.7.80", "2.7.8_rc1"} {
		t.Run(version, func(t *testing.T) {
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			i := Issuer{run: func(context.Context, ...string) ([]byte, error) {
				return []byte("OpenVPN " + version + " test"), nil
			}}
			if i.EnsureServerKey(context.Background(), filepath.Join(dir, "key")) == nil {
				t.Fatal("unpinned OpenVPN accepted")
			}
		})
	}
}
