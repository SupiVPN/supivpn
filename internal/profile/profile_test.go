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
		size := 128
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(args[len(args)-1], pem.EncodeToMemory(&pem.Block{Type: serverType, Bytes: data}), 0600)
	}}
}

func TestPrivatePersistentServerKey(t *testing.T) {
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
	info, err := os.Stat(key)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("wrapping key permissions", err)
	}
}

func TestInitializationRefusesInvalidExistingKey(t *testing.T) {
	for mode, initialize := range map[string]func(context.Context, string) error{
		"local": fakeIssuer().EnsureServerKey,
		"shared": func(ctx context.Context, path string) error {
			return fakeIssuer().EnsureServerKeyInStore(ctx, path, "cluster", &memorySecretStore{})
		},
	} {
		for _, name := range []string{"corrupt", "public", "symlink", "public-directory", "directory-symlink"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				key := filepath.Join(dir, "server.key")
				data := testKey(serverType)
				permissions := os.FileMode(0600)
				switch name {
				case "corrupt":
					data = []byte("invalid test-only data")
				case "public":
					permissions = 0644
				case "symlink":
					if err := os.Symlink(filepath.Join(dir, "missing"), key); err != nil {
						t.Fatal(err)
					}
				case "public-directory":
					if err := os.Chmod(dir, 0755); err != nil {
						t.Fatal(err)
					}
				case "directory-symlink":
					alias := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(dir, alias); err != nil {
						t.Fatal(err)
					}
					key = filepath.Join(alias, "server.key")
				}
				if name == "corrupt" || name == "public" {
					if err := os.WriteFile(key, data, permissions); err != nil {
						t.Fatal(err)
					}
				}
				if initialize(context.Background(), key) == nil {
					t.Fatal("unsafe existing key accepted or replaced")
				}
				if name == "corrupt" || name == "public" {
					after, err := os.ReadFile(key)
					if err != nil || !bytes.Equal(after, data) {
						t.Fatal("refused initialization changed existing key")
					}
				} else if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused initialization created a key")
				}
			})
		}
	}
}

func TestRenderRejectsWrappingKeyAndMalformedTemplate(t *testing.T) {
	template := "<tls-crypt-v2>\n" + Placeholder + "\n</tls-crypt-v2>"
	if _, err := Render([]byte(template), testKey(serverType)); err == nil {
		t.Fatal("server key included in profile")
	}
	for _, source := range []string{"client", Placeholder, template + template, template + Placeholder, template + "<tls-crypt-v2>", template + "</tls-crypt-v2>"} {
		t.Run(source, func(t *testing.T) {
			if _, err := Render([]byte(source), testKey(clientType)); err == nil {
				t.Fatal("invalid inline slot accepted")
			}
			load := func(context.Context) ([]byte, error) {
				t.Fatal("invalid template accessed wrapping key")
				return nil, nil
			}
			if _, err := DownloadIssuer([]byte("remote supivpn.example.test 1194\n"+source), "vpn.test", load); err == nil {
				t.Fatal("invalid download inline slot accepted")
			}
		})
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
