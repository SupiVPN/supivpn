// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package profile provides OpenVPN key bootstrap/CLI issuance and a portable
// in-memory profile issuer for browser downloads.
package profile

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const Version = "2.7.8"
const Placeholder = "{{TLS_CRYPT_V2_CLIENT_KEY}}"
const serverType = "OpenVPN tls-crypt-v2 server key"
const clientType = "OpenVPN tls-crypt-v2 client key"

var ErrSecretNotFound = errors.New("secret not found")

type SecretStore interface {
	Get(context.Context, string) ([]byte, error)
	// CreateIfAbsent atomically elects one value and returns the stored winner.
	// Concurrent callers must never overwrite it with their own candidate.
	CreateIfAbsent(context.Context, string, []byte) ([]byte, error)
}

type Issuer struct {
	OpenVPN string
	run     func(context.Context, ...string) ([]byte, error)
}

func (i Issuer) command(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if i.run != nil {
		return i.run(ctx, args...)
	}
	if !filepath.IsAbs(i.OpenVPN) {
		return nil, errors.New("OpenVPN executable must be an absolute path")
	}
	cmd := exec.CommandContext(ctx, i.OpenVPN, args...)
	// No generator output or stderr is propagated to logs or errors.
	return cmd.Output()
}

func (i Issuer) checkVersion(ctx context.Context) error {
	out, err := i.command(ctx, "--version")
	if err != nil || !bytes.HasPrefix(out, []byte("OpenVPN "+Version+" ")) {
		return errors.New("OpenVPN " + Version + " is required")
	}
	return nil
}

func validateKey(data []byte, kind string) error {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN "+kind+"-----")) {
		return errors.New("invalid tls-crypt-v2 key format")
	}
	if (kind == serverType && len(block.Bytes) != 128) ||
		(kind == clientType && (len(block.Bytes) <= 256 || len(block.Bytes) > 2048)) {
		return errors.New("invalid tls-crypt-v2 key length")
	}
	return nil
}

func readPrivateKey(path, kind string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("tls-crypt-v2 key must be a regular file with mode 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data) > 8192 {
		return nil, errors.New("cannot read tls-crypt-v2 key")
	}
	if err := validateKey(data, kind); err != nil {
		return nil, err
	}
	return data, nil
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("server key directory must be private (0700)")
	}
	return nil
}

// publish uses an atomic, no-replace link; neither a partial file nor an
// overwrite of an existing key/profile is visible to readers.
func publish(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".supivpn-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Link(tmp.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (i Issuer) generate(ctx context.Context, parent, kind, serverKey string) ([]byte, error) {
	dir, err := os.MkdirTemp(parent, ".supivpn-key-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "generated.key")
	args := []string{"--genkey", "tls-crypt-v2-server", target}
	if kind == clientType {
		args = []string{"--tls-crypt-v2", serverKey, "--genkey", "tls-crypt-v2-client", target}
	}
	if _, err := i.command(ctx, args...); err != nil {
		return nil, errors.New("OpenVPN key generation failed")
	}
	// The directory is 0700 even if the caller's umask is permissive.
	if err := os.Chmod(target, 0600); err != nil {
		return nil, err
	}
	return readPrivateKey(target, kind)
}

// EnsureServerKey preserves an existing key, including concurrent initialization.
// A corrupt or permissively readable key is an error, never a request to rotate.
func (i Issuer) EnsureServerKey(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("server key must be an absolute path")
	}
	if _, err := readPrivateKey(path, serverType); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	if err := privateDirectory(parent); err != nil {
		return err
	}
	if err := i.checkVersion(ctx); err != nil {
		return err
	}
	data, err := i.generate(ctx, parent, serverType, "")
	if err != nil {
		return err
	}
	if err := publish(path, data); err != nil {
		if errors.Is(err, os.ErrExist) {
			_, err = readPrivateKey(path, serverType)
		}
		return err
	}
	return nil
}

// EnsureServerKeyInStore makes a secret store the cluster-wide source of truth
// and keeps a private local copy for OpenVPN. Existing local material is never
// overwritten silently; a mismatch requires an explicit rotation.
func (i Issuer) EnsureServerKeyInStore(ctx context.Context, path, secretID string, store SecretStore) error {
	if secretID == "" || store == nil {
		return errors.New("tls-crypt-v2 secret store configuration is required")
	}
	if !filepath.IsAbs(path) {
		return errors.New("server key must be an absolute path")
	}
	parent := filepath.Dir(path)
	if err := privateDirectory(parent); err != nil {
		return err
	}
	local, localErr := readPrivateKey(path, serverType)
	if localErr != nil && !errors.Is(localErr, os.ErrNotExist) {
		return localErr
	}
	if err := i.checkVersion(ctx); err != nil {
		return err
	}
	remote, err := store.Get(ctx, secretID)
	if errors.Is(err, ErrSecretNotFound) {
		candidate := local
		if localErr != nil {
			candidate, err = i.generate(ctx, parent, serverType, "")
			if err != nil {
				return err
			}
		}
		// Publish only the winner returned by the store, never our proposal.
		remote, err = store.CreateIfAbsent(ctx, secretID, candidate)
		if err != nil {
			return errors.New("cannot initialize tls-crypt-v2 secret")
		}
	} else if err != nil {
		return errors.New("cannot read tls-crypt-v2 secret")
	}
	if err := validateKey(remote, serverType); err != nil {
		return err
	}
	if localErr == nil {
		if !bytes.Equal(local, remote) {
			return errors.New("local tls-crypt-v2 key differs from cluster secret")
		}
		return nil
	}
	if err := publish(path, remote); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		// Another initializer on this host may have published the same winner.
		existing, readErr := readPrivateKey(path, serverType)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, remote) {
			return errors.New("local tls-crypt-v2 key differs from cluster secret")
		}
	}
	return nil
}

// Render fills the explicit inline slot; a server wrapping key cannot be used.
func Render(template, clientKey []byte) ([]byte, error) {
	if err := validateKey(clientKey, clientType); err != nil {
		return nil, err
	}
	source := strings.ReplaceAll(string(template), "\r\n", "\n")
	if !validTemplate(source) {
		return nil, errors.New("profile template must contain exactly one tls-crypt-v2 inline placeholder")
	}
	return []byte(strings.Replace(source, Placeholder, strings.TrimSpace(string(clientKey)), 1)), nil
}

func validTemplate(source string) bool {
	return strings.Count(source, Placeholder) == 1 && strings.Count(source, "<tls-crypt-v2>") == 1 &&
		strings.Count(source, "</tls-crypt-v2>") == 1 &&
		strings.Contains(source, "<tls-crypt-v2>\n"+Placeholder+"\n</tls-crypt-v2>")
}

// Issue creates one new per-profile key. The wrapping key never leaves its path
// except for OpenVPN reading it. The result is not an authorization credential:
// SAML must still approve the user and group for every VPN session.
func (i Issuer) Issue(ctx context.Context, serverKey string, template []byte, output string) error {
	if output == "" {
		return errors.New("profile output path is required")
	}
	if _, err := os.Lstat(output); err == nil {
		return errors.New("profile output already exists; choose a new filename")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := readPrivateKey(serverKey, serverType); err != nil {
		return err
	}
	if err := i.checkVersion(ctx); err != nil {
		return err
	}
	key, err := i.generate(ctx, filepath.Dir(serverKey), clientType, serverKey)
	if err != nil {
		return err
	}
	result, err := Render(template, key)
	if err != nil {
		return err
	}
	return publish(output, result)
}
