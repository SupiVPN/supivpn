// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptionSecretLoading(t *testing.T) {
	key, cert := encryptionFixture(t)
	certPath := filepath.Join(t.TempDir(), "recipient.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	defer clear(private)
	const reference = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:saml-recipient-Ab12Cd"
	for _, mode := range []string{EncryptionOptional, EncryptionRequired} {
		for _, name := range []string{"pkcs1", "pkcs8", "provider-error", "empty", "oversized", "junk", "prefix", "suffix", "multiple", "headers", "non-rsa", "wrong-key", "cancelled"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				c := &EncryptionConfig{Mode: mode, CertificateFile: certPath, PrivateKeySecretARN: reference}
				var supplied []byte
				calls := 0
				load := func(ctx context.Context, id string) ([]byte, error) {
					calls++
					if id != reference {
						t.Fatal("secret reference changed")
					}
					supplied = bytes.Clone(private)
					switch name {
					case "pkcs8":
						der, err := x509.MarshalPKCS8PrivateKey(key)
						if err != nil {
							t.Fatal(err)
						}
						supplied = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
					case "provider-error":
						return supplied, errors.New("provider-sensitive-details")
					case "empty":
						supplied = nil
					case "oversized":
						supplied = bytes.Repeat([]byte("x"), (64<<10)+1)
					case "junk":
						supplied = []byte("not a private key")
					case "prefix":
						supplied = append([]byte("junk\n"), supplied...)
					case "suffix":
						supplied = append(supplied, []byte("junk")...)
					case "multiple":
						supplied = append(supplied, private...)
					case "headers":
						supplied = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"X-Test": "refuse"}, Bytes: x509.MarshalPKCS1PrivateKey(key)})
					case "non-rsa":
						supplied = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
					case "wrong-key":
						other, _ := encryptionFixture(t)
						supplied = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
					case "cancelled":
						cancel()
					}
					return supplied, nil
				}
				state, err := c.LoadWithKey(ctx, load)
				valid := name == "pkcs1" || name == "pkcs8"
				if calls != 1 || (err == nil) != valid || (state != nil) != valid {
					t.Fatal("secret key validation failed")
				}
				if !bytes.Equal(supplied, make([]byte, len(supplied))) {
					t.Fatal("caller-owned PEM was not cleared")
				}
				if err != nil && strings.Contains(err.Error(), "sensitive") {
					t.Fatal("provider details escaped")
				}
				if !valid {
					return
				}
				sp, signer, base := fixture(t)
				sp.AssertionEncryption = state
				encrypted := encryptedResponse(t, signer, base, &key.PublicKey, "both")
				if _, err := sp.ParseXMLResponse(document(t, encrypted), []string{"_request"}, sp.AcsURL); err != nil {
					t.Fatal("loaded key cannot decrypt signed assertion")
				}
				plaintext := signedFixture(t, signer, base.Copy(), "both")
				_, err = sp.ParseXMLResponse(document(t, plaintext), []string{"_request"}, sp.AcsURL)
				if (err == nil) != (mode == EncryptionOptional) || calls != 1 {
					t.Fatal("mode changed or secret reloaded during request")
				}
			})
		}
	}
	load := func(context.Context, string) ([]byte, error) { t.Fatal("unconfigured secret read"); return nil, nil }
	for _, c := range []*EncryptionConfig{nil, {}, {Mode: EncryptionDisabled}} {
		if state, err := c.LoadWithKey(context.Background(), load); err != nil || state != nil {
			t.Fatal("disabled behavior changed")
		}
	}
	for _, c := range []*EncryptionConfig{
		{Mode: EncryptionDisabled, PrivateKeySecretARN: reference},
		{Mode: EncryptionRequired, CertificateFile: certPath, PrivateKeyFile: "/not/read", PrivateKeySecretARN: reference},
		{Mode: EncryptionRequired, PrivateKeySecretARN: reference},
	} {
		if _, err := c.LoadWithKey(context.Background(), load); err == nil {
			t.Fatal("conflicting or incomplete source accepted")
		}
	}
	c := &EncryptionConfig{Mode: EncryptionRequired, CertificateFile: certPath, PrivateKeySecretARN: reference}
	if _, err := c.Load(); err == nil {
		t.Fatal("secret reference silently fell back to filesystem")
	}
}

func TestEncryptionConfiguration(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []*EncryptionConfig{nil, {}, {Mode: EncryptionDisabled}} {
		state, err := c.Load()
		if err != nil || state != nil {
			t.Fatal("disabled default changed")
		}
	}
	for _, c := range []*EncryptionConfig{
		{Mode: "enabled"}, {Mode: "Optional"}, {Mode: EncryptionDisabled, PrivateKeyFile: "/not/read"},
		{Mode: EncryptionOptional}, {Mode: EncryptionRequired, CertificateFile: "relative", PrivateKeyFile: "/not/read"},
		{Mode: EncryptionOptional, CertificateFile: "/same", PrivateKeyFile: "/same"},
	} {
		if c.Validate() == nil {
			t.Fatal("unsafe encryption configuration accepted")
		}
	}
	key, cert := encryptionFixture(t)
	certPath, keyPath := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	write := func(p string, b []byte, mode os.FileMode) {
		t.Helper()
		if _, err := os.Stat(p); err == nil {
			if os.Chmod(p, 0600) != nil {
				t.Fatal("fixture permissions")
			}
		}
		if os.WriteFile(p, b, mode) != nil || os.Chmod(p, mode) != nil {
			t.Fatal("fixture write failed")
		}
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	c := &EncryptionConfig{Mode: EncryptionRequired, CertificateFile: certPath, PrivateKeyFile: keyPath}
	write(certPath, public, 0644)
	for _, mode := range []os.FileMode{0600, 0640, 0400, 0440} {
		write(keyPath, private, mode)
		if _, err := c.Load(); err != nil {
			t.Fatal("readable private key permissions refused")
		}
	}
	for _, mode := range []os.FileMode{0644, 0660, 0700} {
		write(keyPath, private, mode)
		if _, err := c.Load(); err == nil {
			t.Fatal("unsafe key permissions accepted")
		}
	}
	write(keyPath, private, 0600)
	if _, err := c.LoadWithKey(context.Background(), func(context.Context, string) ([]byte, error) {
		t.Fatal("file source invoked cloud loader")
		return nil, nil
	}); err != nil {
		t.Fatal("explicit file source changed when a cloud adapter is available")
	}
	for _, name := range []string{"symlink", "directory", "missing", "oversized", "multiple-blocks", "junk", "wrong-key", "pkcs8"} {
		t.Run(name, func(t *testing.T) {
			copy := *c
			p := filepath.Join(dir, name)
			copy.PrivateKeyFile = p
			switch name {
			case "symlink":
				if os.Symlink(keyPath, p) != nil {
					t.Fatal("symlink fixture")
				}
			case "directory":
				if os.Mkdir(p, 0700) != nil {
					t.Fatal("directory fixture")
				}
			case "missing":
			case "oversized":
				write(p, make([]byte, 65537), 0600)
			case "multiple-blocks":
				write(p, append(append([]byte(nil), private...), private...), 0600)
			case "junk":
				write(p, []byte("not a key"), 0600)
			case "wrong-key":
				other, _ := encryptionFixture(t)
				write(p, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)}), 0600)
			case "pkcs8":
				der, err := x509.MarshalPKCS8PrivateKey(key)
				if err != nil {
					t.Fatal(err)
				}
				write(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
			}
			_, err := copy.Load()
			if (err == nil) != (name == "pkcs8") {
				t.Fatal("key file policy not enforced")
			}
		})
	}
}
func TestEncryptionCertificatePolicy(t *testing.T) {
	key, cert := encryptionFixture(t)
	for _, name := range []string{"valid", "expired", "future", "signing-only", "weak-rsa", "wrong-key", "missing-key", "missing-cert", "unknown-mode", "disabled-with-key"} {
		t.Run(name, func(t *testing.T) {
			k, c := key, *cert
			mode := EncryptionRequired
			switch name {
			case "expired":
				c.NotAfter = time.Now().Add(-time.Second)
			case "future":
				c.NotBefore = time.Now().Add(time.Hour)
			case "signing-only":
				c.KeyUsage = x509.KeyUsageDigitalSignature
			case "weak-rsa":
				var err error
				k, err = rsa.GenerateKey(rand.Reader, 1024)
				if err != nil {
					t.Fatal(err)
				}
				c.PublicKey = &k.PublicKey
			case "wrong-key":
				k, _ = encryptionFixture(t)
			case "missing-key":
				k = nil
			case "unknown-mode":
				mode = "typo"
			case "disabled-with-key":
				mode = EncryptionDisabled
			}
			cp := &c
			if name == "missing-cert" {
				cp = nil
			}
			_, err := NewAssertionEncryption(mode, k, cp)
			if (err == nil) != (name == "valid") {
				t.Fatal("encryption certificate policy not enforced")
			}
		})
	}
}
