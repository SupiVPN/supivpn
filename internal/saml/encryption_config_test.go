// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
