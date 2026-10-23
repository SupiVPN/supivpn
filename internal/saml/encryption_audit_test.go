// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// pem.Decode can skip a malformed leading block and return a later valid one.
// Provisioned files must describe exactly one object, not a parser-dependent
// choice between multiple apparent objects.
func TestEncryptionPEMRejectsSkippedLeadingBlocks(t *testing.T) {
	key, cert := encryptionFixture(t)
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	for _, kind := range []string{"key", "certificate"} {
		for _, malformed := range []string{"invalid-body", "missing-end"} {
			t.Run(kind+"/"+malformed, func(t *testing.T) {
				dir := t.TempDir()
				keyPath, certPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
				keyData, certData := private, public
				label, good := "RSA PRIVATE KEY", private
				if kind == "certificate" {
					label, good = "CERTIFICATE", public
				}
				prefix := "-----BEGIN " + label + "-----\ninvalid\n"
				if malformed == "invalid-body" {
					prefix += "-----END " + label + "-----\n"
				}
				bad := append([]byte(prefix), good...)
				if kind == "key" {
					keyData = bad
				} else {
					certData = bad
				}
				if os.WriteFile(keyPath, keyData, 0600) != nil || os.WriteFile(certPath, certData, 0644) != nil {
					t.Fatal("fixture write failed")
				}
				config := EncryptionConfig{Mode: EncryptionRequired, PrivateKeyFile: keyPath, CertificateFile: certPath}
				if _, err := config.Load(); err == nil {
					t.Fatal("accepted a skipped leading PEM block")
				}
			})
		}
	}
}
