// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"crypto/x509"
	"encoding/base64"
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

func TestEncryptionKeyHintsCannotChangeTrust(t *testing.T) {
	sp, signer, base := fixture(t)
	_, untrustedSigner, _ := fixture(t)
	key, cert := encryptionFixture(t)
	otherKey, otherCert := encryptionFixture(t)
	var err error
	sp.AssertionEncryption, err = NewAssertionEncryption(EncryptionRequired, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	for _, layout := range []string{"inline", "peer"} {
		for _, name := range []string{"untrusted-hint", "unsigned-assertion", "untrusted-signature", "wrong-recipient-key"} {
			t.Run(layout+"/"+name, func(t *testing.T) {
				ctx, recipient, signatures := signer, &key.PublicKey, "assertion"
				if name == "unsigned-assertion" {
					signatures = "none"
				}
				if name == "untrusted-signature" {
					ctx = untrustedSigner
				}
				if name == "wrong-recipient-key" {
					recipient = &otherKey.PublicKey
				}
				root := encryptedResponse(t, ctx, base, recipient, signatures)
				path := "./EncryptedAssertion/EncryptedData/KeyInfo/EncryptedKey"
				if layout == "peer" {
					root = peerEncryptionKey(root)
					path = "./EncryptedAssertion/EncryptedKey"
				}
				info := root.FindElement(path).CreateElement("ds:KeyInfo")
				info.CreateElement("ds:KeyName").SetText("https://unused.example.test/keys")
				hint := signer.sp.Certificate
				if name == "untrusted-hint" {
					hint = otherCert
				}
				if name == "wrong-recipient-key" {
					hint = cert
				}
				info.CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(hint.Raw))
				_, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL)
				if (err == nil) != (name == "untrusted-hint") {
					t.Fatal("descriptive key hints changed trust or recipient-key selection")
				}
			})
		}
	}
}
