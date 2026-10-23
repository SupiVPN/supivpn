// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/beevik/etree"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestXMLSecAssertionEncryption(t *testing.T) {
	binary := os.Getenv("SUPIVPN_TEST_XMLSEC")
	if binary == "" {
		t.Skip("set SUPIVPN_TEST_XMLSEC to run independent XMLSec checks")
	}
	sp, signer, base := fixture(t)
	key, cert := encryptionFixture(t)
	sp.AssertionEncryption, _ = NewAssertionEncryption(EncryptionRequired, key, cert)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "encryption-cert"), filepath.Join(dir, "encryption-key")
	write := func(path string, b []byte) {
		t.Helper()
		if os.WriteFile(path, b, 0600) != nil {
			t.Fatal("cannot write ephemeral XMLSec fixture")
		}
	}
	run := func(t *testing.T, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, binary, args...).Run() != nil {
			t.Fatal("independent XMLSec encryption operation failed")
		}
	}
	write(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	for _, bits := range []int{128, 256} {
		for _, legacy := range []bool{true, false} {
			t.Run(fmt.Sprintf("AES%d/legacy-%t", bits, legacy), func(t *testing.T) {
				// Sign the assertion independently with XMLSec, then encrypt that XML.
				signed := signedFixture(t, signer, base.Copy(), "assertion").FindElement("./Assertion")
				signKey, signCert := filepath.Join(dir, "signing-key"), filepath.Join(dir, "signing-cert")
				write(signKey, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signer.sp.Key.(*rsa.PrivateKey))}))
				write(signCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.sp.Certificate.Raw}))
				plainPath, signPath := filepath.Join(dir, "plain.xml"), filepath.Join(dir, "signed.xml")
				write(plainPath, document(t, signed))
				run(t, "--sign", "--privkey-pem", signKey+","+signCert, "--id-attr:ID", "Assertion", "--output", signPath, plainPath)
				alg, parameters := rsaOAEP10, ""
				template := fmt.Sprintf(`<x:EncryptedData xmlns:x="%s" xmlns:x11="%s" xmlns:ds="%s" Type="%sElement"><x:EncryptionMethod Algorithm="%saes%d-gcm"/><ds:KeyInfo><x:EncryptedKey><x:EncryptionMethod Algorithm="%s">%s</x:EncryptionMethod><x:CipherData><x:CipherValue/></x:CipherData></x:EncryptedKey></ds:KeyInfo><x:CipherData><x:CipherValue/></x:CipherData></x:EncryptedData>`, xencNamespace, xenc11Namespace, dsNamespace, xencNamespace, xenc11Namespace, bits, alg, parameters)
				templatePath, outPath := filepath.Join(dir, "template.xml"), filepath.Join(dir, "encrypted.xml")
				write(templatePath, []byte(template))
				run(t, "--encrypt", "--pubkey-cert-pem", certPath, "--session-key", fmt.Sprintf("aes-%d", bits), "--xml-data", signPath, "--output", outPath, templatePath)
				raw, err := os.ReadFile(outPath)
				if err != nil {
					t.Fatal("cannot read XMLSec result")
				}
				data, err := parseXML(raw)
				if err != nil {
					t.Fatal("invalid XMLSec encrypted XML")
				}
				if !legacy {
					// Debian XMLSec lacks the XML Encryption 1.1 OAEP URI. Keep
					// its AES-GCM payload and rewrap its CEK independently using
					// OpenSSL's SHA-256 OAEP/MGF1 implementation.
					ek := data.FindElement("./KeyInfo/EncryptedKey")
					wrapped, err := cipherValue(ek)
					if err != nil {
						t.Fatal("XMLSec key missing")
					}
					cek, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, wrapped, nil)
					if err != nil {
						t.Fatal("cannot unwrap ephemeral XMLSec key")
					}
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					cmd := exec.CommandContext(ctx, "openssl", "pkeyutl", "-encrypt", "-certin", "-inkey", certPath,
						"-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha256")
					cmd.Stdin = bytes.NewReader(cek)
					wrapped, err = cmd.Output()
					cancel()
					clear(cek)
					if err != nil {
						t.Fatal("independent OpenSSL OAEP operation failed")
					}
					ek.FindElement("./CipherData/CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
					method := ek.FindElement("./EncryptionMethod")
					method.CreateAttr("Algorithm", rsaOAEP)
					method.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestSHA256)
					method.CreateElement("x11:MGF").CreateAttr("Algorithm", xenc11Namespace+"mgf1sha256")
				}
				root := base.Copy()
				root.RemoveChild(root.FindElement("./Assertion"))
				wrapper := root.CreateElement("a:EncryptedAssertion")
				wrapper.AddChild(data)
				assertion, err := sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL)
				if err != nil || assertion.Subject.NameID.Value != "test-user" {
					t.Fatal("XMLSec encrypted assertion refused")
				}
				// The envelope also works with a verified outer signature over ciphertext.
				root = signedFixture(t, signer, root, "response")
				if _, err = sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err != nil {
					t.Fatal("signed encrypted response refused")
				}
				// Move the independently encrypted key into Okta's sibling layout.
				// The ciphertext and authenticated assertion remain unchanged.
				root.RemoveChild(root.FindElement("./Signature"))
				root = peerEncryptionKey(root)
				if _, err = sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err != nil {
					t.Fatal("XMLSec sibling encrypted key refused")
				}
				root = signedFixture(t, signer, root, "response")
				if _, err = sp.ParseXMLResponse(document(t, root), []string{"_request"}, sp.AcsURL); err != nil {
					t.Fatal("signed XMLSec sibling encrypted key refused")
				}
				// No library-specific re-encryption is needed to decrypt the original payload.
				plainOut := filepath.Join(dir, "decrypted.xml")
				run(t, "--decrypt", "--privkey-pem", keyPath, "--output", plainOut, outPath)
				decrypted, err := os.ReadFile(plainOut)
				if err != nil {
					t.Fatal("XMLSec decryption failed")
				}
				doc := etree.NewDocument()
				if doc.ReadFromBytes(decrypted) != nil {
					t.Fatal("XMLSec plaintext invalid")
				}
				if _, err := verifySignature(doc.Root(), []*x509.Certificate{signer.sp.Certificate}); err != nil {
					t.Fatal("independent roundtrip changed signature")
				}
			})
		}
	}
}
