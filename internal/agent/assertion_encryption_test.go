// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/beevik/etree"
	"net/url"
	"os"
	"path/filepath"
	"supivpn/internal/saml"
	"testing"
	"time"
)

func enableAssertionEncryption(t *testing.T, sp *saml.ServiceProvider, config ...*saml.EncryptionConfig) func(*etree.Element) *etree.Element {
	t.Helper()
	recipient, _ := testIdP(t) // A separate ephemeral RSA key, never the IdP signing key.
	key := recipient.Key.(*rsa.PrivateKey)
	template := *recipient.Certificate
	template.KeyUsage = x509.KeyUsageKeyEncipherment
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(config) == 1 {
		dir := t.TempDir()
		config[0].Mode = saml.EncryptionRequired
		config[0].CertificateFile = filepath.Join(dir, "encryption.crt")
		config[0].PrivateKeyFile = filepath.Join(dir, "encryption.key")
		if os.WriteFile(config[0].CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600) != nil ||
			os.WriteFile(config[0].PrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600) != nil {
			t.Fatal("cannot write ephemeral encryption fixture")
		}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sp.AssertionEncryption, err = saml.NewAssertionEncryption(saml.EncryptionRequired, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	return func(root *etree.Element) *etree.Element {
		t.Helper()
		assertion := root.FindElement("./Assertion")
		// Response.Element serializes a typed assertion with its own namespace.
		d := etree.NewDocument()
		d.SetRoot(assertion.Copy())
		plaintext, err := d.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(plaintext)
		cek, nonce := make([]byte, 32), make([]byte, 12)
		if _, err = rand.Read(cek); err != nil {
			t.Fatal(err)
		}
		defer clear(cek)
		if _, err = rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(cek)
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
		wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, cek, nil)
		if err != nil {
			t.Fatal(err)
		}
		const x = "http://www.w3.org/2001/04/xmlenc#"
		const x11 = "http://www.w3.org/2009/xmlenc11#"
		const ds = "http://www.w3.org/2000/09/xmldsig#"
		wrapper := etree.NewElement("EncryptedAssertion")
		wrapper.CreateAttr("xmlns", saml.AssertionNamespace)
		wrapper.CreateAttr("xmlns:x", x)
		wrapper.CreateAttr("xmlns:x11", x11)
		wrapper.CreateAttr("xmlns:ds", ds)
		data := wrapper.CreateElement("x:EncryptedData")
		data.CreateAttr("Type", x+"Element")
		data.CreateElement("x:EncryptionMethod").CreateAttr("Algorithm", x11+"aes256-gcm")
		ek := data.CreateElement("ds:KeyInfo").CreateElement("x:EncryptedKey")
		method := ek.CreateElement("x:EncryptionMethod")
		method.CreateAttr("Algorithm", x11+"rsa-oaep")
		method.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", x+"sha256")
		method.CreateElement("x11:MGF").CreateAttr("Algorithm", x11+"mgf1sha256")
		ek.CreateElement("x:CipherData").CreateElement("x:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
		data.CreateElement("x:CipherData").CreateElement("x:CipherValue").SetText(base64.StdEncoding.EncodeToString(ciphertext))
		root.RemoveChild(assertion)
		root.AddChild(wrapper)
		return root
	}
}

func TestEncryptedVPNLogin(t *testing.T) {
	signer, md := testIdP(t)
	for _, name := range []string{"valid", "wrong-audience", "wrong-recipient", "expired", "no-group", "plaintext-downgrade"} {
		t.Run(name, func(t *testing.T) {
			app, commands := testApp(t, md)
			encrypt := enableAssertionEncryption(t, app.sp)
			assertion := assertionFor(app)
			switch name {
			case "wrong-audience":
				assertion.Conditions.AudienceRestrictions[0].Audience.Value = "https://other.example.test"
			case "wrong-recipient":
				assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = "https://other.example.test"
			case "expired":
				assertion.Conditions.NotOnOrAfter = assertion.Conditions.NotBefore
			case "no-group":
				assertion.Subject.NameID.Value = "unassigned-user"
			}
			values, err := url.ParseQuery(responseBody(t, app, signer, assertion, false, false))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(values.Get("SAMLResponse"))
			if err != nil {
				t.Fatal(err)
			}
			doc := etree.NewDocument()
			if doc.ReadFromBytes(raw) != nil {
				t.Fatal("response fixture")
			}
			root := doc.Root()
			if name != "plaintext-downgrade" {
				root = encrypt(root)
			}
			signing, err := saml.GetSigningContext(signer)
			if err != nil {
				t.Fatal(err)
			}
			root, err = signing.SignEnveloped(root)
			if err != nil {
				t.Fatal(err)
			}
			doc.SetRoot(root)
			raw, err = doc.WriteToBytes()
			if err != nil {
				t.Fatal(err)
			}
			values.Set("SAMLResponse", base64.StdEncoding.EncodeToString(raw))
			w := submit(app, values.Encode(), "test-browser")
			if name == "valid" {
				if w.Code != 200 {
					t.Fatalf("encrypted VPN login rejected: %d", w.Code)
				}
				select {
				case command := <-commands:
					if command != "client-auth-nt 7 2" {
						t.Fatal("no VPN admission")
					}
				case <-time.After(time.Second):
					t.Fatal("no admission command")
				}
				if submit(app, values.Encode(), "test-browser").Code == 200 {
					t.Fatal("encrypted assertion replay admitted")
				}
			} else if w.Code == 200 {
				t.Fatal("encryption bypassed VPN authorization")
			}
			select {
			case <-commands:
				t.Fatal("unexpected VPN admission")
			default:
			}
		})
	}
}
