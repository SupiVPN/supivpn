// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"supivpn/internal/gateway"
	"supivpn/internal/saml"
	"supivpn/internal/vm"
)

func TestPublicEncryptionSecretInitialization(t *testing.T) {
	// Only public certificates/metadata are written. The ephemeral private key
	// reaches the production runtime exclusively through the injected loader.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	defer clear(private)
	dir := t.TempDir()
	c := validConfig()
	c.Gateway = &gateway.Config{}
	c.IDPMetadata = filepath.Join(dir, "idp.xml")
	c.AssertionEncryption = &saml.EncryptionConfig{CertificateFile: filepath.Join(dir, "recipient.crt"), PrivateKeySecretARN: "arn:aws:secretsmanager:eu-west-1:123456789012:secret:saml-recipient-Ab12Cd"}
	metadata := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(der) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/sso"/></IDPSSODescriptor></EntityDescriptor>`
	if os.WriteFile(c.IDPMetadata, []byte(metadata), 0600) != nil || os.WriteFile(c.AssertionEncryption.CertificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644) != nil {
		t.Fatal("public fixture write failed")
	}
	for _, mode := range []string{saml.EncryptionOptional, saml.EncryptionRequired} {
		t.Run(mode, func(t *testing.T) {
			c.AssertionEncryption.Mode = mode
			raw, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseConfig(string(raw))
			if err != nil {
				t.Fatal("secret-source configuration was not parsed")
			}
			for _, unavailable := range []bool{false, true} {
				calls := 0
				var supplied []byte
				load := func(ctx context.Context, id string) ([]byte, error) {
					calls++
					if id != c.AssertionEncryption.PrivateKeySecretARN || ctx.Err() != nil {
						t.Fatal("loader lost context or secret reference")
					}
					if unavailable {
						return nil, errors.New("provider-sensitive-details")
					}
					supplied = bytes.Clone(private)
					return supplied, nil
				}
				profileKey := func(context.Context) ([]byte, error) {
					t.Fatal("profile key read during initialization")
					return nil, nil
				}
				app, err := OpenPublicWithEncryptionKey(context.Background(), parsed, "", nil, profileKey, load)
				want := "database configuration required" // Empty DSN stops before connecting.
				if unavailable {
					want = "cannot load SAML encryption private key"
				}
				if app != nil || err == nil || err.Error() != want || calls != 1 {
					t.Fatal("runtime key delivery did not precede database access")
				}
				if !bytes.Equal(supplied, make([]byte, len(supplied))) {
					t.Fatal("runtime retained PEM buffer")
				}
			}
			if _, err := OpenPublic(context.Background(), parsed, "", nil, nil); err == nil || err.Error() != "SAML encryption secret loader unavailable" {
				t.Fatal("missing adapter was not refused")
			}
			if _, err := OpenAgent(context.Background(), parsed, "", nil); err == nil {
				t.Fatal("agent accepted SAML encryption configuration")
			}
			parsed.VM = &vm.Config{}
			if _, _, err := parsed.Policy(); err == nil {
				t.Fatal("VM accepted Lambda-only secret source")
			}
			parsed.VM = nil
			parsed.Gateway = nil
			if _, _, err := parsed.Policy(); err == nil {
				t.Fatal("combined controller accepted Lambda-only secret source")
			}
		})
	}
}
