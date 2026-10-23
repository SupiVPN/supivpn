// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"context"
	"encoding/json"
	"supivpn/internal/saml"
	"supivpn/internal/vm"
	"testing"
)

func TestAssertionEncryptionConfiguration(t *testing.T) {
	for _, mode := range []string{"", "disabled", "optional", "required", "typo"} {
		t.Run(mode, func(t *testing.T) {
			c := validConfig()
			c.AssertionEncryption = &saml.EncryptionConfig{Mode: mode}
			if mode == "optional" || mode == "required" {
				c.AssertionEncryption.CertificateFile = "/etc/supivpn/controller/encryption.crt"
				c.AssertionEncryption.PrivateKeyFile = "/etc/supivpn/controller/encryption.key"
			}
			data, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseConfig(string(data))
			if (err == nil) != (mode != "typo") {
				t.Fatal("mode parsing")
			}
			if mode == "typo" {
				return
			}
			if _, _, err = parsed.Policy(); err != nil {
				t.Fatal("valid mode refused")
			}
			if mode == "required" {
				c.VM = &vm.Config{TLSPrivateKey: c.AssertionEncryption.PrivateKeyFile}
				if _, _, err = c.Policy(); err == nil {
					t.Fatal("TLS key reuse accepted")
				}
			}
		})
	}
	for _, body := range []string{
		`{"assertion_encryption":{"mode":"optional"}}`,
		`{"assertion_encryption":{"mode":"disabled","private_key_file":"/not/read"}}`,
		`{"assertion_encryption":{"mode":"required","unknown":true}}`,
	} {
		if _, err := ParseConfig(body); err == nil {
			t.Fatal("invalid encryption settings accepted")
		}
	}
	c := validConfig()
	c.AssertionEncryption = &saml.EncryptionConfig{Mode: "required", CertificateFile: "/not/read/cert", PrivateKeyFile: "/not/read/key"}
	if _, err := OpenAgent(context.Background(), c, "", nil); err == nil {
		t.Fatal("agent component accepted SAML decryption configuration")
	}
}
