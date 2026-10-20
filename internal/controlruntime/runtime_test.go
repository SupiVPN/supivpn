// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controlruntime

import (
	"context"
    "bytes"
    "encoding/pem"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

    "supivpn/internal/gateway"
    "supivpn/internal/profile"
)

func validConfig() Config {
	return Config{PublicURL: "https://vpn.example.test", IDPMetadata: "/etc/supivpn/idp-metadata.xml", SAMLGroupsAttribute: "groups", Groups: []Group{{Name: "admins-vpn", Priority: 10}, {Name: "engineers-production-vpn", Priority: 20}}, PendingSeconds: 180, SessionSeconds: 900}
}
func TestControllerConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"http", func(c *Config) { c.PublicURL = "http://vpn.example.test" }},
		{"path", func(c *Config) { c.PublicURL += "/prefix" }},
		{"userinfo", func(c *Config) { c.PublicURL = "https://user@vpn.example.test" }},
		{"metadata-relative", func(c *Config) { c.IDPMetadata = "idp-metadata.xml" }},
		{"no-groups", func(c *Config) { c.Groups = nil }},
		{"duplicate-group", func(c *Config) { c.Groups = append(c.Groups, c.Groups[0]) }},
		{"empty-claim", func(c *Config) { c.SAMLGroupsAttribute = "" }},
		{"long-pending", func(c *Config) { c.PendingSeconds = 181 }},
		{"long-session", func(c *Config) { c.SessionSeconds = 43201 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.edit(&c)
			if _, _, err := c.Policy(); err == nil {
				t.Fatal("invalid controller configuration accepted")
			}
		})
	}
	c := validConfig()
	p, u, err := c.Policy()
	if err != nil || u.Host != "vpn.example.test" || p.Groups[0].GroupName != "admins-vpn" || p.SessionSeconds != 900 {
		t.Fatal("valid group policy changed")
	}
	path := filepath.Join(t.TempDir(), "controller.json")
	b, _ := json.Marshal(c)
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadConfig(path); err != nil {
		t.Fatal("cannot read valid config")
	}
	for _, body := range []string{string(b) + " {}", `{"unknown_field":true}`, strings.Repeat(" ", (64<<10)+1)} {
		if err = os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = ReadConfig(path); err == nil {
			t.Fatal("invalid config JSON accepted")
		}
	}
}
func TestBoundedKeepsCallerDeadline(t *testing.T) {
	outer, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := outer.Deadline()
	h := Bounded(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, ok := r.Context().Deadline()
		if !ok || d.After(deadline) {
			t.Error("request extended invocation deadline")
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "https://vpn.example.test/healthz", nil).WithContext(outer))
}

func TestRuntimeExamples(t *testing.T) {
	for _, name := range []string{"controller.vm.example.json", "controller.lambda.example.json"} {
		c, err := ReadConfig(filepath.Join("../../examples", name))
		if err != nil {
			t.Fatalf("%s cannot be parsed", name)
		}
		_, origin, err := c.Policy()
		if err != nil {
			t.Fatalf("%s policy invalid", name)
		}
		if c.VM != nil {
			if err = c.VM.Validate(); err != nil {
				t.Fatalf("%s VM config invalid", name)
			}
		}
		if c.Gateway != nil {
			if _, err = gateway.New(*c.Gateway, origin, http.NotFoundHandler(), http.NotFoundHandler()); err != nil {
				t.Fatalf("%s gateway config invalid", name)
			}
		}
	}
}

func TestProfileIssuerVMAndInjectedLoader(t *testing.T) {
    dir := t.TempDir()
    keyFile := filepath.Join(dir, "wrapping.key")
    templateFile := filepath.Join(dir, "client.template")
    key := pem.EncodeToMemory(&pem.Block{Type: "OpenVPN tls-crypt-v2 server key", Bytes: bytes.Repeat([]byte{7}, 128)})
    template := []byte("client\nremote supivpn.example.test 1194\n<tls-crypt-v2>\n" + profile.Placeholder + "\n</tls-crypt-v2>\n")
    if os.WriteFile(keyFile, key, 0600) != nil || os.WriteFile(templateFile, template, 0600) != nil {
        t.Fatal("cannot write ephemeral profile fixtures")
    }
    c := &ProfileConfig{Endpoint: "vpn.example.test", TemplateFile: templateFile, ServerKeyFile: keyFile}
    issue, err := profileIssuer(c, nil)
    if err != nil { t.Fatal(err) }
    if _, err := issue(context.Background()); err != nil { t.Fatal("VM issuer failed without AWS") }
    calls := 0
    injected := func(context.Context) ([]byte, error) { calls++; return bytes.Clone(key), nil }
    if _, err := profileIssuer(c, injected); err == nil { t.Fatal("ambiguous key sources accepted") }
    c.ServerKeyFile = ""
    issue, err = profileIssuer(c, injected)
    if err != nil || calls != 0 { t.Fatal("injected issuer loaded key at startup") }
    if _, err := issue(context.Background()); err != nil || calls != 1 { t.Fatal("injected issuer failed") }
    if _, err := profileIssuer(c, nil); err == nil { t.Fatal("missing wrapping-key source accepted") }
}
