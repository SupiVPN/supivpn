// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMetricsTLSListener(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	pair := fixture.TLS.Certificates[0]
	client := fixture.Client()
	client.Timeout = 2 * time.Second
	fixture.Close()
	dir := t.TempDir()
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal("test key serialization")
	}
	c := &Config{Enabled: true, TLSCertificate: filepath.Join(dir, "server.crt"), TLSPrivateKey: filepath.Join(dir, "server.key")}
	if err = os.WriteFile(c.TLSCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.TLSPrivateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = probe.Addr().String()
	probe.Close()
	stop, err := Listen(context.Background(), c, Handler(func(context.Context) ([]Family, error) { return nil, nil }))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	res, err := client.Get("https://" + c.Listen + "/metrics")
	if err != nil {
		t.Fatal("trusted scrape failed", err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.TLS == nil {
		t.Fatal("TLS scrape failed")
	}
	for _, path := range []string{"/", "/healthz", "/saml/metadata", "/metrics/"} {
		res, err = client.Get("https://" + c.Listen + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Fatal("metrics listener exposes another route")
		}
	}
	untrusted := &http.Client{Timeout: 2 * time.Second}
	if res, err = untrusted.Get("https://" + c.Listen + "/metrics"); err == nil {
		res.Body.Close()
		t.Fatal("untrusted server accepted")
	}
	res, err = untrusted.Get("http://" + c.Listen + "/metrics")
	if err == nil {
		res.Body.Close()
		if res.StatusCode == 200 {
			t.Fatal("cleartext metrics served")
		}
	}
}
