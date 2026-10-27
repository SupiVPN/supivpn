// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestShippedTemplatePreservesBoundServerIdentity(t *testing.T) {
	template, err := os.ReadFile("../../examples/client.ovpn.example")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../agent/testdata/client.ovpn.example")
	if err != nil || !bytes.Equal(fixture, template) {
		t.Fatal("native client tests must use the shipped template")
	}
	load := func(context.Context) ([]byte, error) { return testKey(serverType), nil }
	legacy, err := DownloadIssuer(template, "vpn.example.test", load)
	if err != nil {
		t.Fatal(err)
	}
	var saved Credential
	bound, err := BoundDownloadIssuer(template, "vpn.example.test", 1195, load,
		func(_ context.Context, c Credential, _ Owner) error { saved = c; return nil })
	if err != nil {
		t.Fatal(err)
	}
	legacyData, err := legacy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	boundData, err := bound(context.Background(), Owner{SubjectHash: [32]byte{1}, Username: "test-owner"})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{legacyData, boundData} {
		if bytes.Contains(data, []byte("remote-cert-ku")) || bytes.Contains(data, []byte("remote-cert-eku")) {
			t.Fatal("explicit KU/EKU directive returned to the portable template")
		}
		if !bytes.Contains(data, []byte("<ca>\n-----BEGIN CERTIFICATE-----")) ||
			!bytes.Contains(data, []byte("tls-version-min 1.2\n")) {
			t.Fatal("certificate trust or TLS minimum removed")
		}
	}
	if !saved.Valid() || !bytes.Contains(boundData, []byte("\nverify-x509-name vpn.example.test name\n")) ||
		!bytes.Contains(boundData, []byte(saved.Secret)) {
		t.Fatal("bound profile lost its server identity check or persisted proof")
	}
}
