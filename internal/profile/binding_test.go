// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBoundProfileIssuancePersistsBeforeDisclosure(t *testing.T) {
	template := []byte("client\nremote supivpn.example.test 1194\n<tls-crypt-v2>\n" + Placeholder + "\n</tls-crypt-v2>\n")
	owner := Owner{SubjectHash: [32]byte{1}, Username: "verified-owner"}
	calls := 0
	fail := false
	var saved Credential
	issue, err := BoundDownloadIssuer(template, "vpn.example.test", 1195, func(context.Context) ([]byte, error) { calls++; return testKey(serverType), nil }, func(_ context.Context, c Credential, subject Owner) error {
		if subject != owner {
			t.Fatal("unverified owner substituted")
		}
		saved = c
		if fail {
			return errors.New("synthetic failure")
		}
		return nil
	})
	if err != nil || calls != 0 {
		t.Fatal("construction loaded key")
	}
	if _, err = issue(context.Background(), Owner{}); err == nil || calls != 0 {
		t.Fatal("missing owner admitted")
	}
	data, err := issue(context.Background(), owner)
	if bytes.Contains(data, []byte(owner.Username)) {
		t.Fatal("owner label leaked into the profile")
	}
	if err != nil || !saved.Valid() || !bytes.Contains(data, []byte("verify-x509-name vpn.example.test name")) || !bytes.Contains(data, []byte("remote vpn.example.test 1195")) || !bytes.Contains(data, []byte(saved.Secret)) || !bytes.Contains(data, []byte("push-peer-info")) {
		t.Fatal("invalid bound profile")
	}
	fail = true
	data, err = issue(context.Background(), owner)
	if err == nil || len(data) != 0 {
		t.Fatal("persistence failure disclosed a profile")
	}
}

func TestProfileOwnerMetadataBounds(t *testing.T) {
	for _, name := range []string{"", "alice@example.test", "Unicode-Älice", "escaped\nlabel"} {
		if !(Owner{SubjectHash: [32]byte{1}, Username: name}).Valid() {
			t.Fatal("valid audit metadata rejected")
		}
	}
	for _, o := range []Owner{{}, {SubjectHash: [32]byte{1}, Username: strings.Repeat("x", 1025)}, {SubjectHash: [32]byte{1}, Username: "a\x00b"}, {SubjectHash: [32]byte{1}, Username: string([]byte{255})}} {
		if o.Valid() {
			t.Fatal("invalid owner metadata accepted")
		}
	}
}

func TestProfileCredentialIsolation(t *testing.T) {
	a, err := NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID || a.Secret == b.Secret || da == db {
		t.Fatal("profile proof reused")
	}
	mixed := Credential{ID: b.ID, Secret: a.Secret}
	dm, err := mixed.Digest()
	if err != nil || dm == da || dm == db {
		t.Fatal("proof digest is not bound to profile ID")
	}
	for _, bad := range []Credential{{}, {ID: a.ID, Secret: ""}, {ID: a.ID, Secret: a.Secret + "="}, {ID: strings.ToUpper(a.ID), Secret: a.Secret}, {ID: a.ID, Secret: strings.Repeat("!", 43)}, {ID: a.ID + "\n", Secret: a.Secret}} {
		if bad.Valid() {
			t.Fatal("malformed proof accepted")
		}
		if _, err := bad.Digest(); err == nil {
			t.Fatal("malformed proof hashed")
		}
	}
}

func TestProfileListenerFormatsAndAge(t *testing.T) {
	now := time.Unix(1800000000, 0)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(now.Unix()))
	bound := append([]byte(bindingMarker), ts...)
	if !VerifyClientMetadata("required", "0", bound, now, time.Hour) {
		t.Fatal("current metadata refused")
	}
	if !VerifyClientMetadata("legacy", "1", ts, now, time.Hour) {
		t.Fatal("explicit legacy metadata refused")
	}
	if VerifyClientMetadata("legacy", "1", ts, now.Add(time.Hour+time.Second), time.Hour) ||
		VerifyClientMetadata("legacy", "1", ts, now.Add(-301*time.Second), 0) ||
		VerifyClientMetadata("legacy", "1", ts, now, -time.Second) {
		t.Fatal("legacy gate ignored timestamp or age policy")
	}
	for _, tc := range []struct {
		mode, kind string
		data       []byte
	}{
		{"legacy", "0", ts}, {"legacy", "1", bound}, {"legacy", "1", nil},
		{"legacy", "0", bound}, {"required", "1", ts}, {"required", "0", append([]byte("SupiVPN/profile-auth/v2\x00"), ts...)},
		{"required", "0", bound[:len(bound)-1]}, {"legacy", "1", append(ts, 0)}, {"unknown", "1", ts},
	} {
		if VerifyClientMetadata(tc.mode, tc.kind, tc.data, now, time.Hour) {
			t.Fatal("cross-port or unknown metadata accepted")
		}
	}
	if VerifyClientMetadata("required", "0", bound, now.Add(time.Hour+time.Second), time.Hour) {
		t.Fatal("expired metadata accepted")
	}
	if VerifyClientMetadata("required", "0", bound, now.Add(-301*time.Second), 0) {
		t.Fatal("future metadata accepted")
	}
	if !VerifyClientMetadata("required", "0", bound, now.Add(10000*time.Hour), 0) {
		t.Fatal("zero max age imposed an expiry")
	}
}
