// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
    "bytes"
    "context"
    "encoding/pem"
    "errors"
    "strings"
    "testing"
    "time"
)

func TestPortableClientKeysAndFailurePaths(t *testing.T) {
    server := testKey(serverType)
    original := bytes.Clone(server)
    now := time.Unix(1800000000, 0)
    first, err := GenerateClientKey(server, now)
    if err != nil { t.Fatal(err) }
    second, err := GenerateClientKey(server, now)
    if err != nil { t.Fatal(err) }
    block, rest := pem.Decode(first)
    if block == nil || block.Type != clientType || len(rest) != 0 || len(block.Bytes) != 555 {
        t.Fatal("invalid timestamp-format client key")
    }
    if bytes.Equal(first, second) || !bytes.Equal(server, original) ||
        bytes.Contains(first, server) || bytes.Contains(first, []byte(serverType)) {
        t.Fatal("client key uniqueness or server-key isolation failed")
    }
    // Real OpenVPN 2.7.8 tests independently check unwrap/interoperability;
    // do not duplicate the production cryptographic algorithm in this test.
    for _, invalid := range [][]byte{nil, testKey(clientType), append(bytes.Clone(server), server...)} {
        if _, err := GenerateClientKey(invalid, now); err == nil { t.Fatal("invalid server key accepted") }
    }
    if _, err := GenerateClientKey(server, time.Unix(-1, 0)); err == nil {
        t.Fatal("negative timestamp accepted")
    }
    if _, err := generateClientKey(server, now, bytes.NewReader(make([]byte, 255))); err == nil {
        t.Fatal("short randomness input accepted")
    }
}

func TestDownloadIssuerLoadsOnlyOnDemandAndClearsOwnedKey(t *testing.T) {
    template := []byte("client\nremote supivpn.example.test 1194\n<tls-crypt-v2>\n" + Placeholder + "\n</tls-crypt-v2>\n")
    calls := 0
    var supplied []byte
    issue, err := DownloadIssuer(template, "vpn.example.test", func(context.Context) ([]byte, error) {
        calls++
        supplied = testKey(serverType)
        return supplied, nil
    })
    if err != nil || calls != 0 { t.Fatal("construction accessed wrapping key") }
    // The issuer owns a snapshot of the public template.
    clear(template)
    first, err := issue(context.Background())
    if err != nil { t.Fatal(err) }
    if calls != 1 || !bytes.Equal(supplied, make([]byte, len(supplied))) ||
        !bytes.Contains(first, []byte("remote vpn.example.test 1194\n")) ||
        bytes.Contains(first, []byte(Placeholder)) || bytes.Contains(first, []byte(serverType)) {
        t.Fatal("download template or key lifetime violated")
    }
    second, err := issue(context.Background())
    if err != nil || bytes.Equal(first, second) { t.Fatal("download did not issue a fresh key") }
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    before := calls
    if _, err := issue(ctx); err == nil || calls != before { t.Fatal("cancelled request loaded wrapping key") }
}

func TestDownloadConfigurationAndSecretErrors(t *testing.T) {
    template := []byte("client\nremote supivpn.example.test 1194\n<tls-crypt-v2>\n" + Placeholder + "\n</tls-crypt-v2>\n")
    load := func(context.Context) ([]byte, error) { return nil, errors.New("sensitive-loader-details") }
    for _, endpoint := range []string{"", "vpn.test\nverb 9", "https://vpn.test", "vpn..test", "vpn.test:1194"} {
        if _, err := DownloadIssuer(template, endpoint, load); err == nil { t.Fatal("invalid endpoint accepted") }
    }
    for _, source := range [][]byte{nil, append(bytes.Clone(template), template...), []byte(strings.Repeat("x", 65537))} {
        if _, err := DownloadIssuer(source, "vpn.test", load); err == nil { t.Fatal("invalid template accepted") }
    }
    issue, err := DownloadIssuer(template, "vpn.test", load)
    if err != nil { t.Fatal(err) }
    if _, err := issue(context.Background()); err == nil || strings.Contains(err.Error(), "sensitive-loader-details") {
        t.Fatal("loader details exposed")
    }
}

