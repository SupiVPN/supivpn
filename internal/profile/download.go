// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "encoding/pem"
    "errors"
    "io"
    "regexp"
    "strings"
    "time"
)

// GenerateClientKey encodes an interoperable tls-crypt-v2 client key using the
// documented OpenVPN wire format, with the standard timestamp metadata.
// It creates no server key and performs no storage or cloud operations.
func GenerateClientKey(serverPEM []byte, now time.Time) ([]byte, error) {
    return generateClientKey(serverPEM, now, rand.Reader)
}

func generateClientKey(serverPEM []byte, now time.Time, random io.Reader) ([]byte, error) {
    if err := validateKey(serverPEM, serverType); err != nil {
        return nil, err
    }
    if now.Unix() < 0 {
        return nil, errors.New("invalid key creation time")
    }
    server, _ := pem.Decode(serverPEM)
    defer clear(server.Bytes)
    // Each direction has 64 bytes of cipher material and 64 bytes of HMAC
    // material. AES-256 and HMAC-SHA256 use the first 32 bytes of their slots.
    plaintext := make([]byte, 256+9)
    defer clear(plaintext)
    if _, err := io.ReadFull(random, plaintext[:256]); err != nil {
        return nil, errors.New("client key randomness unavailable")
    }
    plaintext[256] = 1
    binary.BigEndian.PutUint64(plaintext[257:], uint64(now.Unix()))

    size := make([]byte, 2)
    binary.BigEndian.PutUint16(size, uint16(sha256.Size+len(plaintext)+len(size)))
    mac := hmac.New(sha256.New, server.Bytes[64:96])
    mac.Write(size)
    mac.Write(plaintext)
    tag := mac.Sum(nil)
    block, err := aes.NewCipher(server.Bytes[:32])
    if err != nil {
        return nil, errors.New("client key cipher unavailable")
    }
    encrypted := make([]byte, len(plaintext))
    cipher.NewCTR(block, tag[:aes.BlockSize]).XORKeyStream(encrypted, plaintext)
    encoded := make([]byte, 0, 256+len(tag)+len(encrypted)+len(size))
    encoded = append(encoded, plaintext[:256]...)
    encoded = append(encoded, tag...)
    encoded = append(encoded, encrypted...)
    encoded = append(encoded, size...)
    defer clear(encoded)
    return pem.EncodeToMemory(&pem.Block{Type: clientType, Bytes: encoded}), nil
}

// KeyFile loads the already provisioned wrapping key for a VM controller.
func KeyFile(path string) func(context.Context) ([]byte, error) {
    return func(ctx context.Context) ([]byte, error) {
        if ctx.Err() != nil {
            return nil, errors.New("profile request cancelled")
        }
        return readPrivateKey(path, serverType)
    }
}

var endpointPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// DownloadIssuer captures only the public template. The deployment adapter
// supplies a wrapping-key loader, called only after SAML authorization.
// The loader must return a caller-owned buffer; it is cleared after use.
func DownloadIssuer(template []byte, endpoint string, load func(context.Context) ([]byte, error)) (func(context.Context) ([]byte, error), error) {
    source := strings.ReplaceAll(string(template), "\r\n", "\n")
    remote := "remote supivpn.example.test 1194\n"
    slot := "<tls-crypt-v2>\n" + Placeholder + "\n</tls-crypt-v2>"
    if load == nil || !endpointPattern.MatchString(endpoint) || strings.Contains(endpoint, "..") ||
        len(source) > 64<<10 || strings.Count(source, remote) != 1 ||
        strings.Count(source, Placeholder) != 1 || !strings.Contains(source, slot) ||
        strings.Count(source, "<tls-crypt-v2>") != 1 || strings.Count(source, "</tls-crypt-v2>") != 1 {
        return nil, errors.New("invalid profile download configuration")
    }
    configured := []byte(strings.Replace(source, remote, "remote "+endpoint+" 1194\n", 1))
    return func(ctx context.Context) ([]byte, error) {
        if ctx.Err() != nil {
            return nil, errors.New("profile request cancelled")
        }
        server, err := load(ctx)
        if err != nil {
            return nil, errors.New("profile wrapping key unavailable")
        }
        defer clear(server)
        key, err := GenerateClientKey(server, time.Now())
        if err != nil {
            return nil, err
        }
        defer clear(key)
        if ctx.Err() != nil {
            return nil, errors.New("profile request cancelled")
        }
        return Render(configured, key)
    }, nil
}
