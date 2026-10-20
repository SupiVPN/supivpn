// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package tracecontext carries W3C-compatible trace IDs without an exporter or
// synthetic spans. IDs are correlation metadata, never authentication material.
package tracecontext

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

type key struct{}

// ValidID accepts the canonical nonzero, 16-byte W3C TraceId representation.
func ValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	nonzero := false
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		nonzero = nonzero || c != '0'
	}
	return nonzero
}

func WithID(ctx context.Context, id string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if !ValidID(id) {
		id = ""
	}
	return context.WithValue(ctx, key{}, id)
}

func ID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(key{}).(string)
	return id
}

// New creates an independent request trace. No incoming HTTP trace headers are
// trusted. Failure to obtain entropy must not fall back to a predictable ID.
func New(ctx context.Context) context.Context {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return WithID(ctx, "")
	}
	return WithID(ctx, hex.EncodeToString(b[:]))
}

// ForLogin is called only for a locally generated or backend-validated ticket.
// It never exposes the bearer ticket or its database lookup hash. Production
// tickets contain 256 random bits; no username, IP, CID or timestamp is used.
func ForLogin(ticket string) string {
	if ticket == "" || len(ticket) > 128 {
		return ""
	}
	h := sha256.Sum256([]byte(ticket))
	return ForLoginHash(h[:])
}

// ForLoginHash reconstructs the same ID from an authorized stored login. Keep
// this domain/version stable: replicas and older/newer nodes must agree. The
// extra hash and truncation prevent a log reader from recovering the lookup key.
func ForLoginHash(hash []byte) string {
	if len(hash) != sha256.Size {
		return ""
	}
	h := sha256.New()
	h.Write([]byte("supivpn/login-trace/v1\x00"))
	h.Write(hash)
	id := hex.EncodeToString(h.Sum(nil)[:16])
	if !ValidID(id) {
		return ""
	}
	return id
}
