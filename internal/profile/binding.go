// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// BoundDownloadIssuer creates the proof only after the controller has verified
// SAML, and persists ownership before returning a profile. Failed persistence
// never produces a usable download.
func BoundDownloadIssuer(template []byte, endpoint string, port uint16, load func(context.Context) ([]byte, error), save func(context.Context, Credential, [32]byte) error) (func(context.Context, [32]byte) ([]byte, error), error) {
	if save == nil || port == 0 {
		return nil, errors.New("invalid bound profile configuration")
	}
	if _, err := DownloadIssuer(template, endpoint, load); err != nil {
		return nil, err
	}
	source := strings.ReplaceAll(string(template), "\r\n", "\n")
	// Replace legacy template guidance that no longer describes a bound profile.
	source = strings.ReplaceAll(source, "# TEMPORARY: server certificate name verification is intentionally disabled.\n", "# Verify the VPN server's exact certificate common name before sending the profile proof.\n")
	source = strings.ReplaceAll(source, "# This can accept other servers with certificates chaining to the same trusted CA.\n", "")
	source = strings.ReplaceAll(source, "# Deliberately no client cert/key or auth-user-pass. SAML still authorizes access.\n", "# No client certificate. The opaque profile proof and its verified SAML owner authorize access.\n")
	configured := []byte(strings.Replace(source, "remote supivpn.example.test 1194\n", "remote "+endpoint+" "+strconv.Itoa(int(port))+"\n", 1))
	// A profile now contains a bearer proof. Validate the VPN server identity
	// before sending it, in addition to the template's CA/purpose validation.
	configured = append(configured, []byte("\nverify-x509-name "+endpoint+" name\n")...)
	return func(ctx context.Context, subject [32]byte) ([]byte, error) {
		if ctx.Err() != nil || subject == [32]byte{} {
			return nil, errors.New("profile authorization unavailable")
		}
		credential, err := NewCredential()
		if err != nil {
			return nil, err
		}
		server, err := load(ctx)
		if err != nil {
			return nil, errors.New("profile wrapping key unavailable")
		}
		defer clear(server)
		key, err := GenerateBoundClientKey(server, time.Now())
		if err != nil {
			return nil, err
		}
		defer clear(key)
		data, err := RenderBound(configured, key, credential)
		if err != nil {
			return nil, err
		}
		if err = save(ctx, credential, subject); err != nil {
			clear(data)
			return nil, errors.New("profile ownership unavailable")
		}
		return data, nil
	}, nil
}

const bindingMarker = "SupiVPN/profile-auth/v1\x00"

// Credential is an independent bearer proof, never an IdP password or SAML token.
// Only its digest and opaque ID belong in persistent state. Possession does not
// grant VPN access: the verified SAML subject must also match its active owner.
type Credential struct{ ID, Secret string }

func NewCredential() (Credential, error) {
	var entropy [48]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return Credential{}, errors.New("profile randomness unavailable")
	}
	defer clear(entropy[:])
	return Credential{ID: "svp1_" + hex.EncodeToString(entropy[:16]), Secret: base64.RawURLEncoding.EncodeToString(entropy[16:])}, nil
}

func ValidProfileID(id string) bool {
	if len(id) != 37 || !strings.HasPrefix(id, "svp1_") {
		return false
	}
	decoded, err := hex.DecodeString(id[5:])
	return err == nil && hex.EncodeToString(decoded) == id[5:]
}

func (c Credential) Valid() bool {
	decoded, err := base64.RawURLEncoding.DecodeString(c.Secret)
	defer clear(decoded)
	return ValidProfileID(c.ID) && err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == c.Secret
}

func (c Credential) Digest() ([32]byte, error) {
	if !c.Valid() {
		return [32]byte{}, errors.New("invalid profile credential")
	}
	return sha256.Sum256([]byte("SupiVPN/profile-proof/v1\x00" + c.ID + "\x00" + c.Secret)), nil
}

// GenerateBoundClientKey uses authenticated user metadata to prevent a new
// profile from being replayed against a separately configured legacy listener.
// The metadata contains only a format marker and creation time, never identity.
func GenerateBoundClientKey(serverPEM []byte, now time.Time) ([]byte, error) {
	if now.Unix() < 0 {
		return nil, errors.New("invalid key creation time")
	}
	metadata := make([]byte, 1+len(bindingMarker)+8)
	copy(metadata[1:], bindingMarker)
	binary.BigEndian.PutUint64(metadata[1+len(bindingMarker):], uint64(now.Unix()))
	return generateClientKeyWithMetadata(serverPEM, metadata, rand.Reader)
}

// VerifyClientMetadata consumes OpenVPN's metadata_file (which omits the type
// byte), after OpenVPN has authenticated it using the wrapping key. Bound and
// legacy listeners accept disjoint formats. maxAge zero means no age limit.
func VerifyClientMetadata(mode string, kind string, data []byte, now time.Time, maxAge time.Duration) bool {
	if maxAge < 0 || now.Unix() < 0 {
		return false
	}
	var timestamp []byte
	switch mode {
	case "legacy":
		if kind != "1" || len(data) != 8 {
			return false
		}
		timestamp = data
	case "required":
		if kind != "0" || len(data) != len(bindingMarker)+8 || string(data[:len(bindingMarker)]) != bindingMarker {
			return false
		}
		timestamp = data[len(bindingMarker):]
	default:
		return false
	}
	issued := binary.BigEndian.Uint64(timestamp)
	current := uint64(now.Unix())
	if issued > current+300 {
		return false
	}
	return maxAge == 0 || issued >= current || current-issued <= uint64(maxAge/time.Second)
}

// RenderBound preserves the existing template validation, then adds an opaque
// proof. The caller persists its owner/digest before returning bytes to a user.
func RenderBound(template, key []byte, credential Credential) ([]byte, error) {
	if !credential.Valid() {
		return nil, errors.New("invalid bound profile configuration")
	}
	data, err := Render(template, key)
	if err != nil {
		return nil, err
	}
	return append(data, []byte("\npush-peer-info\n<auth-user-pass>\n"+credential.ID+"\n"+credential.Secret+"\n</auth-user-pass>\n")...), nil
}
