// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"crypto"
	"reflect"
	"strings"
	"testing"
)

// Fuzz edit operations, not a saved private key or a timestamped signed file.
// Each worker signs its own fresh fixture once. Every accepted mutation must
// decode to the SAME signed claims, including identity, groups and deadlines.
func FuzzSignedSAMLClaims(f *testing.F) {
	sp, signer, base := fixture(f)
	key, cert := encryptionFixture(f)
	sp.AssertionEncryption, _ = NewAssertionEncryption(EncryptionOptional, key, cert)
	var originals [][]byte
	var expected []*Assertion
	for _, mode := range []string{"response", "assertion", "both", "encrypted-response", "encrypted-assertion", "encrypted-both", "peer-response", "peer-assertion", "peer-both"} {
		root := base.Copy()
		if strings.HasPrefix(mode, "peer-") {
			signatures := strings.TrimPrefix(mode, "peer-")
			if signatures != "response" {
				root = signedFixture(f, signer, root, "assertion")
			}
			root = peerEncryptionKey(encryptFixture(f, root, &key.PublicKey, 32, true, crypto.SHA1, crypto.SHA1))
			if signatures != "assertion" {
				root = signedFixture(f, signer, root, "response")
			}
		} else if strings.HasPrefix(mode, "encrypted-") {
			root = encryptedResponse(f, signer, root, &key.PublicKey, strings.TrimPrefix(mode, "encrypted-"))
		} else {
			root = signedFixture(f, signer, root, mode)
		}
		data := document(f, root)
		a, err := sp.ParseXMLResponse(data, []string{"_request"}, sp.AcsURL)
		if err != nil {
			f.Fatal("valid signed fuzz fixture refused")
		}
		originals = append(originals, data)
		expected = append(expected, a)
	}
	for mode := byte(0); int(mode) < len(originals); mode++ {
		f.Add(mode, byte(0), uint32(0), []byte{})
		f.Add(mode, byte(0), uint32(0), []byte(" "))
		f.Add(mode, byte(1), uint32(50), []byte("<a:Assertion/>"))
		f.Add(mode, byte(2), uint32(50), []byte("remove"))
		f.Add(mode, byte(3), uint32(0), []byte("attacker"))
		f.Add(mode, byte(4), uint32(0), []byte("attacker-vpn"))
	}
	f.Fuzz(func(t *testing.T, mode, operation byte, offset uint32, edit []byte) {
		if len(edit) > 512 {
			return
		}
		index := int(mode) % len(originals)
		input := originals[index]
		at := int(offset % uint32(len(input)+1))
		end := min(at+len(edit), len(input))
		var mutated []byte
		switch operation % 5 {
		case 0: // Insert; empty edit and document whitespace are positive controls.
			mutated = append(mutated, input[:at]...)
			mutated = append(mutated, edit...)
			mutated = append(mutated, input[at:]...)
		case 1:
			mutated = append(mutated, input[:at]...)
			mutated = append(mutated, edit...)
			mutated = append(mutated, input[end:]...)
		case 2:
			mutated = append(mutated, input[:at]...)
			mutated = append(mutated, input[end:]...)
		case 3:
			mutated = bytes.ReplaceAll(input, []byte("test-user"), edit)
		case 4:
			mutated = bytes.ReplaceAll(input, []byte("admins-vpn"), edit)
		}
		claims, err := sp.ParseXMLResponse(mutated, []string{"_request"}, sp.AcsURL)
		if err == nil && !reflect.DeepEqual(claims, expected[index]) {
			t.Fatal("accepted XML mutation changed verified claims")
		}
		if operation%5 == 0 && len(edit) == 0 && err != nil {
			t.Fatal("unchanged signed positive control was rejected")
		}
	})
}
