// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package jsonobject rejects ambiguous JSON objects before typed decoding.
// Callers own input size limits and domain-specific validation.
package jsonobject

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
)

// Decode requires a single object with unique, case-sensitive field names.
// Values remain raw JSON; nested values are validated by the caller.
func Decode(r io.Reader) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(r)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid field")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, err
		}
		fields[name] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid object")
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return fields, nil
}

// Flat additionally requires allowlisted fields containing non-null scalars.
// This prevents encoding/json's case-insensitive struct matching from choosing
// between multiple spellings of a security-sensitive field.
func Flat(r io.Reader, permitted ...string) (map[string]json.RawMessage, error) {
	fields, err := Decode(r)
	if err != nil {
		return nil, err
	}
	for name, value := range fields {
		if !slices.Contains(permitted, name) {
			return nil, errors.New("invalid field")
		}
		if len(value) == 0 || value[0] == '{' || value[0] == '[' || string(value) == "null" {
			return nil, errors.New("invalid value")
		}
	}
	return fields, nil
}
