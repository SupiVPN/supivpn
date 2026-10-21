// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package jsonobject

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestObjectBoundary(t *testing.T) {
	for _, raw := range []string{
		``, `null`, `[]`, `1`, `"object"`, `{`, `{"a":`, `{"a":1`,
		`{"a":1,}`, `{"a":1]`, `{"a":1,"a":2}`, `{"a":1,"\u0061":2}`,
		`{} {}`, `{} null`, `{} garbage`, `{"a":{"invalid":}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(raw)); err == nil {
				t.Fatal("malformed or ambiguous object accepted")
			}
		})
	}
	// Recovery envelopes retain nested JSON and case-sensitive field names.
	const raw = `{"a":[{"id":1}],"A":null,"b":{"ok":true}}`
	got, err := Decode(strings.NewReader(raw))
	var want map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &want) != nil || err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("valid object changed during decoding")
	}
	if fields, err := Decode(strings.NewReader(" {} \n\t")); err != nil || len(fields) != 0 {
		t.Fatal("empty object or trailing whitespace refused")
	}
}

func TestFlatBoundary(t *testing.T) {
	for _, raw := range []string{
		`{"a":null}`, `{"a":[]}`, `{"a":{}}`, `{"A":1}`, `{"unknown":1}`,
		`{"a":1,"\u0061":2}`, `{"a":1} true`,
	} {
		if _, err := Flat(strings.NewReader(raw), "a"); err == nil {
			t.Fatalf("invalid flat object accepted: %s", raw)
		}
	}
	for _, value := range []string{`0`, `false`, `""`, `"\u0000"`, `1.5`, `1e1000`} {
		fields, err := Flat(strings.NewReader(`{"a":`+value+`}`), "a")
		if err != nil || string(fields["a"]) != value {
			t.Fatal("scalar changed before caller type/domain validation")
		}
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestObjectRequiresReaderEOF(t *testing.T) {
	for _, prefix := range []string{`{"a":`, `{}`} {
		_, err := Decode(io.MultiReader(strings.NewReader(prefix), failedReader{}))
		if err == nil || errors.Is(err, io.EOF) {
			t.Fatal("reader failure treated as complete object")
		}
	}
}
