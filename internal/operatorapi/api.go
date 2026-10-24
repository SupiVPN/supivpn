// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package operatorapi handles a small, explicitly privileged operator protocol.
// It has no HTTP routes and must not be attached to the agent/public listeners.
package operatorapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"supivpn/internal/jsonobject"
	"supivpn/internal/postgres"
)

const Source = "supivpn.operator.v1"

type Store interface {
	Operate(context.Context, postgres.OperatorRequest) (postgres.OperatorState, error)
}
type Reply struct {
	OK    bool                    `json:"ok"`
	State *postgres.OperatorState `json:"state,omitempty"`
	Error string                  `json:"error,omitempty"`
}

func Decode(raw []byte) (postgres.OperatorRequest, error) {
	var q postgres.OperatorRequest
	refused := errors.New("invalid operator request")
	if len(raw) > 8192 {
		return q, refused
	}
	fields, err := jsonobject.Flat(bytes.NewReader(raw), "source", "action", "node_id", "expected_generation",
		"profile_id", "recovery_id", "expected_revision", "maintenance_id", "request_id", "reason")
	if err != nil {
		return q, refused
	}
	var source string
	if json.Unmarshal(fields["source"], &source) != nil || source != Source {
		return q, refused
	}
	delete(fields, "source")
	b, err := json.Marshal(fields)
	if err != nil || json.Unmarshal(b, &q) != nil {
		return q, refused
	}
	return q, nil
}
func Handler(s Store) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		q, err := Decode(raw)
		if err != nil || s == nil {
			return Reply{Error: "invalid_request"}, nil
		}
		state, err := s.Operate(ctx, q)
		if err != nil {
			code := "unavailable"
			if errors.Is(err, postgres.ErrConflict) || errors.Is(err, postgres.ErrGeneration) {
				code = "conflict"
			}
			return Reply{Error: code}, nil
		}
		return Reply{OK: true, State: &state}, nil
	}
}
