// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"supivpn/internal/operatorapi"
)

// RecoveryHandler has no HTTP callback. IAM must restrict direct invocation to
// the exact scheduler rule and authorized operators; event fields are not auth.
func RecoveryHandler(tick func(context.Context) error, rule string, operator func(context.Context, json.RawMessage) (any, error)) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		refused := errors.New("untrusted recovery invocation")
		if len(raw) > 8192 {
			return nil, refused
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		token, err := d.Token()
		if err != nil || token != json.Delim('{') {
			return nil, refused
		}
		fields := map[string]json.RawMessage{}
		for d.More() {
			token, err = d.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return nil, refused
			}
			if _, duplicate := fields[key]; duplicate {
				return nil, refused
			}
			var v json.RawMessage
			if d.Decode(&v) != nil {
				return nil, refused
			}
			fields[key] = v
		}
		if token, err = d.Token(); err != nil || token != json.Delim('}') {
			return nil, refused
		}
		if _, err = d.Token(); err != io.EOF {
			return nil, refused
		}
		var source, kind string
		var resources []string
		if json.Unmarshal(fields["source"], &source) != nil {
			return nil, refused
		}
		if source == operatorapi.Source && operator != nil {
			if _, err := operatorapi.Decode(raw); err != nil {
				return nil, refused
			}
			return operator(ctx, raw)
		}
		for key := range fields {
			if !slices.Contains([]string{"source", "detail-type", "resources", "version", "id", "account", "time", "region", "detail"}, key) {
				return nil, refused
			}
		}
		if source != "aws.events" || tick == nil || rule == "" ||
			json.Unmarshal(fields["detail-type"], &kind) != nil || kind != "Scheduled Event" ||
			json.Unmarshal(fields["resources"], &resources) != nil || len(resources) != 1 || resources[0] != rule {
			return nil, refused
		}
		if err := tick(ctx); err != nil {
			return nil, errors.New("recovery unavailable")
		}
		return struct{}{}, nil
	}
}
