// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-lambda-go/events"
)

// HTTPHandler has no recovery/operator callbacks. Event routing is a guard,
// not caller authentication: Lambda resource policies must restrict invocation.
func HTTPHandler(rest func(context.Context, events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		var fields map[string]json.RawMessage
		if len(raw) > 2<<20 || json.Unmarshal(raw, &fields) != nil || fields == nil {
			return nil, errors.New("invalid HTTP invocation")
		}
		for _, name := range []string{"source", "detail-type", "resources", "action"} {
			if _, ok := fields[name]; ok {
				return nil, errors.New("non-HTTP invocation refused")
			}
		}
		var e events.APIGatewayProxyRequest
		if json.Unmarshal(raw, &e) != nil {
			return nil, errors.New("invalid HTTP invocation")
		}
		return rest(ctx, e)
	}
}
