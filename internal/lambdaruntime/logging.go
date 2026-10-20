// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package lambdaruntime

import (
	"context"

	"supivpn/internal/logging"
	"supivpn/internal/tracecontext"

	"github.com/aws/aws-lambda-go/lambdacontext"
)

// Keep invocation metadata in the request context. Warm/concurrent invocations
// must never inherit another request's ID; no event body or HTTP header is logged.
func withInvocation[T, R any](next func(context.Context, T) (R, error)) func(context.Context, T) (R, error) {
	return func(ctx context.Context, event T) (R, error) {
		ctx = tracecontext.New(ctx)
		if invocation, ok := lambdacontext.FromContext(ctx); ok {
			ctx = logging.WithRequestID(ctx, invocation.AwsRequestID)
		}
		result, err := next(ctx, event)
		if err != nil {
			logging.Emit(ctx, "invocation.failed")
		}
		return result, err
	}
}
