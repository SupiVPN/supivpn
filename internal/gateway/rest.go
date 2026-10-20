// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-lambda-go/events"
)

// HandleREST accepts only trusted REST API Lambda proxy envelopes. The deployment
// must restrict InvokeFunction to this API/stage and use AWS_IAM on agent methods.
func (a *Adapter) HandleREST(ctx context.Context, e events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	reject := func(code int) (events.APIGatewayProxyResponse, error) {
		return events.APIGatewayProxyResponse{StatusCode: code, Headers: map[string]string{"Cache-Control": "no-store"}, Body: "Request refused"}, nil
	}
	rc := e.RequestContext
	if e.HTTPMethod != rc.HTTPMethod || e.Resource != rc.ResourcePath || e.Resource == "" ||
		(rc.Path != e.Path && rc.Path != "/"+rc.Stage+e.Path) {
		return reject(403)
	}
	// REST provides the decoded path; all our routes and opaque tickets are ASCII.
	if strings.ContainsAny(e.Path, "%?#\\\r\n\x00") {
		return reject(400)
	}
	headers := make(map[string]string)
	for key, value := range e.Headers {
		key = strings.ToLower(key)
		if _, exists := headers[key]; exists {
			return reject(400)
		}
		headers[key] = value
	}
	seen := make(map[string]bool)
	for key, values := range e.MultiValueHeaders {
		key = strings.ToLower(key)
		if seen[key] || len(values) == 0 {
			return reject(400)
		}
		seen[key] = true
		if key == "cookie" {
			headers[key] = strings.Join(values, "; ")
		} else {
			if len(values) != 1 {
				return reject(400)
			}
			if old, exists := headers[key]; exists && old != values[0] {
				return reject(400)
			}
			headers[key] = values[0]
		}
	}
	query := url.Values{}
	for key, value := range e.QueryStringParameters {
		query.Set(key, value)
	}
	for key, values := range e.MultiValueQueryStringParameters {
		query[key] = values
	}
	route := e.HTTPMethod + " " + e.Resource
	v2 := events.APIGatewayV2HTTPRequest{
		Version: "2.0", RouteKey: route, RawPath: e.Path, RawQueryString: query.Encode(),
		Headers: headers, Body: e.Body, IsBase64Encoded: e.IsBase64Encoded,
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			APIID: rc.APIID, AccountID: rc.AccountID, Stage: rc.Stage,
			DomainName: rc.DomainName, RouteKey: route,
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: e.HTTPMethod, Path: e.Path},
		},
	}
	if cookie, ok := headers["cookie"]; ok {
		v2.Cookies = []string{cookie}
	}
	if rc.Identity.UserArn != "" {
		v2.RequestContext.Authorizer = &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
			IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
				AccountID: rc.Identity.AccountID, UserARN: rc.Identity.UserArn,
			},
		}
	}
	out, err := a.Handle(ctx, v2)
	if err != nil {
		return reject(500)
	}
	body := []byte(out.Body)
	if out.IsBase64Encoded {
		body, err = base64.StdEncoding.DecodeString(out.Body)
		if err != nil || !utf8.Valid(body) {
			return reject(500)
		}
	}
	// Public and agent responses are text/JSON/XML. Returning plain text avoids
	// REST binary-media-type negotiation altering browser responses.
	result := events.APIGatewayProxyResponse{
		StatusCode: out.StatusCode, Headers: out.Headers, Body: string(body),
		MultiValueHeaders: map[string][]string{},
	}
	if len(out.Cookies) != 0 {
		result.MultiValueHeaders[http.CanonicalHeaderKey("set-cookie")] = out.Cookies
	}
	return result, nil
}
