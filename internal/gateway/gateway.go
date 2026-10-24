// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package gateway adapts trusted API Gateway HTTP API v2 events to net/http.
// Invoke permission must be restricted to the configured API Gateway; this is
// not a verifier for arbitrary events supplied through lambda:InvokeFunction.
package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"supivpn/internal/agentapi"
)

type Config struct {
	APIID           string            `json:"api_id"`
	AccountID       string            `json:"account_id"`
	Stage           string            `json:"stage"`
	Domains         []string          `json:"domains"`
	AgentPrincipals map[string]string `json:"agent_principals"`
}
type Adapter struct {
	config         Config
	origin         *url.URL
	public, agents http.Handler
	only           string
}

// Isolated adapters refuse the other surface even if API Gateway is miswired.
func NewPublic(c Config, origin *url.URL, h http.Handler) (*Adapter, error) {
	a, err := New(c, origin, h, http.NotFoundHandler())
	if err == nil {
		a.only = "public"
	}
	return a, err
}
func NewAgent(c Config, origin *url.URL, h http.Handler) (*Adapter, error) {
	a, err := New(c, origin, http.NotFoundHandler(), h)
	if err == nil {
		a.only = "agent"
	}
	return a, err
}

var principalPattern = regexp.MustCompile(`^arn:aws:sts::([0-9]{12}):assumed-role/[A-Za-z0-9_+=,.@-]+/i-[0-9a-f]{17}$`)

func New(c Config, origin *url.URL, public, agents http.Handler) (*Adapter, error) {
	if c.APIID == "" || c.AccountID == "" || c.Stage == "" || len(c.Domains) == 0 ||
		origin == nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || (origin.Path != "" && origin.Path != "/supivpn") || origin.RawPath != "" ||
		origin.RawQuery != "" || origin.Fragment != "" || public == nil || agents == nil {
		return nil, errors.New("invalid gateway configuration")
	}
	publicDomain := false
	for _, domain := range c.Domains {
		if domain == "" || strings.ContainsAny(domain, " /\\\t\r\n:@") {
			return nil, errors.New("invalid gateway domain")
		}
		if domain == origin.Hostname() {
			publicDomain = true
		}
	}
	if !publicDomain {
		return nil, errors.New("public origin must be a gateway domain")
	}
	copyPrincipals := make(map[string]string, len(c.AgentPrincipals))
	for principal, node := range c.AgentPrincipals {
		match := principalPattern.FindStringSubmatch(principal)
		if len(match) != 2 || match[1] != c.AccountID || !agentapi.ValidNode(node) {
			return nil, errors.New("invalid agent principal mapping")
		}
		copyPrincipals[principal] = node
	}
	c.AgentPrincipals = copyPrincipals
	c.Domains = append([]string(nil), c.Domains...)
	u := *origin
	return &Adapter{config: c, origin: &u, public: public, agents: agents}, nil
}
func (a *Adapter) Handle(ctx context.Context, e events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	reject := func(status int) (events.APIGatewayV2HTTPResponse, error) {
		return events.APIGatewayV2HTTPResponse{
			StatusCode: status, Headers: map[string]string{"cache-control": "no-store", "content-type": "text/plain"}, Body: "Request refused"}, nil
	}
	rc := e.RequestContext
	domainOK := false
	for _, domain := range a.config.Domains {
		if rc.DomainName == domain {
			domainOK = true
		}
	}
	if e.Version != "2.0" || rc.APIID != a.config.APIID || rc.AccountID != a.config.AccountID ||
		rc.Stage != a.config.Stage || !domainOK || e.RouteKey != rc.RouteKey {
		return reject(403)
	}
	path, err := url.PathUnescape(e.RawPath)
	if err != nil || path == "" || path[0] != '/' || strings.ContainsAny(path, "\r\n\x00") ||
		path != rc.HTTP.Path || len(e.RawQueryString) > 8192 {
		return reject(400)
	}
	route := rc.HTTP.Method + " " + path
	handler := a.public
	if a.only == "public" && strings.HasPrefix(path, "/agent/") || a.only == "agent" && !strings.HasPrefix(path, "/agent/") {
		return reject(403)
	}
	if strings.HasPrefix(path, "/agent/") {
		if !agentapi.IsPath(path) || e.RawPath != path || rc.RouteKey != route || rc.HTTP.Method != "POST" {
			return reject(403)
		}
		if rc.Authorizer == nil || rc.Authorizer.IAM == nil {
			return reject(403)
		}
		iam := rc.Authorizer.IAM
		node, ok := a.config.AgentPrincipals[iam.UserARN]
		if !ok || iam.AccountID != a.config.AccountID {
			return reject(403)
		}
		ctx = agentapi.WithNode(ctx, node)
		handler = a.agents
	} else {
		if rc.DomainName != a.origin.Hostname() {
			return reject(403)
		}
		if a.origin.Path != "" && !strings.HasPrefix(path, a.origin.Path+"/") {
			return reject(404)
		}
		publicPath := strings.TrimPrefix(path, a.origin.Path)
		switch {
		case publicPath == "/saml/launch" && rc.HTTP.Method == "POST":
			if rc.RouteKey != route || e.RawPath != path {
				return reject(403)
			}
		case publicPath == "/healthz" && rc.HTTP.Method == "GET", publicPath == "/saml/metadata" && rc.HTTP.Method == "GET", publicPath == "/saml/acs" && rc.HTTP.Method == "POST", publicPath == "/profile" && rc.HTTP.Method == "GET":
			if rc.RouteKey != route {
				return reject(403)
			}
		case publicPath == "/openvpn-api/profile" && (rc.HTTP.Method == "GET" || rc.HTTP.Method == "HEAD"), publicPath == "/profile/connect" && rc.HTTP.Method == "GET":
			if rc.RouteKey != route || e.RawPath != path {
				return reject(403)
			}
		case strings.HasPrefix(publicPath, "/profile/import/") && rc.HTTP.Method == "GET":
			token := strings.TrimPrefix(publicPath, "/profile/import/")
			if rc.RouteKey != "GET "+a.origin.Path+"/profile/import/{token}" || e.RawPath != path || len(token) != 43 || strings.Trim(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
				return reject(403)
			}
		case strings.HasPrefix(publicPath, "/login/") && (rc.HTTP.Method == "GET" || rc.HTTP.Method == "POST"):
			ticket := strings.TrimPrefix(publicPath, "/login/")
			if rc.RouteKey != rc.HTTP.Method+" "+a.origin.Path+"/login/{ticket}" ||
				e.RawPath != path || ticket == "" || strings.Contains(ticket, "/") {
				return reject(403)
			}
		default:
			return reject(404)
		}
	}
	if len(e.Body) > base64.StdEncoding.EncodedLen(1<<20) {
		return reject(413)
	}
	body := []byte(e.Body)
	if e.IsBase64Encoded {
		body, err = base64.StdEncoding.DecodeString(e.Body)
		if err != nil {
			return reject(400)
		}
	}
	if len(body) > 1<<20 {
		return reject(413)
	}
	u := &url.URL{Scheme: "https", Host: a.origin.Host, Path: path, RawPath: e.RawPath, RawQuery: e.RawQueryString}
	req, err := http.NewRequestWithContext(ctx, rc.HTTP.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		return reject(400)
	}
	size := 0
	hostSeen := false
	seenHeaders := make(map[string]bool)
	for key, value := range e.Headers {
		size += len(key) + len(value)
		if size > 16<<10 || strings.ContainsAny(key+value, "\r\n\x00") {
			return reject(400)
		}
		if seenHeaders[strings.ToLower(key)] {
			return reject(400)
		}
		seenHeaders[strings.ToLower(key)] = true
		switch strings.ToLower(key) {
		case "host":
			hostSeen = true
			// Public browser requests must actually target the configured SP hostname.
			if !strings.HasPrefix(path, "/agent/") && !strings.EqualFold(value, a.origin.Host) {
				return reject(400)
			}
		case "cookie": // API Gateway v2 supplies cookies separately.
		case "content-length", "connection", "transfer-encoding":
		default:
			req.Header.Set(key, value)
		}
	}
	if !hostSeen {
		return reject(400)
	}
	for _, cookie := range e.Cookies {
		size += len(cookie)
		if size > 16<<10 || strings.ContainsAny(cookie, "\r\n\x00") {
			return reject(400)
		}
		req.Header.Add("Cookie", cookie)
	}
	// TLS is asserted only at this trusted HTTPS event boundary, never from XFP.
	req.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: a.origin.Hostname()}
	req.Host = a.origin.Host
	out := &response{header: make(http.Header)}
	handler.ServeHTTP(out, req)
	if out.overflow {
		return reject(500)
	}
	if out.status == 0 {
		out.status = 200
	}
	headers := make(map[string]string)
	for key, values := range out.header {
		if !strings.EqualFold(key, "Set-Cookie") {
			headers[key] = strings.Join(values, ",")
		}
	}
	return events.APIGatewayV2HTTPResponse{StatusCode: out.status, Headers: headers, Cookies: out.header.Values("Set-Cookie"),
		Body: base64.StdEncoding.EncodeToString(out.body.Bytes()), IsBase64Encoded: true}, nil
}

type response struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (w *response) Header() http.Header { return w.header }
func (w *response) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *response) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if w.body.Len()+len(b) > 2<<20 {
		w.overflow = true
		return 0, errors.New("response too large")
	}
	return w.body.Write(b)
}
