// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package agentclient implements the bounded HTTP transport for the node API.
// Authentication is injected; the agent's lifecycle does not depend on AWS.
package agentclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"supivpn/internal/agentapi"
)

type Request struct {
	ProfileID       string `json:"profile_id,omitempty"`
	ProfileSecret   string `json:"profile_secret,omitempty"`
	IncludeUsername *bool  `json:"include_username,omitempty"`
	IncludeSubject  *bool  `json:"include_subject,omitempty"`
	Ready           *bool  `json:"ready,omitempty"`
	Generation      string `json:"generation"`
	Previous        string `json:"previous_generation,omitempty"`
	CID             *int64 `json:"cid,omitempty"`
	KID             *int64 `json:"kid,omitempty"`
	Ticket          string `json:"ticket,omitempty"`
	DecisionID      string `json:"decision_id,omitempty"`
	Outcome         string `json:"outcome,omitempty"`
}

type API interface {
	Call(context.Context, string, Request) (*agentapi.Decision, error)
}

// Error deliberately omits response bodies, request URLs and credentials.
type Error struct{ Status int }

func (e *Error) Error() string { return fmt.Sprintf("controller request failed (status=%d)", e.Status) }
func Retryable(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Status == 0 || e.Status == 429 || e.Status >= 500)
}
func Status(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

type Sign func(context.Context, *http.Request, []byte) error
type Client struct {
	endpoint string
	http     *http.Client
	sign     Sign
}

func ValidURL(raw string, public bool) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" &&
		len(raw) <= 300 && !strings.ContainsAny(raw, " \t\r\n\\\"") &&
		(u.Path == "" || public && u.Path == "/supivpn")
}

// New creates an HTTPS client with optional request signing and transport.
// Redirects never receive signed requests or login tickets. Use NewUnix for a
// colocated controller with kernel peer authentication.
func New(endpoint string, transport http.RoundTripper, sign Sign) (*Client, error) {
	if !ValidURL(endpoint, false) {
		return nil, errors.New("agent API requires an HTTPS origin")
	}
	if transport == nil {
		transport = &http.Transport{
			Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
			MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second,
		}
	}
	return newClient(endpoint, transport, sign), nil
}

func newClient(endpoint string, transport http.RoundTripper, sign Sign) *Client {
	return &Client{endpoint: endpoint, sign: sign, http: &http.Client{
		Transport: transport, Timeout: 6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}
func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) Call(ctx context.Context, operation string, q Request) (*agentapi.Decision, error) {
	path := "/agent/v1/" + operation
	if !agentapi.IsPath(path) {
		return nil, &Error{400}
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	body, err := json.Marshal(q)
	if err != nil {
		return nil, &Error{400}
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(body))
	if err != nil {
		return nil, &Error{400}
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	if c.sign != nil {
		if err = c.sign(ctx, r, body); err != nil {
			return nil, &Error{0}
		}
	}
	res, err := c.http.Do(r)
	if err != nil {
		return nil, &Error{0}
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, &Error{res.StatusCode}
	}
	media, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if operation != "fetch" || err != nil || media != "application/json" {
		return nil, &Error{502}
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, (8<<10)+1))
	if err != nil || len(b) > 8<<10 {
		return nil, &Error{502}
	}
	decision, err := agentapi.DecodeDecision(b)
	if err != nil {
		return nil, &Error{502}
	}
	return decision, nil
}
