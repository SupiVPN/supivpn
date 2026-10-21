// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"supivpn/internal/jsonobject"
	"supivpn/internal/vm"
)

type userSessionsRequest struct {
	Operation string `json:"operation"`
	Username  string `json:"username"`
}
type userSessionsResult struct {
	Version      int `json:"version"`
	Matched      int `json:"matched"`
	Closing      int `json:"closing"`
	Requested    int `json:"requested"`
	Unidentified int `json:"unidentified"`
}

func decodeUserSessions(data []byte) (userSessionsRequest, error) {
	var q userSessionsRequest
	refused := errors.New("require operation status/drop and an exact SAML NameID")
	if len(data) > 2048 || !utf8.Valid(data) {
		return q, refused
	}
	fields, err := jsonobject.Flat(bytes.NewReader(data), "operation", "username")
	if err != nil || json.Unmarshal(fields["operation"], &q.Operation) != nil ||
		json.Unmarshal(fields["username"], &q.Username) != nil {
		return q, refused
	}
	if q.Operation != "status" && q.Operation != "drop" {
		return q, refused
	}
	if len(q.Username) == 0 || len(q.Username) > 1024 || strings.TrimSpace(q.Username) != q.Username ||
		strings.ContainsFunc(q.Username, func(r rune) bool { return unicode.IsControl(r) || r == utf8.RuneError }) {
		return q, refused
	}
	return q, nil
}

// The same lock binds authorization, user matching and client-kill. A reused CID
// cannot turn a queued operator request into a kill for another user's session.
func (a *agent) userSessions(ctx context.Context, issuer string, q userSessionsRequest) (userSessionsResult, error) {
	result := userSessionsResult{Version: 1}
	hash := sha256.Sum256([]byte(issuer + "\x00" + q.Username))
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || issuer == "" || !a.readyLocked() {
		return result, errors.New("agent unavailable")
	}
	for _, c := range a.connections {
		if !c.active {
			continue
		}
		if c.subjectHash == [32]byte{} {
			result.Unidentified++
			continue
		}
		if c.subjectHash != hash {
			continue
		}
		result.Matched++
		if q.Operation == "drop" && !c.closing {
			// Keep the IP and controller slot until the normal DISCONNECT path.
			a.closeClientLocked(c, "operator_requested")
			result.Requested++
			a.logEvent("operator.tunnel_drop_requested", c)
		}
		if c.closing {
			result.Closing++
		}
	}
	if !a.readyLocked() {
		return result, errors.New("OpenVPN termination unconfirmed")
	}
	return result, nil
}

func (a *agent) userSessionsHandler(issuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost || r.URL.Path != "/user-sessions" || r.URL.RawPath != "" || r.URL.RawQuery != "" {
			http.Error(w, "request refused", 400)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		q, parseErr := decodeUserSessions(data)
		if err != nil || parseErr != nil {
			http.Error(w, "request refused", 400)
			return
		}
		result, err := a.userSessions(r.Context(), issuer, q)
		if err != nil {
			http.Error(w, "agent unavailable; termination unconfirmed", 503)
			return
		}
		json.NewEncoder(w).Encode(result)
	})
}

func operatorSocket(management string) string {
	return filepath.Join(filepath.Dir(management), "operator.sock")
}

func (a *agent) listenOperator(issuer string) (*http.Server, <-chan struct{}, error) {
	listener, err := vm.ListenAgent(operatorSocket(a.config.ManagementSocket), uint32(os.Getuid()), "local-operator")
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{Handler: a.userSessionsHandler(issuer), ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096,
		ErrorLog: log.New(io.Discard, "", 0)}
	stopped := make(chan struct{})
	go func() { defer close(stopped); server.Serve(listener) }()
	return server, stopped, nil
}

// This CLI mode reads no private key, contacts no controller and accepts no
// arbitrary management command. The authenticated Unix socket is the only peer.
func requestUserSessions(ctx context.Context, socket string, input io.Reader, output io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil {
		return errors.New("cannot read operator request")
	}
	if _, err = decodeUserSessions(data); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://local-operator/user-sessions", bytes.NewReader(data))
	if err != nil {
		return errors.New("cannot create operator request")
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return errors.New("operator socket unavailable; termination unconfirmed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if err != nil || len(body) > 4096 || res.StatusCode != 200 {
		return errors.New("operator request failed; termination unconfirmed")
	}
	var result userSessionsResult
	if json.Unmarshal(body, &result) != nil || result.Version != 1 {
		return errors.New("invalid operator reply")
	}
	_, err = output.Write(body)
	return err
}
