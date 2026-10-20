// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package agentapi exposes node-scoped operations to authenticated transports.
// It never derives a node identity from HTTP headers, paths or JSON.
package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
    "encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

type Store interface {
	Heartbeat(context.Context, postgres.Agent) error
	RotateNode(context.Context, string, string, string) error
	Register(context.Context, postgres.Agent, postgres.Connection, string, time.Duration) error
	Fetch(context.Context, postgres.Agent, postgres.Connection) (postgres.Decision, error)
	Acknowledge(context.Context, postgres.Agent, string, postgres.Outcome) error
	Cancel(context.Context, postgres.Agent, postgres.Connection) error
}
type nodeKey struct{}

var nodePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var ticketPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func ValidNode(node string) bool { return nodePattern.MatchString(node) }

// WithNode is for trusted transport adapters only, after authenticating the peer.
func WithNode(ctx context.Context, node string) context.Context {
	return context.WithValue(ctx, nodeKey{}, node)
}
func IsPath(path string) bool {
	switch path {
	case "/agent/v1/rotate", "/agent/v1/register", "/agent/v1/fetch", "/agent/v1/ack", "/agent/v1/cancel", "/agent/v1/heartbeat":
		return true
	default:
		return false
	}
}

type request struct {
	IncludeUsername *bool `json:"include_username"`
    IncludeSubject *bool `json:"include_subject"`
	Ready *bool `json:"ready"`
	Generation string           `json:"generation"`
	Previous   string           `json:"previous_generation"`
	CID        *int64           `json:"cid"`
	KID        *int64           `json:"kid"`
	Ticket     string           `json:"ticket"`
	DecisionID string           `json:"decision_id"`
	Outcome    postgres.Outcome `json:"outcome"`
}
type Decision struct {
	Username string `json:"username,omitempty"`
    SubjectHash string `json:"subject_hash,omitempty"`
	ID               string    `json:"decision_id"`
	NodeID           string    `json:"node_id"`
	Generation       string    `json:"generation"`
	CID              int64     `json:"cid"`
	KID              int64     `json:"kid"`
	GroupName        string    `json:"group_name,omitempty"`
	DenialReason     string    `json:"denial_reason,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
    SessionUnlimited bool `json:"session_unlimited"`
}

// flatObject rejects duplicate, unknown and nested fields before typed decoding.
// In particular encoding/json's case-insensitive struct matching cannot choose
// which security-sensitive value wins.
func flatObject(r io.Reader, permitted ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(r)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !slices.Contains(permitted, name) {
			return nil, errors.New("invalid field")
		}
		if _, exists := fields[name]; exists {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, err
		}
		if len(value) == 0 || value[0] == '{' || value[0] == '[' || string(value) == "null" {
			return nil, errors.New("invalid value")
		}
		fields[name] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return fields, nil
}

func decode(r io.Reader, out *request) error {
	fields, err := flatObject(r, "generation", "previous_generation", "cid", "kid", "ticket", "decision_id", "outcome", "ready", "include_subject", "include_username")
	if err != nil {
		return err
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// DecodeDecision preserves the complete node/connection binding across the
// transport. Missing IDs are errors even though explicit zero is valid.
func DecodeDecision(data []byte) (*Decision, error) {
	refused := errors.New("invalid controller decision")
	if len(data) > 8<<10 {
		return nil, refused
	}
	fields, err := flatObject(bytes.NewReader(data), "decision_id", "node_id", "generation",
		"cid", "kid", "group_name", "denial_reason", "expires_at", "session_expires_at", "session_unlimited", "subject_hash", "username")
	if err != nil {
		return nil, refused
	}
	for _, name := range []string{"decision_id", "node_id", "generation", "cid", "kid", "expires_at", "session_expires_at"} {
		if _, present := fields[name]; !present {
			return nil, refused
		}
	}
	b, err := json.Marshal(fields)
	if err != nil {
		return nil, refused
	}
	var out Decision
	if json.Unmarshal(b, &out) != nil {
		return nil, refused
	}
    if _, present := fields["subject_hash"]; present && !ValidSubjectHash(out.SubjectHash) {
        return nil, refused
    }
	if !controller.ValidLogUsername(out.Username) {
		return nil, refused
	}
	return &out, nil
}

// Empty hashes are allowed only by omission for older controllers.
func ValidSubjectHash(s string) bool {
    b, err := hex.DecodeString(s)
    return err == nil && len(b) == 32 && hex.EncodeToString(b) == s && [32]byte(b) != [32]byte{}
}

func New(store Store, pending time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		node, _ := r.Context().Value(nodeKey{}).(string)
		if !ValidNode(node) {
			fail(w, http.StatusForbidden)
			return
		}
		if store == nil || pending < 30*time.Second || pending > 180*time.Second {
			fail(w, 503)
			return
		}
		if !IsPath(r.URL.Path) || r.URL.RawQuery != "" || r.URL.RawPath != "" {
			fail(w, 404)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			fail(w, 405)
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			fail(w, 415)
			return
		}
		var q request
		if err = decode(http.MaxBytesReader(w, r.Body, 8<<10), &q); err != nil {
			fail(w, 400)
			return
		}
		if !ValidNode(q.Generation) {
			fail(w, 400)
			return
		}
		if (q.Previous != "" && !ValidNode(q.Previous)) ||
			(r.URL.Path == "/agent/v1/register" && !ticketPattern.MatchString(q.Ticket)) ||
			(r.URL.Path == "/agent/v1/ack" && (!ValidNode(q.DecisionID) ||
				(q.Outcome != postgres.Applied && q.Outcome != postgres.Denied && q.Outcome != postgres.Failed))) {
			fail(w, 400)
			return
		}
		a := postgres.Agent{NodeID: node, Generation: q.Generation}
		var c postgres.Connection
		if r.URL.Path != "/agent/v1/rotate" && r.URL.Path != "/agent/v1/ack" && r.URL.Path != "/agent/v1/heartbeat" {
			if q.CID == nil || q.KID == nil || *q.CID < 0 || *q.KID < 0 {
				fail(w, 400)
				return
			}
			c = postgres.Connection{CID: *q.CID, KID: *q.KID}
		}
		// Reject fields that belong to another operation rather than silently ignore.
		if (q.Previous != "" && r.URL.Path != "/agent/v1/rotate") ||
			(q.Ticket != "" && r.URL.Path != "/agent/v1/register") ||
			(q.Ticket != "" && !ticketPattern.MatchString(q.Ticket)) ||
			(q.Ready != nil && r.URL.Path != "/agent/v1/heartbeat") ||
            (q.IncludeSubject != nil && r.URL.Path != "/agent/v1/fetch") ||
			(q.IncludeUsername != nil && r.URL.Path != "/agent/v1/fetch") ||
			((q.DecisionID != "" || q.Outcome != "") && r.URL.Path != "/agent/v1/ack") ||
			((q.CID != nil || q.KID != nil) && (r.URL.Path == "/agent/v1/rotate" || r.URL.Path == "/agent/v1/ack" || r.URL.Path == "/agent/v1/heartbeat")) {
			fail(w, 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		switch r.URL.Path {
		case "/agent/v1/heartbeat":
			if hs, ok := store.(interface { HeartbeatStatus(context.Context, postgres.Agent, bool) error }); ok {
				err = hs.HeartbeatStatus(ctx, a, q.Ready != nil && *q.Ready)
			} else { err = store.Heartbeat(ctx, a) }
		case "/agent/v1/rotate":
			err = store.RotateNode(ctx, node, q.Previous, q.Generation)
		case "/agent/v1/register":
            err = store.Register(ctx, a, c, q.Ticket, pending)
		case "/agent/v1/fetch":
			d, fetchErr := store.Fetch(ctx, a, c)
            err = fetchErr
			if err == nil {
				reply := Decision{ID: d.ID, NodeID: d.Agent.NodeID, Generation: d.Agent.Generation,
					CID: d.Connection.CID, KID: d.Connection.KID, GroupName: d.GroupName, DenialReason: d.DenialReason,
					ExpiresAt: d.ExpiresAt, SessionExpiresAt: d.SessionExpiresAt, SessionUnlimited: d.SessionUnlimited}
                // Old agents strictly reject unknown response fields.
                if q.IncludeSubject != nil && *q.IncludeSubject && d.DenialReason == "" && d.SubjectHash != [32]byte{} {
                    reply.SubjectHash = hex.EncodeToString(d.SubjectHash[:])
                }
				if q.IncludeUsername != nil && *q.IncludeUsername && d.DenialReason == "" && controller.ValidLogUsername(d.Username) {
					reply.Username = d.Username
				}
                json.NewEncoder(w).Encode(reply)
				return
			}
		case "/agent/v1/ack":
			err = store.Acknowledge(ctx, a, q.DecisionID, q.Outcome)
		case "/agent/v1/cancel":
			err = store.Cancel(ctx, a, c)
		}
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, postgres.ErrNoDecision):
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, postgres.ErrConflict), errors.Is(err, postgres.ErrGeneration):
			fail(w, 409)
		case errors.Is(err, controller.ErrLoginExpired):
			fail(w, 410)
		default:
			fail(w, 503)
		}
	})
}
func fail(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	io.WriteString(w, `{"error":"request refused"}`)
}
