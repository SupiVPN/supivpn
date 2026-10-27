// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/controller"
	"supivpn/internal/tracecontext"
)

type remoteConfig struct {
	Transport      string  `json:"transport,omitempty"`
	AgentSocket    string  `json:"agent_socket,omitempty"`
	ControllerUID  *uint32 `json:"controller_uid,omitempty"`
	AgentURL       string  `json:"agent_url"`
	PublicURL      string  `json:"public_url"`
	Region         string  `json:"region"`
	NodeID         string  `json:"node_id"`
	StateDirectory string  `json:"state_directory"`
}

func (r *remoteConfig) validate(c config) error {
	if !agentclient.ValidURL(r.PublicURL, true) || !agentapi.ValidNode(r.NodeID) ||
		!filepath.IsAbs(r.StateDirectory) || filepath.Clean(r.StateDirectory) == filepath.Dir(c.ManagementSocket) ||
		c.SAMLGroupsAttribute == "" {
		return errors.New("remote_controller requires an HTTPS public_url, node_id, persistent state_directory and group pools")
	}
	switch r.Transport {
	case "", "aws":
		if !agentclient.ValidURL(r.AgentURL, false) || !regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`).MatchString(r.Region) || r.AgentSocket != "" || r.ControllerUID != nil {
			return errors.New("AWS controller transport requires agent_url and region, without Unix settings")
		}
	case "unix":
		if !agentclient.ValidSocketPath(r.AgentSocket) || r.ControllerUID == nil || r.AgentURL != "" || r.Region != "" ||
			filepath.Clean(r.StateDirectory) == filepath.Dir(r.AgentSocket) {
			return errors.New("Unix controller transport requires agent_socket, controller_uid and separate persistent state, without AWS settings")
		}
	default:
		return errors.New("unknown controller transport")
	}
	return nil
}

func (r *remoteConfig) client() (*agentclient.Client, string, error) {
	if r.Transport == "unix" {
		if r.ControllerUID == nil {
			return nil, "", errors.New("controller_uid is required")
		}
		api, err := agentclient.NewUnix(r.AgentSocket, *r.ControllerUID)
		// Bind durable generations to both the socket and authenticated server UID.
		return api, "unix:" + r.AgentSocket + "#uid=" + strconv.FormatUint(uint64(*r.ControllerUID), 10), err
	}
	if r.Transport != "" && r.Transport != "aws" {
		return nil, "", errors.New("unknown controller transport")
	}
	api, err := agentclient.New(r.AgentURL, nil, agentclient.EC2Signer(r.Region))
	return api, r.AgentURL, err
}

type remoteJob struct {
	conn                *connection
	phase               string
	due, deadline       time.Time
	decisionID, outcome string
	failures            uint
	disconnectConfirmed bool
}

// jobs and connection state are protected by agent.mu. Only the worker performs
// HTTP; no network call holds the lock needed by disconnect/expiry processing.
type remoteAgent struct {
	api                         agentclient.API
	node, generation, publicURL string
	jobs                        []*remoteJob
	leaseUntil, heartbeatDue    time.Time
}

const maxRemoteJobs = 2 * maxConnections

func (r *remoteAgent) canRegister(e clientEvent) bool {
	return e.cid <= math.MaxInt64 && e.kid <= math.MaxInt64 && len(r.jobs) < maxRemoteJobs
}
func (r *remoteAgent) enqueue(c *connection) {
	r.jobs = append(r.jobs, &remoteJob{conn: c, phase: "register", deadline: c.expires})
}
func (a *agent) refuseRemoteLocked(c *connection) {
	if a.connections[c.cid] != c || c.closing || c.active {
		return
	}
	a.denyConnectionLocked(c, "controller_refused")
}

// The startup generation is established before OpenVPN leaves its hold.
func (a *agent) startRemote(ctx context.Context) (func(), error) {
	policy := controller.Config{Policy: controllerPolicy(a.config), SessionSeconds: a.config.SessionSeconds}
	if policy.HasUnlimitedSessions() {
		a.logEvent("session.unlimited_configured", nil)
	}
	cfg := a.config.RemoteController
	api, endpoint, err := cfg.client()
	if err != nil {
		return nil, err
	}
	journal, err := agentclient.OpenJournal(cfg.StateDirectory, cfg.NodeID, endpoint)
	if err != nil {
		api.Close()
		return nil, err
	}
	cleanup := func() { api.Close(); journal.Close() }
	startup, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	generation, err := journal.Begin(startup, api)
	if err != nil {
		cleanup()
		return nil, err
	}
	started := a.now()
	if _, err := api.Call(startup, "heartbeat", agentclient.Request{Generation: generation}); err != nil ||
		!a.now().Before(started.Add(40*time.Second)) {
		cleanup()
		return nil, errors.New("controller lease unavailable")
	}
	a.remote = &remoteAgent{api: api, node: cfg.NodeID, generation: generation, publicURL: cfg.PublicURL}
	a.remote.leaseUntil = started.Add(40 * time.Second)
	a.remote.heartbeatDue = started.Add(15 * time.Second)
	a.logEvent("controller.ready", nil)
	return cleanup, nil
}

func (a *agent) remoteEvents(ctx context.Context, m *management) {
	// At most four calls per second per node, including retries and cancellations.
	// Idle nodes send only one lease heartbeat every 15 seconds.
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			a.remoteStep(ctx)
		}
	}
}

func (a *agent) nextRemoteLocked() *remoteJob {
	now := a.now()
	for i := 0; i < len(a.remote.jobs); {
		j := a.remote.jobs[i]
		// A proven disconnect cannot authorize traffic. Retain its bounded
		// cancellation job across transient API outages while this generation's
		// lease is live; abandoning it would strand a cluster session slot.
		if !(j.phase == "cancel" && j.disconnectConfirmed) && !now.Before(j.deadline) {
			if j.phase == "cancel" || j.phase == "ack" && j.outcome == "applied" {
				// An uncertain release/ACK must not leak a user's slot indefinitely.
				// Stop the node heartbeat; slot reuse requires fencing or a clean restart.
				a.management.close()
				return nil
			}
			if j.phase == "ack" {
				a.logEvent("controller.ack_expired", j.conn)
			}
			a.refuseRemoteLocked(j.conn)
			if !a.readyLocked() {
				return nil
			}
			a.remote.jobs = slices.Delete(a.remote.jobs, i, i+1)
			continue
		}
		if j.phase != "ack" && !a.pendingConnectionLocked(j.conn) {
			j.phase = "cancel"
		}
		if !now.Before(j.due) {
			// Round robin prevents slow browser logins from starving new connections.
			a.remote.jobs = append(slices.Delete(a.remote.jobs, i, i+1), j)
			return j
		}
		i++
	}
	return nil
}
func (a *agent) finishRemoteLocked(j *remoteJob) {
	if i := slices.Index(a.remote.jobs, j); i >= 0 {
		a.remote.jobs = slices.Delete(a.remote.jobs, i, i+1)
	}
}

func (a *agent) remoteStep(ctx context.Context) {
	a.mu.Lock()
	if !a.readyLocked() {
		a.mu.Unlock()
		return
	}
	if !a.now().Before(a.remote.leaseUntil) {
		a.management.close()
		a.mu.Unlock()
		return
	}
	if !a.now().Before(a.remote.heartbeatDue) {
		started := a.now()
		a.remote.heartbeatDue = started.Add(5 * time.Second)
		q := agentclient.Request{Generation: a.remote.generation}
		a.mu.Unlock()
		ready := a.loadBalancerReady(ctx)
		q.Ready = &ready
		_, err := a.remote.api.Call(ctx, "heartbeat", q)
		a.mu.Lock()
		defer a.mu.Unlock()
		if !a.readyLocked() || ctx.Err() != nil {
			return
		}
		// A late success cannot resurrect a locally expired lease.
		if !a.now().Before(a.remote.leaseUntil) {
			a.management.close()
			return
		}
		if err == nil {
			a.remote.leaseUntil = started.Add(40 * time.Second)
			a.remote.heartbeatDue = started.Add(15 * time.Second)
		} else if !agentclient.Retryable(err) {
			a.management.close()
		}
		return
	}
	j := a.nextRemoteLocked()
	if j == nil {
		a.mu.Unlock()
		return
	}
	c, phase := j.conn, j.phase
	previousRegistration := c.registrationMayExist
	if phase == "register" {
		// Set before releasing mu: a disconnect during the request must retain
		// cancellation until its result is known. Retries may have committed.
		c.registrationMayExist = true
	}
	cid, kid := int64(c.cid), int64(c.kid)
	q := agentclient.Request{Generation: a.remote.generation}
	if phase == "fetch" {
		include := true
		q.IncludeSubject = &include
		q.IncludeUsername = &include
	}
	if phase == "ack" {
		q.DecisionID, q.Outcome = j.decisionID, j.outcome
	} else {
		q.CID, q.KID = &cid, &kid
		if phase == "register" {
			q.Ticket = c.ticket
			q.ProfileID, q.ProfileSecret = c.proof.ID, c.proof.Secret
		}
	}
	a.mu.Unlock()

	d, err := a.remote.api.Call(tracecontext.WithID(ctx, tracecontext.ForLogin(c.ticket)), phase, q)

	a.mu.Lock()
	defer a.mu.Unlock()
	if phase == "register" && agentclient.Status(err) == http.StatusGone && !previousRegistration {
		// A first, definitive rejection cannot have created a controller login.
		// Do not infer this after a timeout/retry: an earlier attempt may exist.
		c.registrationMayExist = false
		if j.phase == "cancel" {
			a.finishRemoteLocked(j)
			return
		}
	}
	if ctx.Err() != nil || !a.readyLocked() {
		return
	}
	if !a.now().Before(a.remote.leaseUntil) {
		a.management.close()
		return
	}
	if j.phase != phase {
		return
	}
	if err != nil {
		status := agentclient.Status(err)
		if status == 409 {
			// Never try a new generation while the old OpenVPN process is still alive.
			a.logEvent("controller.generation_rejected", c)
			a.management.close()
			return
		}
		if agentclient.Retryable(err) {
			if j.failures == 0 {
				a.logEvent("controller.request_retry", c, slog.String("operation", phase), slog.Int("status", status))
			}
			j.failures++
			j.due = a.now().Add(time.Duration(1<<min(j.failures, 4)) * time.Second)
			return
		}
		if phase != "cancel" {
			a.logEvent("controller.request_refused", c, slog.String("operation", phase), slog.Int("status", status))
		}
		if phase == "cancel" || phase == "ack" && j.outcome == "applied" {
			a.management.close()
			return
		}
		a.refuseRemoteLocked(c)
		a.finishRemoteLocked(j)
		return
	}
	j.failures = 0
	j.due = a.now().Add(time.Second)
	if phase == "ack" || phase == "cancel" {
		a.finishRemoteLocked(j)
		return
	}
	if !a.pendingConnectionLocked(c) {
		j.phase = "cancel"
		return
	}
	switch phase {
	case "register":
		c.proof.Secret = ""
		remaining := int(c.expires.Sub(a.now()).Seconds())
		if remaining <= 0 {
			a.refuseRemoteLocked(c)
			j.phase = "cancel"
			return
		}
		if a.requestBrowserLocked(c, a.remote.publicURL) != nil {
			a.management.close()
			return
		}
		j.phase = "fetch"
		a.logEvent("vpn.browser_auth_requested", c)
	case "fetch":
		if d == nil {
			return
		}
		// All bindings are checked again after HTTP. A late reply cannot authorize a
		// disconnected/replaced connection or extend the controller's expiry.
		if !a.validRemoteDecision(c, d) {
			a.logEvent("controller.decision_rejected", c)
			a.refuseRemoteLocked(c)
			j.phase = "cancel"
			return
		}
		outcome := "applied"
		if d.SubjectHash != "" {
			hash, _ := hex.DecodeString(d.SubjectHash)
			copy(c.subjectHash[:], hash)
		}
		err = a.applyAuthorizationLocked(c, controller.Authorization{
			Username:  d.Username,
			GroupName: d.GroupName, DenialReason: d.DenialReason, SessionExpiresAt: d.SessionExpiresAt, SessionUnlimited: d.SessionUnlimited,
		})
		if errors.Is(err, controller.ErrGroupDenied) {
			outcome = "denied"
		} else if err != nil {
			outcome = "failed"
		}
		j.phase, j.decisionID, j.outcome = "ack", d.ID, outcome
		j.deadline = minTime(j.deadline, d.ExpiresAt)
	}
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (a *agent) validRemoteDecision(c *connection, d *agentapi.Decision) bool {
	now := a.now()
	policy := controller.Config{Policy: controllerPolicy(a.config), SessionSeconds: a.config.SessionSeconds}
	if !agentapi.ValidNode(d.ID) || d.NodeID != a.remote.node || d.Generation != a.remote.generation ||
		(d.SubjectHash != "" && !agentapi.ValidSubjectHash(d.SubjectHash)) ||
		!controller.ValidLogUsername(d.Username) ||
		d.CID != int64(c.cid) || d.KID != int64(c.kid) || !now.Before(d.ExpiresAt) ||
		!validSessionDecision(now, d.ExpiresAt, d.SessionExpiresAt, d.SessionUnlimited, policy.SessionLimit(d.GroupName)) {
		return false
	}
	switch d.DenialReason {
	case "":
		return agentapi.ValidNode(d.GroupName)
	case "invalid_groups_claim", "no_vpn_group", "connection_limit", "profile_refused":
		return d.GroupName == ""
	default:
		return false
	}
}

// Called after DISCONNECT or confirmed CID absence, never just after client-kill.
func (a *agent) cancelRemoteLocked(c *connection) {
	if !c.registrationMayExist && !c.active {
		// Never dispatched, or definitively refused before any uncertain retry.
		// There is no authorization or reservation to cancel at the controller.
		a.remote.jobs = slices.DeleteFunc(a.remote.jobs, func(j *remoteJob) bool { return j.conn == c })
		return
	}
	for _, j := range a.remote.jobs {
		if j.conn == c {
			j.phase, j.due = "cancel", time.Time{}
			j.disconnectConfirmed = true
			j.failures = 0
			return
		}
	}
	if len(a.remote.jobs) >= maxRemoteJobs {
		a.management.close()
		return
	}
	a.remote.jobs = append(a.remote.jobs, &remoteJob{conn: c, phase: "cancel", disconnectConfirmed: true})
}

// The old node HTTPS listener remains for the NLB health check. SAML routes are
// served only by the remote controller; an outage cannot activate local login.
func (a *agent) remoteHealth() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || (r.URL.Path != "/readyz" && (r.Host != a.origin.Host || r.URL.Path != "/healthz")) ||
			r.URL.RawQuery != "" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if !a.loadBalancerReady(r.Context()) {
			http.Error(w, "not ready", 503)
			return
		}
		w.Write([]byte("ready\n"))
	})
}
