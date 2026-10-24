// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"testing"

	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
)

// A rejected profile has no controller login to cancel. It must not restart
// the listener and disconnect unrelated, already authorized clients.
func TestRejectedRegistrationDoesNotStopListener(t *testing.T) {
	for _, timing := range []string{"before-dispatch", "after-refusal", "during-refusal"} {
		t.Run(timing, func(t *testing.T) {
			var a *agent
			cancels := 0
			api := remoteAPIFunc(func(_ context.Context, op string, q agentclient.Request) (*agentapi.Decision, error) {
				if op == "register" {
					if timing == "during-refusal" {
						a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 8})
					}
					return nil, &agentclient.Error{Status: 410}
				}
				if op == "cancel" {
					cancels++
					return nil, &agentclient.Error{Status: 410}
				}
				return nil, nil
			})
			a, _ = remoteFixture(t, api)
			a.handleEvent(clientEvent{kind: "CONNECT", cid: 8, kid: 1, sso: "webauth"})
			if timing != "before-dispatch" {
				remoteStepNow(a)
			}
			if timing != "during-refusal" {
				a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 8})
			}
			remoteStepNow(a)
			if !a.readyLocked() || cancels != 0 || len(a.remote.jobs) != 0 {
				t.Fatal("unregistered/rejected connection disrupted the listener")
			}
		})
	}
}

func TestUncertainRegistrationStillRequiresCancellation(t *testing.T) {
	attempts, cancels := 0, 0
	a, _ := remoteFixture(t, remoteAPIFunc(func(_ context.Context, op string, _ agentclient.Request) (*agentapi.Decision, error) {
		if op == "register" {
			attempts++
			if attempts == 1 {
				return nil, &agentclient.Error{Status: 503}
			}
			return nil, &agentclient.Error{Status: 410}
		}
		if op == "cancel" {
			cancels++
			return nil, &agentclient.Error{Status: 410}
		}
		return nil, nil
	}))
	a.handleEvent(clientEvent{kind: "CONNECT", cid: 8, kid: 1, sso: "webauth"})
	remoteStepNow(a)
	remoteStepNow(a)
	a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 8})
	remoteStepNow(a)
	if a.readyLocked() || cancels != 1 {
		t.Fatal("uncertain registration was silently forgotten")
	}
}
