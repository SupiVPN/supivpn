// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/controller"
	"supivpn/internal/gateway"
	"supivpn/internal/postgres"
)

// Exercise the Lambda adapters with real restricted PostgreSQL roles. Only the
// API Gateway IAM envelope, transient HTTP faults and agent clock are synthetic.
// Replacing handlers simulates cold starts; no live AWS infrastructure is used.
func testLambdaUpdateCancellation(t *testing.T, admin, publicPool, agentPool *pgxpool.Pool) {
	for _, rest := range []bool{false, true} {
		format := "http-v2"
		if rest {
			format = "rest"
		}
		t.Run(format, func(t *testing.T) {
			for _, scenario := range []string{"public-replaced", "cancel-outage", "cancel-response-lost", "api-outage-short", "api-outage-restart"} {
				t.Run(scenario, func(t *testing.T) {
					ctx := context.Background()
					start := time.Now()
					now := start
					node := "update-" + rand.Text()
					origin, _ := url.Parse("https://login.example.test")
					const principal = "arn:aws:sts::123456789012:assumed-role/supivpn/i-00000000000000001"
					var public *postgres.Store
					var adapter *gateway.Adapter
					replace := func() {
						t.Helper()
						var err error
						public, err = postgres.NewIsolated(ctx, publicPool, postgres.Public, nil)
						if err != nil {
							t.Fatal(err)
						}
						agentStore, err := postgres.NewIsolated(ctx, agentPool, postgres.AgentAPI, nil)
						if err != nil {
							t.Fatal(err)
						}
						adapter, err = gateway.NewAgent(gateway.Config{APIID: "testapi", AccountID: "123456789012", Stage: "live",
							Domains: []string{origin.Hostname()}, AgentPrincipals: map[string]string{principal: node}},
							origin, agentapi.New(agentStore, 180*time.Second))
						if err != nil {
							t.Fatal(err)
						}
					}
					replace()
					faults := false
					client, err := agentclient.New(origin.String(), agentRoundTrip(func(r *http.Request) (*http.Response, error) {
						failed := faults && (scenario == "cancel-outage" || scenario == "cancel-response-lost") && r.URL.Path == "/agent/v1/cancel" && now.Before(start.Add(90*time.Second)) ||
							faults && scenario == "api-outage-short" && now.Before(start.Add(20*time.Second)) ||
							faults && scenario == "api-outage-restart"
						response := httptest.NewRecorder()
						if failed && scenario != "cancel-response-lost" {
							response.WriteHeader(http.StatusServiceUnavailable)
							return response.Result(), nil
						}
						body, err := io.ReadAll(r.Body)
						if err != nil {
							return nil, err
						}
						path := r.URL.Path
						var code int
						var result string
						if rest {
							out, callErr := adapter.HandleREST(r.Context(), events.APIGatewayProxyRequest{
								Resource: path, Path: path, HTTPMethod: "POST", Headers: map[string]string{"Host": origin.Host, "Content-Type": "application/json"}, Body: string(body),
								RequestContext: events.APIGatewayProxyRequestContext{APIID: "testapi", AccountID: "123456789012", Stage: "live",
									DomainName: origin.Hostname(), ResourcePath: path, Path: "/live" + path, HTTPMethod: "POST",
									Identity: events.APIGatewayRequestIdentity{AccountID: "123456789012", UserArn: principal}},
							})
							code, result, err = out.StatusCode, out.Body, callErr
						} else {
							e := runtimeEvent(origin, "POST", path, string(body), nil)
							e.Headers["content-type"] = "application/json"
							e.RequestContext.Stage = "live"
							e.RequestContext.Authorizer = &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
								IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{AccountID: "123456789012", UserARN: principal},
							}
							out, callErr := adapter.Handle(r.Context(), e)
							code, result, err = out.StatusCode, out.Body, callErr
						}
						if err != nil {
							return nil, err
						}
						if failed {
							if code != http.StatusNoContent {
								t.Fatal("cancel did not commit before simulated response loss")
							}
							code, result = http.StatusServiceUnavailable, ""
						}
						response.Header().Set("Content-Type", "application/json")
						response.WriteHeader(code)
						response.WriteString(result)
						return response.Result(), nil
					}), nil)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(client.Close)
					stateDir := t.TempDir()
					if err := os.Chmod(stateDir, 0700); err != nil {
						t.Fatal(err)
					}
					journal, err := agentclient.OpenJournal(stateDir, node, origin.String())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(journal.Close)
					generation, err := journal.Begin(ctx, client)
					if err != nil {
						t.Fatal(err)
					}
					actor := postgres.Agent{NodeID: node, Generation: generation}
					agentStore := postgres.New(admin) // Fixture setup/inspection only.
					subject := sha256.Sum256([]byte(node))
					admit := func(target postgres.Agent, cid int64, want error) {
						t.Helper()
						ticket, err := randomToken()
						if err != nil {
							t.Fatal(err)
						}
						browser := sha256.Sum256([]byte(ticket))
						if err := registerOwnedFixture(t, agentStore, ctx, target, postgres.Connection{CID: cid, KID: 1}, ticket, 180*time.Second, subject); err != nil {
							t.Fatal(err)
						}
						if err := public.Start(ctx, ticket, "request-"+ticket, browser); err != nil {
							t.Fatal(err)
						}
						pending, err := public.Lookup(ctx, ticket, browser)
						if err != nil {
							t.Fatal(err)
						}
						var dbNow time.Time
						if err := admin.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&dbNow); err != nil {
							t.Fatal(err)
						}
						decision := controller.Authorization{SubjectHash: subject, MaxConnections: 1, AssertionHash: browser, GroupName: coreGroup,
							AssertionExpiresAt: dbNow.Add(time.Minute), NotBefore: dbNow.Add(-time.Minute), NotOnOrAfter: dbNow.Add(time.Minute), SessionExpiresAt: dbNow.Add(time.Hour)}
						if err := public.Complete(ctx, pending, decision); !errors.Is(err, want) {
							t.Fatalf("admission after %s: got %v, want %v", scenario, err, want)
						}
					}
					admit(actor, 1, controller.ErrDecisionPending)
					decision, err := agentStore.Fetch(ctx, actor, postgres.Connection{CID: 1, KID: 1})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := client.Call(ctx, "ack", agentclient.Request{Generation: generation, DecisionID: decision.ID, Outcome: "applied"}); err != nil {
						t.Fatal(err)
					}
					a, _ := remoteFixture(t, client)
					a.now = func() time.Time { return now }
					a.remote.node, a.remote.generation = node, generation
					a.remote.leaseUntil, a.remote.heartbeatDue = start.Add(40*time.Second), start.Add(15*time.Second)
					a.connections[1] = &connection{cid: 1, kid: 1, active: true, expires: start.Add(time.Hour)}
					replace()
					admit(actor, 2, controller.ErrConnectionLimit) // A cold start cannot forget a live tunnel.
					other := postgres.Agent{NodeID: node + "-other", Generation: "g1"}
					if err := agentStore.RotateNode(ctx, other.NodeID, "", other.Generation); err != nil {
						t.Fatal(err)
					}
					faults = scenario != "public-replaced"
					a.handleEvent(clientEvent{kind: "DISCONNECT", cid: 1})
					for step := 0; step <= 480; step++ {
						now = start.Add(time.Duration(step) * 250 * time.Millisecond)
						a.remoteStep(ctx)
					}
					if scenario == "api-outage-restart" {
						if a.readyLocked() {
							t.Fatal("complete outage did not stop the old pair")
						}
						// Advance the database lease independently: neither clock alone
						// can prove the old OpenVPN process stopped.
						if _, err := admin.Exec(ctx, "UPDATE supivpn.nodes SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE node_id=$1", node); err != nil {
							t.Fatal(err)
						}
						admit(other, 3, controller.ErrConnectionLimit)
						faults = false
						replace()
						journal.Close()
						journal, err = agentclient.OpenJournal(stateDir, node, origin.String())
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(journal.Close)
						actor.Generation, err = journal.Begin(ctx, client)
						if err != nil || actor.Generation == generation {
							t.Fatal("clean pair restart did not establish a fresh generation", err)
						}
					} else if !a.readyLocked() || len(a.remote.jobs) != 0 {
						t.Fatal("healthy generation failed to finish cancellation after Lambda recovery")
					}
					var state string
					if err := admin.QueryRow(ctx, "SELECT state FROM supivpn.logins WHERE node_id=$1 AND generation=$2 AND cid=1", node, generation).Scan(&state); err != nil {
						t.Fatal(err)
					}
					wantState := "cancelled"
					if scenario == "api-outage-restart" {
						wantState = "acknowledged" // Retired generation, deliberately retained for audit.
					}
					if state != wantState {
						t.Fatalf("old row state=%s, want %s", state, wantState)
					}
					admit(actor, 4, controller.ErrDecisionPending)
					if actor.Generation != generation {
						cid, kid := int64(4), int64(1)
						if _, err := client.Call(ctx, "cancel", agentclient.Request{Generation: generation, CID: &cid, KID: &kid}); agentclient.Status(err) != http.StatusGone {
							t.Fatal("old-generation cancellation reached the replacement connection", err)
						}
						admit(other, 4, controller.ErrConnectionLimit)
					}
					if err := agentStore.Cancel(ctx, actor, postgres.Connection{CID: 4, KID: 1}); err != nil {
						t.Fatal(err)
					}
					admit(other, 1, controller.ErrDecisionPending) // Reconnect on either node works without DELETE.
				})
			}
		})
	}
}
