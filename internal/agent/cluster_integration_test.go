// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/beevik/etree"
	"supivpn/internal/agentapi"
	"supivpn/internal/agentclient"
	"supivpn/internal/controller"
	"supivpn/internal/gateway"
	"supivpn/internal/postgres"
	"supivpn/internal/saml"
)

// Two simultaneous nodes use identical CID/KID and generation labels. Identity
// comes from the trusted REST IAM envelope, and all controller replicas share PG.
func TestClusterTwoNodes(t *testing.T) {
	p, other := integrationDatabase(t)
	ctx := context.Background()
	if _, err := p.Exec(ctx, "TRUNCATE supivpn.logins,supivpn.assertions,supivpn.nodes RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal("test reset failed")
	}
	stores := []*postgres.Store{postgres.New(p), postgres.New(other)}
	signer, md := testIdP(t)
	fixture, _ := testApp(t, md)
	policy := controller.Config{Policy: controllerPolicy(clusterGroupConfig(0)),
		PendingSeconds: 180, SessionSeconds: 900}
	controllers := make([]*controller.Controller, 2)
	// Use the real handlers and two independent DB pools.
	for i := range controllers {
		c, err := controller.New(policy, fixture.origin, fixture.sp, stores[i], time.Now)
		if err != nil {
			t.Fatal(err)
		}
		controllers[i] = c
	}
	nodes := []string{"i-00000000000000001", "i-00000000000000002"}
	principals := map[string]string{}
	for _, node := range nodes {
		principals["arn:aws:sts::123456789012:assumed-role/supivpn/"+node] = node
	}
	agents := make([]*agent, 2)
	commands := make([]chan string, 2)
	clients := make([]*agentclient.Client, 2)
	for i, node := range nodes {
		adapter, err := gateway.New(gateway.Config{APIID: "testapi", AccountID: "123456789012", Stage: "live",
			Domains: []string{fixture.origin.Hostname()}, AgentPrincipals: principals},
			fixture.origin, controllers[i].Handler(), agentapi.New(stores[i], 180*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		client, err := agentclient.New("https://login.example.test", agentRoundTrip(func(r *http.Request) (*http.Response, error) {
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				return nil, readErr
			}
			path := r.URL.Path
			out, err := adapter.HandleREST(ctx, events.APIGatewayProxyRequest{
				Resource: path, Path: path, HTTPMethod: "POST", Headers: map[string]string{"Host": fixture.origin.Host, "Content-Type": "application/json"}, Body: string(body),
				RequestContext: events.APIGatewayProxyRequestContext{APIID: "testapi", AccountID: "123456789012", Stage: "live",
					DomainName: fixture.origin.Hostname(), ResourcePath: path, Path: "/live" + path, HTTPMethod: "POST",
					Identity: events.APIGatewayRequestIdentity{AccountID: "123456789012", UserArn: "arn:aws:sts::123456789012:assumed-role/supivpn/" + node}},
			})
			if err != nil {
				return nil, err
			}
			response := httptest.NewRecorder()
			for k, v := range out.Headers {
				response.Header().Set(k, v)
			}
			response.WriteHeader(out.StatusCode)
			response.WriteString(out.Body)
			return response.Result(), nil
		}), nil)
		if err != nil {
			t.Fatal(err)
		}
		clients[i] = client
		t.Cleanup(client.Close)
		if _, err = client.Call(ctx, "rotate", agentclient.Request{Generation: "g1"}); err != nil {
			t.Fatal(err)
		}
		a, ch := remoteFixture(t, client)
		a.remote.node = node
		a.config = clusterGroupConfig(i)
		a.pools = newPoolAllocator(a.config)
		agents[i], commands[i] = a, ch
		connectRemote(t, a, ch)
	}
	// Both requests coexist before either browser finishes; second controller
	// handles the callback even though the first one initiated it.
	complete := func(i int) {
		t.Helper()
		ticket := agents[i].connections[7].ticket
		w := confirmVPNLogin(t, controllers[0].Handler(), fixture.origin, ticket)
		if w.Code != 302 || len(w.Result().Cookies()) != 2 {
			t.Fatal("SAML redirect failed")
		}
		cookie := samlLoginCookie(t, w.Result(), ticket)
		pending, err := stores[1].Lookup(ctx, ticket, sha256.Sum256([]byte(cookie.Value)))
		if err != nil {
			t.Fatal("shared browser binding missing")
		}
		assertion := assertionFor(fixture)
		assertion.ID = fmt.Sprintf("cluster-assertion-%d", i)
		assertion.Subject.NameID.Value = fmt.Sprintf("cluster-user-%d", i)
		assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = pending.RequestID
		assertion.AttributeStatements = []saml.AttributeStatement{{Attributes: []saml.Attribute{{Name: "groups",
			Values: []saml.AttributeValue{{Value: "engineers-production-vpn"}, {Value: "admins-vpn"}}}}}}
		sr := saml.Response{ID: fmt.Sprintf("cluster-response-%d", i), InResponseTo: pending.RequestID, Version: "2.0",
			IssueInstant: time.Now().UTC(), Destination: fixture.sp.AcsURL.String(), Issuer: &assertion.Issuer,
			Status: saml.Status{StatusCode: saml.StatusCode{Value: "urn:oasis:names:tc:SAML:2.0:status:Success"}}, Assertion: assertion}
		signing, err := saml.GetSigningContext(signer)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signing.SignEnveloped(sr.Element())
		if err != nil {
			t.Fatal(err)
		}
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		data, err := doc.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"RelayState": {ticket}, "SAMLResponse": {base64.StdEncoding.EncodeToString(data)}}.Encode()
		request := httptest.NewRequest("POST", fixture.sp.AcsURL.String(), strings.NewReader(form))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		result := httptest.NewRecorder()
		controllers[1].Handler().ServeHTTP(result, request)
		if result.Code != 202 {
			t.Fatalf("SAML callback status=%d", result.Code)
		}
	}
	for i := range nodes {
		complete(i)
	}
	cid, kid := int64(7), int64(2)
	query := agentclient.Request{Generation: "g1", CID: &cid, KID: &kid}
	first, err := clients[0].Call(ctx, "fetch", query)
	if err != nil || first == nil {
		t.Fatal("first decision missing")
	}
	second, err := clients[1].Call(ctx, "fetch", query)
	if err != nil || second == nil {
		t.Fatal("second decision missing")
	}
	if first.ID == second.ID || first.NodeID == second.NodeID {
		t.Fatal("decisions not node-scoped")
	}
	if _, err = clients[1].Call(ctx, "ack", agentclient.Request{Generation: "g1", DecisionID: first.ID, Outcome: "applied"}); err == nil {
		t.Fatal("cross-node ACK accepted")
	}
	if agents[1].validRemoteDecision(agents[1].connections[7], first) {
		t.Fatal("cross-node decision accepted")
	}
	remoteStepNow(agents[0])
	if cmd := <-commands[0]; cmd != "client-auth 7 2\nifconfig-push 10.200.0.2 255.255.240.0\nEND" {
		t.Fatal("node 1 pool incorrect")
	}
	// Restart/rotate one node while the other still has an unacknowledged decision.
	agents[0].management.close()
	if _, err = clients[0].Call(ctx, "rotate", agentclient.Request{Previous: "g1", Generation: "g2"}); err != nil {
		t.Fatal(err)
	}
	again, err := clients[1].Call(ctx, "fetch", query)
	if err != nil || again == nil {
		t.Fatal("node 1 restart invalidated node 2")
	}
	before, _ := json.Marshal(second)
	after, _ := json.Marshal(again)
	if string(before) != string(after) {
		t.Fatal("node 2 decision changed")
	}
	remoteStepNow(agents[1])
	if cmd := <-commands[1]; cmd != "client-auth 7 2\nifconfig-push 10.200.0.129 255.255.240.0\nEND" {
		t.Fatal("node 2 pool incorrect")
	}
	remoteStepNow(agents[1])
}
