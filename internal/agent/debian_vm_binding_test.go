// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration && linux

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"supivpn/internal/operatorapi"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
)

func vmCheckBoundSandbox(t *testing.T) {
	t.Helper()
	for unit, expected := range map[string]string{"supivpn-node@bound": "0000000000000002", "supivpn-openvpn@bound": "0000000000001002"} {
		data, err := os.ReadFile("/proc/" + vmPID(t, unit) + "/status")
		if err != nil || !strings.Contains(string(data), "CapBnd:\t"+expected) || !strings.Contains(string(data), "NoNewPrivs:\t1") {
			t.Fatal("bound instance lost its installed sandbox", unit)
		}
	}
}

func vmProfileOperation(t *testing.T, action, id string, revision int, success bool) operatorapi.Reply {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := []string{"profiles", strings.TrimPrefix(action, "profile-"), id}
	if revision != 0 {
		args = append(args, "--revision", fmt.Sprint(revision), "--yes")
	}
	cmd := exec.CommandContext(ctx, "/usr/sbin/supivpn-cli", args...)
	out, err := cmd.Output()
	var state postgres.ProfileState
	if (err == nil) != success || success && json.Unmarshal(out, &state) != nil {
		t.Fatal("installed operator command returned an unexpected result (output withheld)")
	}
	return operatorapi.Reply{OK: success, State: &postgres.OperatorState{Profile: &state}}
}

func vmBindingClient(t *testing.T, data []byte, port int, inline bool) *protocolLog {
	t.Helper()
	dir := t.TempDir()
	data = regexp.MustCompile(`(?m)^remote localhost [0-9]+$`).ReplaceAll(data, []byte(fmt.Sprintf("remote 192.0.2.1 %d", port)))
	path := filepath.Join(dir, "client.ovpn")
	vmWrite(t, path, data, 0600, "")
	vmCommand(t, "ip", "netns", "add", "supivpn-binding-client")
	t.Cleanup(func() { vmCommand(t, "ip", "netns", "delete", "supivpn-binding-client") })
	vmCommand(t, "ip", "link", "add", "supi-bind-host", "type", "veth", "peer", "name", "supi-bind-peer")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "delete", "supi-bind-host").Run() })
	vmCommand(t, "ip", "link", "set", "supi-bind-peer", "netns", "supivpn-binding-client")
	vmCommand(t, "ip", "addr", "add", "192.0.2.1/30", "dev", "supi-bind-host")
	vmCommand(t, "ip", "link", "set", "supi-bind-host", "up")
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", "192.0.2.2/30", "dev", "supi-bind-peer"}, {"link", "set", "supi-bind-peer", "up"}} {
		vmCommand(t, "ip", append([]string{"-n", "supivpn-binding-client"}, args...)...)
	}
	args := []string{"netns", "exec", "supivpn-binding-client", "/usr/sbin/openvpn", "--config", path,
		"--dev", "supibclient", "--dev-type", "tun", "--disable-dco", "--connect-retry-max", "1",
		"--tls-exit", "--hand-window", "30", "--explicit-exit-notify", "1", "--setenv", "IV_SSO", "webauth",
		"--setenv", "UV_UUID", "supivpn-vm-binding-device", "--verb", "3"}
	if !inline {
		auth := filepath.Join(dir, "auth")
		vmWrite(t, auth, []byte("unused-test\nunused-test\n"), 0600, "")
		args = append(args, "--auth-user-pass", auth)
	}
	cmd := exec.Command("ip", args...)
	log := &protocolLog{}
	cmd.Stdout, cmd.Stderr = log, log
	if cmd.Start() != nil {
		t.Fatal("cannot start bound VM client")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	return log
}

func vmBindingChallenge(t *testing.T, log *protocolLog) string {
	t.Helper()
	var path string
	vmWait(t, "bound-profile SAML challenge", 30*time.Second, func() bool {
		log.mu.Lock()
		defer log.mu.Unlock()
		match := regexp.MustCompile(`https://localhost:8443(/login/[A-Za-z0-9_-]+)`).FindStringSubmatch(log.b.String())
		if len(match) != 2 {
			return false
		}
		path = match[1]
		return true
	})
	return path
}

func vmBindingDenied(t *testing.T, log *protocolLog, beforeSAML bool) {
	t.Helper()
	vmWait(t, "refusal from unmodified OpenVPN", 40*time.Second, func() bool {
		return log.contains("AUTH_FAILED") || log.contains("TLS Error: TLS key negotiation failed") || log.contains("TLS Error: TLS handshake failed")
	})
	if log.contains("Initialization Sequence Completed") || (beforeSAML && log.contains("/login/")) {
		t.Fatal("refused profile reached an unauthorized stage")
	}
}

func TestDebianVMProfileBinding(t *testing.T) {
	requireDebianVM(t)
	signer, metadata := testIdP(t)
	md, err := xml.Marshal(metadata)
	if err != nil {
		t.Fatal("cannot encode synthetic IdP")
	}
	vmWrite(t, "/etc/supivpn/controller/idp-metadata.xml", md, 0640, "root:supivpn-controller")
	vmWrite(t, "/etc/supivpn/node/idp-metadata.xml", md, 0600, "")
	client := vmHTTPS(t)
	vmCommand(t, "systemctl", "restart", "supivpn-controller")
	vmWait(t, "legacy issuance", 30*time.Second, func() bool { return vmReady(client, 8443) })
	legacy := vmLogin(t, client, signer, "/profile", http.StatusOK)
	if bytes.Contains(legacy, []byte("<auth-user-pass>")) {
		t.Fatal("legacy fixture unexpectedly bound")
	}

	vmCommand(t, "systemctl", "stop", "supivpn-node")
	server, err := os.ReadFile("/etc/supivpn/node/openvpn.conf")
	if err != nil {
		t.Fatal("missing installed OpenVPN config")
	}
	vmWrite(t, "/etc/supivpn/node/openvpn.conf", append(bytes.Clone(server), []byte("\ntls-crypt-v2-verify \"/usr/sbin/supivpn -verify-profile-metadata legacy\"\n")...), 0600, "")
	vmCommand(t, "install", "-d", "-m", "0700", "/etc/supivpn/nodes/bound")
	boundServer := strings.NewReplacer("port 1194", "port 1195", "dev supivpn0", "dev supivpn1",
		"10.203.0.0", "10.204.0.0", "/run/supivpn/management.sock", "/run/supivpn-bound/management.sock").Replace(string(server))
	boundServer += "\ntls-crypt-v2-verify \"/usr/sbin/supivpn -verify-profile-metadata required\"\n"
	vmWrite(t, "/etc/supivpn/nodes/bound/openvpn.conf", []byte(boundServer), 0600, "")
	config := vmJSON(t, "/etc/supivpn/node/agent.json")
	config["profile_binding"], config["listen"], config["public_url"] = "required", "127.0.0.1:9444", "https://localhost:9444"
	config["management_socket"], config["vpn_network"] = "/run/supivpn-bound/management.sock", "10.204.0.0/24"
	remote := config["remote_controller"].(map[string]any)
	remote["agent_socket"], remote["node_id"], remote["state_directory"] = "/run/supivpn-controller/agent-bound.sock", "node-bound", "/var/lib/supivpn-node-bound"
	for _, raw := range config["group_pools"].([]any) {
		pool := raw.(map[string]any)
		pool["cidr"] = strings.Replace(pool["cidr"].(string), "10.203.", "10.204.", 1)
	}
	vmSaveJSON(t, "/etc/supivpn/nodes/bound/agent.json", config, 0600, "")
	public := vmJSON(t, "/etc/supivpn/controller/controller.json")
	public["vm"].(map[string]any)["additional_agents"] = []any{map[string]any{"socket": "/run/supivpn-controller/agent-bound.sock", "uid": 0, "node_id": "node-bound"}}
	issuance := public["profile"].(map[string]any)
	issuance["binding"], issuance["port"], issuance["server_url"] = "required", 1195, true
	vmSaveJSON(t, "/etc/supivpn/controller/controller.json", public, 0640, "root:supivpn-controller")
	vmCommand(t, "systemd-analyze", "verify", "supivpn-node@bound.service", "supivpn-openvpn@bound.service")
	vmCommand(t, "systemctl", "restart", "supivpn-controller")
	vmWait(t, "bound issuance", 30*time.Second, func() bool { return vmReady(client, 8443) })
	vmCommand(t, "systemctl", "start", "supivpn-node", "supivpn-node@bound")
	vmWait(t, "both installed pairs", 50*time.Second, func() bool { return vmReady(client, 9443) && vmReady(client, 9444) })
	vmCheckSandbox(t)
	vmCheckBoundSandbox(t)
	listenerPIDs := map[string]string{}
	for _, unit := range []string{"supivpn-node", "supivpn-openvpn", "supivpn-node@bound", "supivpn-openvpn@bound"} {
		listenerPIDs[unit] = vmPID(t, unit)
	}
	for _, args := range [][]string{{"status"}, {"status", "--instance", "bound"}, {"profiles", "list", "--limit", "1"}} {
		if out := vmCommand(t, "/usr/sbin/supivpn-cli", args...); !json.Valid([]byte(out)) {
			t.Fatal("CLI returned invalid JSON")
		}
	}
	refused := exec.Command("runuser", "-u", "nobody", "--", "/usr/sbin/supivpn-cli", "status")
	if refused.Run() == nil {
		t.Fatal("non-root CLI operation succeeded")
	}

	// Redeem the product's Server URL grant over actual HTTPS. The native
	// Connect browser handoff is a separate interactive acceptance test.
	for _, method := range []string{"GET", "HEAD"} {
		req, _ := http.NewRequest(method, "https://localhost:8443/openvpn-api/profile", nil)
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal("discovery unavailable")
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Ovpn-WebAuth") != "SupiVPN,external" {
			t.Fatal("Server URL discovery invalid")
		}
	}
	page := vmLogin(t, client, signer, "/profile/connect", http.StatusOK)
	match := regexp.MustCompile(`openvpn://import-profile/(https://[^"<>]+)`).FindSubmatch(page)
	if len(match) != 2 {
		t.Fatal("authorized import link missing")
	}
	address := html.UnescapeString(string(match[1]))
	u, err := url.Parse(address)
	if err != nil || u.Host != "localhost:8443" || !strings.HasPrefix(u.Path, "/profile/import/") {
		t.Fatal("unexpected import origin")
	}
	resp, err := client.Get(address)
	if err != nil {
		t.Fatal("import unavailable")
	}
	bound, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || len(bound) > 65536 {
		t.Fatal("profile import failed")
	}
	resp, err = client.Get(address)
	if err != nil {
		t.Fatal("replay check unavailable")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatal("one-use import replayed")
	}
	proofMatch := regexp.MustCompile(`<auth-user-pass>\n([^\n]+)\n([^\n]+)\n</auth-user-pass>`).FindSubmatch(bound)
	if len(proofMatch) != 3 {
		t.Fatal("missing inline profile proof")
	}
	proof := profile.Credential{ID: string(proofMatch[1]), Secret: string(proofMatch[2])}
	if !proof.Valid() || !bytes.Contains(bound, []byte("verify-x509-name localhost name")) {
		t.Fatal("bound profile identity or proof invalid")
	}
	state := vmProfileOperation(t, "profile-status", proof.ID, 0, true)
	if state.State == nil || state.State.Profile == nil || state.State.Profile.State != "active" {
		t.Fatal("issued profile was not registered active")
	}
	check := func(name string, f func(*testing.T)) {
		t.Helper()
		for unit, pid := range listenerPIDs {
			if vmPID(t, unit) != pid {
				t.Fatal("a refused client restarted a listener before", name)
			}
		}
		if !t.Run(name, f) {
			t.FailNow()
		}
		vmWait(t, "profile test slot release", 15*time.Second, func() bool {
			return vmDatabaseQuery(t, "SELECT NOT EXISTS (SELECT 1 FROM supivpn.logins l JOIN supivpn.nodes n ON n.node_id=l.node_id AND n.generation=l.generation WHERE l.denial_reason='' AND l.state IN ('decided','acknowledged') AND (l.ack_result IS NULL OR l.ack_result='applied') AND n.fence_state<>'stopped')") == "t"
		})
		for unit, pid := range listenerPIDs {
			if vmPID(t, unit) != pid {
				t.Fatal("a client disrupted another listener during", name)
			}
		}
	}
	accepted := func(t *testing.T, data []byte, port int, gateway string, inline bool) {
		log := vmBindingClient(t, data, port, inline)
		defer func() {
			if t.Failed() {
				for _, category := range []string{"AUTH_FAILED", "TLS Error", "Initialization Sequence Completed", "Inactivity timeout", "SIGTERM", "PUSH_REPLY"} {
					t.Logf("client diagnostic %s=%t", category, log.contains(category))
				}
				t.Log("current-generation decision states:", vmDatabaseQuery(t, "SELECT coalesce(string_agg(state||':'||denial_reason||':'||coalesce(ack_result,''),','),'none') FROM supivpn.logins l JOIN supivpn.nodes n ON n.node_id=l.node_id AND n.generation=l.generation"))
				journal := vmCommand(t, "journalctl", "--unit=supivpn-node@bound", "--since=-90 seconds", "--output=cat", "--no-pager", "--lines=100")
				for _, line := range strings.Split(journal, "\n") {
					var fields map[string]any
					if json.Unmarshal([]byte(line), &fields) != nil {
						continue
					}
					// Only static event/enum fields and numeric correlation IDs.
					// Never print the raw journal, username, URL or profile proof.
					safe := map[string]any{}
					for _, key := range []string{"event", "reason", "operation", "outcome"} {
						if value, ok := fields[key].(string); ok && regexp.MustCompile(`^[a-z_.]{1,64}$`).MatchString(value) {
							safe[key] = value
						}
					}
					for _, key := range []string{"cid", "kid", "status"} {
						if value, ok := fields[key].(float64); ok {
							safe[key] = value
						}
					}
					encoded, _ := json.Marshal(safe)
					t.Log("agent diagnostic:", string(encoded))
				}
			}
		}()
		vmLogin(t, client, signer, vmBindingChallenge(t, log), http.StatusAccepted)
		vmWait(t, "authorized tunnel", 30*time.Second, func() bool { return log.contains("Initialization Sequence Completed") })
		vmCommand(t, "ip", "netns", "exec", "supivpn-binding-client", "ping", "-c", "2", "-W", "3", gateway)
		if inline {
			var sessions struct {
				Matched      int `json:"matched"`
				Requested    int `json:"requested"`
				Unidentified int `json:"unidentified"`
			}
			// groupAssertionFor uses this exact synthetic NameID.
			user := "test-user"
			out := vmCommand(t, "/usr/sbin/supivpn-cli", "sessions", "status", "--user", user, "--instance", "bound")
			if json.Unmarshal([]byte(out), &sessions) != nil || sessions.Matched != 1 {
				t.Fatal("CLI did not find local owner session")
			}
			out = vmCommand(t, "/usr/sbin/supivpn-cli", "sessions", "drop", "--user", user, "--instance", "bound", "--yes")
			if json.Unmarshal([]byte(out), &sessions) != nil || sessions.Requested != 1 {
				t.Fatal("CLI did not request termination")
			}
			vmWait(t, "CLI confirmed session closure", 15*time.Second, func() bool {
				out := vmCommand(t, "/usr/sbin/supivpn-cli", "sessions", "status", "--user", user, "--instance", "bound")
				return json.Unmarshal([]byte(out), &sessions) == nil && sessions.Matched == 0 && sessions.Unidentified == 0
			})
		}
	}
	check("legacy-on-legacy-port", func(t *testing.T) { accepted(t, legacy, 1194, "10.203.0.1", false) })
	check("owner-on-bound-port", func(t *testing.T) { accepted(t, bound, 1195, "10.204.0.1", true) })
	check("legacy-on-bound-port-refused", func(t *testing.T) { vmBindingDenied(t, vmBindingClient(t, legacy, 1195, false), true) })
	check("bound-on-legacy-port-refused", func(t *testing.T) { vmBindingDenied(t, vmBindingClient(t, bound, 1194, true), true) })
	check("stripped-bound-on-legacy-port-refused", func(t *testing.T) {
		stripped := regexp.MustCompile(`(?s)<auth-user-pass>.*?</auth-user-pass>\n`).ReplaceAll(bound, nil)
		vmBindingDenied(t, vmBindingClient(t, stripped, 1194, false), true)
	})
	check("wrong-owner-refused", func(t *testing.T) {
		log := vmBindingClient(t, bound, 1195, true)
		vmLoginAs(t, client, signer, vmBindingChallenge(t, log), http.StatusForbidden, time.Time{}, "other-authorized-user")
		vmBindingDenied(t, log, false)
	})
	check("wrong-proof-refused", func(t *testing.T) {
		other, e := profile.NewCredential()
		if e != nil {
			t.Fatal("test entropy unavailable")
		}
		wrong := bytes.Replace(bound, []byte(proof.Secret), []byte(other.Secret), 1)
		vmBindingDenied(t, vmBindingClient(t, wrong, 1195, true), true)
	})
	vmProfileOperation(t, "profile-block", proof.ID, 1, true)
	check("blocked-before-browser", func(t *testing.T) { vmBindingDenied(t, vmBindingClient(t, bound, 1195, true), true) })
	vmProfileOperation(t, "profile-activate", proof.ID, 1, false)
	vmProfileOperation(t, "profile-activate", proof.ID, 2, true)
	check("reactivated-owner", func(t *testing.T) { accepted(t, bound, 1195, "10.204.0.1", true) })
	journal := vmCommand(t, "journalctl", "--unit=supivpn-node@bound", "--output=cat", "--no-pager")
	if !strings.Contains(journal, proof.ID) || !strings.Contains(journal, "supivpn-vm-binding-device") || strings.Contains(journal, proof.Secret) || strings.Contains(journal, "SAMLResponse=") {
		t.Fatal("bound journal lost diagnostics or disclosed credentials (raw journal withheld)")
	}
	vmCommand(t, "systemctl", "enable", "supivpn-node@bound")
	t.Log("two unmodified OpenVPN listeners passed ownership, cross-port denial, block/reactivate, HTTPS import and device-log checks")
}
