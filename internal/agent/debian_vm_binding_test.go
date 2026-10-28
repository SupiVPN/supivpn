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
	"net"
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
	for unit, expected := range map[string]string{"supivpn-node": "0000000000000002", "supivpn-openvpn-tcp": "0000000000001402"} {
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
	// Select one transport for refusal checks; port zero retains ordered fallback.
	if port != 0 {
		blocks := regexp.MustCompile(`(?s)<connection>.*?</connection>`).FindAll(data, -1)
		if len(blocks) != 0 {
			var selected []byte
			for _, block := range blocks {
				if bytes.Contains(block, []byte(fmt.Sprintf("remote localhost %d\n", port))) {
					selected = block
				}
			}
			if selected == nil {
				t.Fatal("profile transport missing")
			}
			data = regexp.MustCompile(`(?s)<connection>.*?</connection>\n`).ReplaceAll(data, nil)
			data = append(data, selected...)
		} else {
			data = regexp.MustCompile(`(?m)^remote localhost [0-9]+$`).ReplaceAll(data, []byte(fmt.Sprintf("remote localhost %d", port)))
			if port == 443 {
				data = bytes.Replace(data, []byte("proto udp4"), []byte("proto tcp4-client"), 1)
			}
		}
	}
	data = bytes.ReplaceAll(data, []byte("remote localhost "), []byte("remote 192.0.2.1 "))
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
		"--tls-exit", "--hand-window", "30", "--setenv", "IV_SSO", "webauth",
		"--setenv", "UV_UUID", "supivpn-vm-binding-device", "--verb", "3"}
	if !bytes.Contains(data, []byte("proto tcp4-client")) {
		args = append(args, "--explicit-exit-notify", "1")
	}
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

func vmUnboundDenied(t *testing.T, data []byte, port int) {
	t.Helper()
	unit := "supivpn-openvpn"
	if port == 443 {
		unit = "supivpn-openvpn-tcp"
	}
	cursor := vmCommand(t, "journalctl", "--unit="+unit, "--lines=0", "--show-cursor", "--output=cat", "--no-pager")
	if !strings.HasPrefix(cursor, "-- cursor: ") {
		t.Fatal("missing journal boundary for metadata rejection")
	}
	cursor = strings.TrimPrefix(cursor, "-- cursor: ")
	log := vmBindingClient(t, data, port, false)
	// A TCP metadata rejection closes the socket before TLS, so the client
	// need not emit UDP's handshake-timeout text. Require fresh server evidence
	// of our metadata verifier's refusal, not merely a reset or absent tunnel.
	vmWait(t, "server-side unbound metadata refusal", 30*time.Second, func() bool {
		journal := vmCommand(t, "journalctl", "--unit="+unit, "--after-cursor="+cursor, "--output=cat", "--no-pager")
		return strings.Contains(journal, "--tls-crypt-v2-verify") && strings.Contains(journal, "exited with error status: 1")
	})
	if log.contains("Initialization Sequence Completed") || log.contains("/login/") {
		t.Fatal("unbound profile reached authorization or tunnel initialization")
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
	vmWait(t, "bound UDP-only issuance", 30*time.Second, func() bool { return vmReady(client, 8443) })
	udpOnly := vmLogin(t, client, signer, "/profile", http.StatusOK)
	if !bytes.Contains(udpOnly, []byte("<auth-user-pass>")) || bytes.Contains(udpOnly, []byte("<connection>")) {
		t.Fatal("default setup must issue bound UDP-only profiles")
	}
	// Build only an isolated historical-format fixture; current issuance must
	// never offer it. No working credentials or external database are involved.
	wrapping, err := os.ReadFile("/etc/supivpn/keys/tls-crypt-v2-server.key")
	if err != nil {
		t.Fatal("synthetic wrapping key unavailable")
	}
	legacyKey, err := profile.GenerateClientKey(wrapping, time.Now())
	clear(wrapping)
	if err != nil {
		t.Fatal("historical fixture generation failed")
	}
	legacy := regexp.MustCompile(`(?s)<auth-user-pass>.*?</auth-user-pass>\n`).ReplaceAll(udpOnly, nil)
	legacy = regexp.MustCompile(`(?s)<tls-crypt-v2>.*?</tls-crypt-v2>`).ReplaceAll(legacy, append(append([]byte("<tls-crypt-v2>\n"), legacyKey...), []byte("</tls-crypt-v2>")...))
	clear(legacyKey)

	vmCommand(t, "systemctl", "stop", "supivpn-node")
	server, err := os.ReadFile("/etc/supivpn/node/openvpn.conf")
	if err != nil {
		t.Fatal("missing installed OpenVPN config")
	}
	routes := "-route-device supivpn0 -route-network 10.203.0.0/24"
	udpServer := strings.Replace(string(server), "-learn-address\"", "-learn-address "+routes+"\"", 1)
	udpServer += "client-disconnect \"/usr/sbin/supivpn -route-disconnect " + routes + "\"\n"
	vmWrite(t, "/etc/supivpn/node/openvpn.conf", []byte(udpServer), 0600, "")
	tcpServer := strings.NewReplacer("port 1194", "port 443", "proto udp4", "proto tcp4-server",
		"supivpn0", "supivpn1", "/run/supivpn/management.sock", "/run/supivpn/management-tcp.sock").Replace(udpServer)
	vmWrite(t, "/etc/supivpn/node/openvpn-tcp.conf", []byte(tcpServer), 0600, "")
	config := vmJSON(t, "/etc/supivpn/node/agent.json")
	config["tcp_management_socket"] = "/run/supivpn/management-tcp.sock"
	vmSaveJSON(t, "/etc/supivpn/node/agent.json", config, 0600, "")
	public := vmJSON(t, "/etc/supivpn/controller/controller.json")
	issuance := public["profile"].(map[string]any)
	issuance["tcp_fallback_port"], issuance["server_url"] = 443, true
	vmSaveJSON(t, "/etc/supivpn/controller/controller.json", public, 0640, "root:supivpn-controller")
	vmCommand(t, "systemd-analyze", "verify", "supivpn-node.service", "supivpn-openvpn.service", "supivpn-openvpn-tcp.service")
	vmCommand(t, "systemctl", "restart", "supivpn-controller")
	vmWait(t, "dual-transport issuance", 30*time.Second, func() bool { return vmReady(client, 8443) })
	vmCommand(t, "systemctl", "start", "supivpn-node")
	vmWait(t, "one node with both transports", 50*time.Second, func() bool { return vmReady(client, 9443) && vmPID(t, "supivpn-openvpn-tcp") != "0" })
	vmCheckSandbox(t)
	vmCheckBoundSandbox(t)
	listenerPIDs := map[string]string{}
	for _, unit := range []string{"supivpn-node", "supivpn-openvpn", "supivpn-openvpn-tcp"} {
		listenerPIDs[unit] = vmPID(t, unit)
	}
	for _, args := range [][]string{{"status"}, {"profiles", "list", "--limit", "1"}} {
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
				journal := vmCommand(t, "journalctl", "--unit=supivpn-node", "--since=-90 seconds", "--output=cat", "--no-pager", "--lines=100")
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
			out := vmCommand(t, "/usr/sbin/supivpn-cli", "sessions", "status", "--user", user)
			if json.Unmarshal([]byte(out), &sessions) != nil || sessions.Matched != 1 {
				t.Fatal("CLI did not find local owner session")
			}
			out = vmCommand(t, "/usr/sbin/supivpn-cli", "sessions", "drop", "--user", user, "--yes")
			if json.Unmarshal([]byte(out), &sessions) != nil || sessions.Requested != 1 {
				t.Fatal("CLI did not request termination")
			}
			vmWait(t, "CLI confirmed session closure", 15*time.Second, func() bool {
				out := vmCommand(t, "/usr/sbin/supivpn-cli", "sessions", "status", "--user", user)
				return json.Unmarshal([]byte(out), &sessions) == nil && sessions.Matched == 0 && sessions.Unidentified == 0
			})
		}
	}
	check("old-bound-UDP-only", func(t *testing.T) { accepted(t, udpOnly, 1194, "10.203.0.1", true) })
	check("UDP-preferred", func(t *testing.T) { accepted(t, bound, 0, "10.203.0.1", true) })
	check("UDP-unavailable-falls-back-to-TCP", func(t *testing.T) {
		blackhole, err := net.ListenPacket("udp4", "0.0.0.0:1196")
		if err != nil {
			t.Fatal("test blackhole unavailable")
		}
		defer blackhole.Close()
		data := bytes.Replace(bound, []byte("remote localhost 1194"), []byte("remote localhost 1196"), 1)
		accepted(t, data, 0, "10.203.0.1", true)
	})
	for _, port := range []int{1194, 443} {
		check(fmt.Sprintf("unbound-refused-%d", port), func(t *testing.T) { vmUnboundDenied(t, legacy, port) })
		check(fmt.Sprintf("stripped-proof-refused-%d", port), func(t *testing.T) {
			stripped := regexp.MustCompile(`(?s)<auth-user-pass>.*?</auth-user-pass>\n`).ReplaceAll(bound, nil)
			vmBindingDenied(t, vmBindingClient(t, stripped, port, false), true)
		})
		check(fmt.Sprintf("wrong-owner-refused-%d", port), func(t *testing.T) {
			log := vmBindingClient(t, bound, port, true)
			vmLoginAs(t, client, signer, vmBindingChallenge(t, log), http.StatusForbidden, time.Time{}, "other-authorized-user")
			vmBindingDenied(t, log, false)
		})
		check(fmt.Sprintf("wrong-proof-refused-%d", port), func(t *testing.T) {
			other, e := profile.NewCredential()
			if e != nil {
				t.Fatal("test entropy unavailable")
			}
			wrong := bytes.Replace(bound, []byte(proof.Secret), []byte(other.Secret), 1)
			vmBindingDenied(t, vmBindingClient(t, wrong, port, true), true)
		})
	}
	vmProfileOperation(t, "profile-block", proof.ID, 1, true)
	for _, port := range []int{1194, 443} {
		check(fmt.Sprintf("blocked-before-browser-%d", port), func(t *testing.T) { vmBindingDenied(t, vmBindingClient(t, bound, port, true), true) })
	}
	vmProfileOperation(t, "profile-activate", proof.ID, 1, false)
	vmProfileOperation(t, "profile-activate", proof.ID, 2, true)
	check("reactivated-owner-TCP", func(t *testing.T) { accepted(t, bound, 443, "10.203.0.1", true) })
	journal := vmCommand(t, "journalctl", "--unit=supivpn-node", "--output=cat", "--no-pager")
	if !strings.Contains(journal, proof.ID) || !strings.Contains(journal, "supivpn-vm-binding-device") || strings.Contains(journal, proof.Secret) || strings.Contains(journal, "SAMLResponse=") {
		t.Fatal("bound journal lost diagnostics or disclosed credentials (raw journal withheld)")
	}
	// Both transports share the generation. Losing either daemon must restart
	// the whole node, never rotate ownership while its sibling keeps tunnels.
	for _, crashed := range []string{"supivpn-openvpn-tcp", "supivpn-openvpn"} {
		vmResetCrashBudget(t, client)
		before := map[string]string{}
		for _, unit := range []string{"supivpn-node", "supivpn-openvpn", "supivpn-openvpn-tcp"} {
			before[unit] = vmPID(t, unit)
		}
		vmCommand(t, "systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", crashed)
		vmWait(t, "both transports recovered after "+crashed, 60*time.Second, func() bool {
			for unit, old := range before {
				if pid := vmPID(t, unit); pid == "0" || pid == old {
					return false
				}
			}
			return vmReady(client, 9443)
		})
	}
	t.Log("one node with UDP/TCP passed fallback, ownership, block/reactivate, HTTPS import and device-log checks")
}
