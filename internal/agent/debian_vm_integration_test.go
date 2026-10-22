// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration && linux

package agent

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
)

// This opt-in test controls installed services and writes system configuration.
// It must only run in the disposable VM created by the Debian acceptance runner.
func requireDebianVM(t *testing.T) {
	t.Helper()
	if os.Getenv("SUPIVPN_TEST_DEBIAN_VM") != "1" {
		t.Skip("requires the disposable Debian VM acceptance runner")
	}
	marker, err := os.ReadFile("/etc/supivpn-disposable-vm")
	pid1, pidErr := os.ReadFile("/proc/1/comm")
	version, versionErr := os.ReadFile("/etc/debian_version")
	if err != nil || string(marker) != "Debian package acceptance only\n" ||
		pidErr != nil || strings.TrimSpace(string(pid1)) != "systemd" ||
		versionErr != nil || !strings.HasPrefix(string(version), "13.") || os.Geteuid() != 0 {
		t.Fatal("refusing service operations outside the disposable Debian 13 VM")
	}
	if _, err := os.Stat("/.dockerenv"); !os.IsNotExist(err) {
		t.Fatal("a container is not VM acceptance")
	}
}

func vmCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		// A command may handle generated passwords, profiles or one-time URLs.
		t.Fatalf("VM command %s failed (output withheld): %v", filepath.Base(name), err)
	}
	return strings.TrimSpace(string(out))
}

func vmWrite(t *testing.T, path string, data []byte, mode os.FileMode, owner string) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal("cannot write VM fixture", path)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal("cannot set VM fixture permissions")
	}
	if owner != "" {
		vmCommand(t, "chown", owner, path)
	}
}

func vmJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read packaged example", path)
	}
	var value map[string]any
	if err := json.Unmarshal(b, &value); err != nil {
		t.Fatal("invalid packaged example")
	}
	return value
}

func vmSaveJSON(t *testing.T, path string, value map[string]any, mode os.FileMode, owner string) {
	t.Helper()
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal("cannot encode VM configuration")
	}
	vmWrite(t, path, b, mode, owner)
}

func vmWait(t *testing.T, what string, timeout time.Duration, ready func() bool) {
	t.Helper()
	until := time.Now().Add(timeout)
	for time.Now().Before(until) {
		if ready() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("timed out waiting for", what)
}

func vmHTTPS(t *testing.T) *http.Client {
	t.Helper()
	ca, err := os.ReadFile("/etc/supivpn/node/ca.pem")
	if err != nil {
		t.Fatal("missing test CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func vmReady(client *http.Client, port int) bool {
	path := "/readyz"
	if port == 8443 {
		path = "/healthz"
	}
	resp, err := client.Get(fmt.Sprintf("https://localhost:%d%s", port, path))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func vmPID(t *testing.T, unit string) string {
	t.Helper()
	return vmCommand(t, "systemctl", "show", "--property=MainPID", "--value", unit)
}

func TestDebianVMPrepare(t *testing.T) {
	requireDebianVM(t)
	if _, err := os.Stat("/etc/supivpn"); !os.IsNotExist(err) {
		t.Fatal("fresh VM required: refusing to overwrite existing operator files")
	}
	for _, unit := range []string{"supivpn-node", "supivpn-openvpn", "supivpn-controller"} {
		if vmPID(t, unit) != "0" {
			t.Fatal("package installation started a service")
		}
	}
	vmCommand(t, "install", "-d", "-m", "0755", "/etc/supivpn")
	vmCommand(t, "install", "-d", "-m", "0700", "/etc/supivpn/node")
	for _, dir := range []string{"/etc/supivpn/controller", "/etc/supivpn/keys"} {
		vmCommand(t, "install", "-d", "-m", "0750", "-g", "supivpn-controller", dir)
	}
	ca := testVPNCertificate(t, "/etc/supivpn/node")
	vmWrite(t, "/etc/supivpn/node/chain.pem", ca, 0600, "")
	_, metadata := testIdP(t)
	md, err := xml.Marshal(metadata)
	if err != nil {
		t.Fatal("cannot encode test IdP metadata")
	}
	vmWrite(t, "/etc/supivpn/node/idp-metadata.xml", md, 0600, "")
	for _, name := range []string{"crt.pem", "key.pem", "chain.pem", "ca.pem", "idp-metadata.xml"} {
		data, err := os.ReadFile("/etc/supivpn/node/" + name)
		if err != nil {
			t.Fatal("cannot copy generated fixture")
		}
		vmWrite(t, "/etc/supivpn/controller/"+name, data, 0640, "root:supivpn-controller")
	}
	issuer := profile.Issuer{OpenVPN: "/usr/sbin/openvpn"}
	keyPath := "/etc/supivpn/keys/tls-crypt-v2-server.key"
	vmCommand(t, "chmod", "0700", "/etc/supivpn/keys")
	if err := issuer.EnsureServerKey(context.Background(), keyPath); err != nil {
		t.Fatal("test wrapping-key generation failed")
	}
	vmCommand(t, "chown", "supivpn-controller:supivpn-controller", keyPath)
	vmCommand(t, "chmod", "0750", "/etc/supivpn/keys")
	uid := vmCommand(t, "id", "-u", "supivpn-controller")
	controllerUID, err := strconv.Atoi(uid)
	if err != nil || controllerUID <= 0 {
		t.Fatal("invalid controller service identity")
	}
	agentConfig := vmJSON(t, "/usr/share/doc/supivpn-node/examples/agent.example.json")
	agentConfig["public_url"] = "https://localhost:9443"
	remote := agentConfig["remote_controller"].(map[string]any)
	remote["controller_uid"], remote["public_url"] = controllerUID, "https://localhost:8443"
	vmSaveJSON(t, "/etc/supivpn/node/agent.json", agentConfig, 0600, "")
	controllerConfig := vmJSON(t, "/usr/share/doc/supivpn-controller/examples/controller.example.json")
	controllerConfig["public_url"] = "https://localhost:8443"
	controllerConfig["database_tls"] = map[string]any{"mode": "verify-full", "ca_file": "/etc/supivpn/controller/ca.pem", "server_name": "localhost"}
	controllerConfig["profile"].(map[string]any)["endpoint"] = "localhost"
	vmSaveJSON(t, "/etc/supivpn/controller/controller.json", controllerConfig, 0640, "root:supivpn-controller")
	template, err := os.ReadFile("/usr/share/doc/supivpn-controller/examples/client.ovpn.example")
	if err != nil {
		t.Fatal("missing installed client template")
	}
	start, end := bytes.Index(template, []byte("<ca>")), bytes.Index(template, []byte("</ca>"))
	if start < 0 || end < start {
		t.Fatal("invalid packaged client template")
	}
	template = bytes.Join([][]byte{template[:start], []byte("<ca>\n"), ca, template[end:]}, nil)
	vmWrite(t, "/etc/supivpn/controller/client.ovpn.template", template, 0640, "root:supivpn-controller")
	server, err := os.ReadFile("/usr/share/doc/supivpn-node/examples/server.conf.example")
	if err != nil {
		t.Fatal("missing installed server example")
	}
	server = bytes.ReplaceAll(server, []byte("/etc/ssl/certs/ca-certificates.crt"), []byte("/etc/supivpn/node/ca.pem"))
	vmWrite(t, "/etc/supivpn/node/openvpn.conf", server, 0600, "")
	vmDatabase(t)
}

func TestDebianVMServices(t *testing.T) {
	requireDebianVM(t)
	signer, metadata := testIdP(t)
	md, err := xml.Marshal(metadata)
	if err != nil {
		t.Fatal("cannot encode test IdP metadata")
	}
	vmWrite(t, "/etc/supivpn/node/idp-metadata.xml", md, 0600, "")
	vmWrite(t, "/etc/supivpn/controller/idp-metadata.xml", md, 0640, "root:supivpn-controller")
	client := vmHTTPS(t)
	vmCommand(t, "systemctl", "restart", "supivpn-controller")
	vmWait(t, "controller readiness", 30*time.Second, func() bool { return vmReady(client, 8443) })
	vmCommand(t, "systemctl", "start", "supivpn-node")
	vmWait(t, "node readiness and real OpenVPN", 45*time.Second, func() bool { return vmReady(client, 9443) })
	t.Log("controller and node are ready under installed systemd units")
	vmCheckSandbox(t)
	if !t.Run("signed-SAML-and-tunnel", func(t *testing.T) { vmTunnel(t, client, signer) }) {
		t.FailNow()
	}
	for _, crashed := range []string{"supivpn-openvpn", "supivpn-node"} {
		node, vpn := vmPID(t, "supivpn-node"), vmPID(t, "supivpn-openvpn")
		vmCommand(t, "systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", crashed)
		vmWait(t, "pair recovery after "+crashed, 60*time.Second, func() bool {
			newNode, newVPN := vmPID(t, "supivpn-node"), vmPID(t, "supivpn-openvpn")
			return newNode != "0" && newVPN != "0" && newNode != node && newVPN != vpn && vmReady(client, 9443)
		})
		t.Log("pair recovered after", crashed)
	}
	vmCommand(t, "systemctl", "stop", "supivpn-node")
	time.Sleep(7 * time.Second)
	if vmPID(t, "supivpn-node") != "0" || vmPID(t, "supivpn-openvpn") != "0" || vmReady(client, 9443) {
		t.Fatal("manual pair stop did not remain stopped")
	}
	vmCommand(t, "systemctl", "start", "supivpn-node")
	vmWait(t, "manual start", 45*time.Second, func() bool { return vmReady(client, 9443) })
	vmCommand(t, "systemctl", "enable", "supivpn-controller", "supivpn-node")
	t.Log("manual stop/start passed; services enabled for the separate cold-boot check")
}

func vmLogin(t *testing.T, client *http.Client, signer *saml.ServiceProvider, path string, status int) []byte {
	t.Helper()
	resp, err := client.Get("https://localhost:8443" + path)
	if err != nil {
		t.Fatal("test browser login failed")
	}
	resp.Body.Close()
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || location.Host != "idp.example.test" || resp.StatusCode != http.StatusFound || len(resp.Cookies()) != 1 {
		t.Fatal("login did not initiate SAML with the configured test IdP")
	}
	compressed, err := base64.StdEncoding.DecodeString(location.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal("invalid SAML redirect encoding")
	}
	inflater := flate.NewReader(bytes.NewReader(compressed))
	data, err := io.ReadAll(io.LimitReader(inflater, 65536))
	inflater.Close()
	if err != nil {
		t.Fatal("cannot decode test AuthnRequest")
	}
	var request saml.AuthnRequest
	if err := xml.Unmarshal(data, &request); err != nil || request.ID == "" {
		t.Fatal("invalid AuthnRequest")
	}
	origin, _ := url.Parse("https://localhost:8443")
	fixture := &testApplication{agent: &agent{config: config{SAMLGroupsAttribute: "groups"}},
		sp: &saml.ServiceProvider{EntityID: origin.String() + "/saml/metadata", AcsURL: *origin.JoinPath("saml/acs")}}
	assertion := groupAssertionFor(fixture, "admins-vpn")
	assertion.ID = "assertion-" + request.ID
	assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = request.ID
	pending := controller.Pending{Ticket: location.Query().Get("RelayState"), RequestID: request.ID}
	body := profileSAMLBody(t, fixture, signer, pending, assertion, true)
	post, _ := http.NewRequest("POST", origin.String()+"/saml/acs", strings.NewReader(body))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(resp.Cookies()[0])
	callback, err := client.Do(post)
	if err != nil {
		t.Fatal("signed SAML callback failed")
	}
	defer callback.Body.Close()
	if callback.StatusCode != status {
		t.Fatalf("SAML callback returned %d, want %d", callback.StatusCode, status)
	}
	data, err = io.ReadAll(io.LimitReader(callback.Body, 1<<20))
	if err != nil {
		t.Fatal("cannot read authorized response")
	}
	return data
}

func vmTunnel(t *testing.T, client *http.Client, signer *saml.ServiceProvider) {
	t.Helper()
	dir := t.TempDir()
	data := vmLogin(t, client, signer, "/profile", http.StatusOK)
	if !bytes.Contains(data, []byte("<tls-crypt-v2>")) {
		t.Fatal("signed login did not issue a client profile")
	}
	data = bytes.ReplaceAll(data, []byte("remote localhost 1194"), []byte("remote 192.0.2.1 1194"))
	profilePath, authPath := filepath.Join(dir, "client.ovpn"), filepath.Join(dir, "auth")
	vmWrite(t, profilePath, data, 0600, "")
	vmWrite(t, authPath, []byte("unused-test\nunused-test\n"), 0600, "")
	vmCommand(t, "ip", "netns", "add", "supivpn-vm-client")
	t.Cleanup(func() { vmCommand(t, "ip", "netns", "delete", "supivpn-vm-client") })
	vmCommand(t, "ip", "link", "add", "supi-vm-host", "type", "veth", "peer", "name", "supi-vm-peer")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "delete", "supi-vm-host").Run() })
	vmCommand(t, "ip", "link", "set", "supi-vm-peer", "netns", "supivpn-vm-client")
	vmCommand(t, "ip", "addr", "add", "192.0.2.1/30", "dev", "supi-vm-host")
	vmCommand(t, "ip", "link", "set", "supi-vm-host", "up")
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", "192.0.2.2/30", "dev", "supi-vm-peer"}, {"link", "set", "supi-vm-peer", "up"}} {
		vmCommand(t, "ip", append([]string{"-n", "supivpn-vm-client"}, args...)...)
	}
	clientLog := startProtocolProcess(t, "ip", "netns", "exec", "supivpn-vm-client", "/usr/sbin/openvpn", "--config", profilePath,
		"--auth-user-pass", authPath, "--dev", "supivpnc0", "--dev-type", "tun", "--disable-dco", "--setenv", "IV_SSO", "webauth", "--verb", "3")
	var loginPath string
	pattern := regexp.MustCompile(`https://localhost:8443/login/[A-Za-z0-9_-]+`)
	vmWait(t, "real OpenVPN WEB_AUTH challenge", 30*time.Second, func() bool {
		clientLog.mu.Lock()
		defer clientLog.mu.Unlock()
		match := pattern.FindString(clientLog.b.String())
		loginPath = strings.TrimPrefix(match, "https://localhost:8443")
		return match != ""
	})
	if clientLog.contains("Initialization Sequence Completed") {
		t.Fatal("VPN connected before verified SAML")
	}
	vmLogin(t, client, signer, loginPath, http.StatusAccepted)
	vmWait(t, "authorized VPN connection", 30*time.Second, func() bool { return clientLog.contains("Initialization Sequence Completed") })
	if !clientLog.contains("ifconfig 10.203.0.2 255.255.255.0") {
		t.Fatal("signed group did not receive its expected address pool")
	}
	vmCommand(t, "ip", "netns", "exec", "supivpn-vm-client", "ping", "-c", "2", "-W", "3", "10.203.0.1")
	listener, err := net.Listen("tcp", "10.203.0.1:18080")
	if err != nil {
		t.Fatal("cannot listen on the actual VPN interface")
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "supivpn-vm-tunnel-ok") }), ReadHeaderTimeout: 3 * time.Second}
	t.Cleanup(func() { server.Close() })
	go func() { _ = server.Serve(listener) }()
	if vmCommand(t, "ip", "netns", "exec", "supivpn-vm-client", "curl", "--fail", "--silent", "--max-time", "10", "--interface", "supivpnc0", "http://10.203.0.1:18080") != "supivpn-vm-tunnel-ok" {
		t.Fatal("TCP payload did not traverse the real tunnel")
	}
	t.Log("signed SAML profile download and VPN login passed; ICMP and TCP crossed the tunnel")
}

func vmDatabase(t *testing.T) {
	t.Helper()
	vmCommand(t, "install", "-d", "-m", "0700", "-o", "postgres", "-g", "postgres", "/etc/supivpn-test-db")
	for _, name := range []string{"crt.pem", "key.pem"} {
		b, err := os.ReadFile("/etc/supivpn/node/" + name)
		if err != nil {
			t.Fatal("missing generated database TLS fixture")
		}
		vmWrite(t, "/etc/supivpn-test-db/"+name, b, 0600, "postgres:postgres")
	}
	vmWrite(t, "/etc/postgresql/18/main/conf.d/supivpn-test.conf", []byte("listen_addresses = '127.0.0.1'\nssl = on\nssl_cert_file = '/etc/supivpn-test-db/crt.pem'\nssl_key_file = '/etc/supivpn-test-db/key.pem'\n"), 0644, "")
	vmWrite(t, "/etc/postgresql/18/main/pg_hba.conf", []byte("local all postgres peer\nhostssl supivpn_test all 127.0.0.1/32 scram-sha-256\n"), 0640, "postgres:postgres")
	vmCommand(t, "systemctl", "restart", "postgresql@18-main")
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		t.Fatal("cannot generate disposable database password")
	}
	runtimePass := hex.EncodeToString(password)
	if _, err := rand.Read(password); err != nil {
		t.Fatal("cannot generate disposable migration password")
	}
	migrationPass := hex.EncodeToString(password)
	sql := fmt.Sprintf(`CREATE ROLE supivpn_owner NOLOGIN NOINHERIT;
CREATE ROLE supivpn_runtime LOGIN NOINHERIT PASSWORD '%s';
CREATE ROLE supivpn_test_migrator LOGIN NOINHERIT PASSWORD '%s';
GRANT supivpn_owner TO supivpn_test_migrator;
CREATE DATABASE supivpn_test;
REVOKE ALL ON DATABASE supivpn_test FROM PUBLIC;
GRANT CONNECT, CREATE ON DATABASE supivpn_test TO supivpn_owner;
GRANT CONNECT ON DATABASE supivpn_test TO supivpn_runtime, supivpn_test_migrator;
\connect supivpn_test
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO supivpn_owner;
CREATE SCHEMA supivpn AUTHORIZATION supivpn_owner;
GRANT USAGE ON SCHEMA supivpn TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA supivpn GRANT USAGE, SELECT ON SEQUENCES TO supivpn_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE supivpn_owner IN SCHEMA public GRANT SELECT ON TABLES TO supivpn_runtime;
`, runtimePass, migrationPass)
	cmd := exec.Command("runuser", "-u", "postgres", "--", "psql", "-X", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	if err := cmd.Run(); err != nil {
		t.Fatal("disposable database bootstrap failed; output withheld")
	}
	dsn := "postgres://supivpn_test_migrator:" + migrationPass + "@127.0.0.1/supivpn_test?sslmode=verify-full&sslrootcert=/etc/supivpn/node/ca.pem&host=localhost"
	cmd = exec.Command("/usr/sbin/supivpn-migrate")
	cmd.Env = append(os.Environ(), "SUPIVPN_DATABASE_URL="+dsn)
	if err := cmd.Run(); err != nil {
		t.Fatal("installed migration CLI failed; output withheld")
	}
	vmWrite(t, "/etc/supivpn/controller/database.env", []byte("SUPIVPN_DATABASE_URL=postgres://supivpn_runtime:"+runtimePass+"@127.0.0.1/supivpn_test\n"), 0600, "")
}

func vmCheckSandbox(t *testing.T) {
	t.Helper()
	for unit, expected := range map[string]string{"supivpn-node": "0000000000000002", "supivpn-openvpn": "0000000000001002", "supivpn-controller": "0000000000000000"} {
		pid := vmPID(t, unit)
		status, err := os.ReadFile("/proc/" + pid + "/status")
		if err != nil || !strings.Contains(string(status), "CapBnd:\t"+expected) || !strings.Contains(string(status), "NoNewPrivs:\t1") {
			t.Fatal("unexpected running-service capability/no-new-privileges state", unit)
		}
	}
	u, err := user.Lookup("supivpn-controller")
	if err != nil || u.Uid == "0" || u.HomeDir != "/nonexistent" {
		t.Fatal("controller account is not isolated")
	}
	pid := vmPID(t, "supivpn-node")
	if _, err := os.Stat("/proc/" + pid + "/root/dev/net/tun"); !os.IsNotExist(err) {
		t.Fatal("agent's private devices expose TUN")
	}
	t.Log("kernel confirms capability bounds, no-new-privileges and agent TUN isolation")
}

func TestDebianVMAfterReboot(t *testing.T) {
	requireDebianVM(t)
	client := vmHTTPS(t)
	vmWait(t, "controller after boot", time.Minute, func() bool { return vmReady(client, 8443) })
	vmWait(t, "node after boot", time.Minute, func() bool { return vmReady(client, 9443) })
	vmCheckSandbox(t)
}

func TestDebianVMPackageLifecycle(t *testing.T) {
	requireDebianVM(t)
	client := vmHTTPS(t)
	if !vmReady(client, 8443) || !vmReady(client, 9443) {
		t.Fatal("running-service lifecycle requires ready services")
	}
	identities := func() map[string]string {
		out := make(map[string]string)
		for _, unit := range []string{"supivpn-node", "supivpn-openvpn", "supivpn-controller"} {
			out[unit] = vmCommand(t, "systemctl", "show", "--property=MainPID,InvocationID", unit)
		}
		return out
	}
	type preserved struct {
		digest [32]byte
		mode   os.FileMode
	}
	snapshot := func() map[string]preserved {
		out := make(map[string]preserved)
		for _, root := range []string{"/etc/supivpn", "/var/lib/supivpn-node"} {
			err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.Mode().IsRegular() {
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					out[path] = preserved{sha256.Sum256(data), info.Mode()}
				}
				return nil
			})
			if err != nil {
				t.Fatal("cannot inspect disposable operator state")
			}
		}
		return out
	}
	beforePID, beforeFiles := identities(), snapshot()
	debs, err := filepath.Glob("/opt/supivpn-test/supivpn*.deb")
	if err != nil || len(debs) != 3 {
		t.Fatal("expected three test packages")
	}
	vmCommand(t, "dpkg", append([]string{"-i"}, debs...)...)
	vmCommand(t, "dpkg-reconfigure", "-f", "noninteractive", "supivpn-controller")
	dir := t.TempDir()
	var upgrades []string
	for i, deb := range debs {
		version := vmCommand(t, "dpkg-deb", "-f", deb, "Version")
		unpacked := filepath.Join(dir, strconv.Itoa(i))
		vmCommand(t, "dpkg-deb", "-R", deb, unpacked)
		path := filepath.Join(unpacked, "DEBIAN/control")
		control, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("cannot read test package metadata")
		}
		vmWrite(t, path, bytes.ReplaceAll(control, []byte(version), []byte(version+"+vmtest1")), 0644, "")
		target := filepath.Join(dir, strconv.Itoa(i)+".deb")
		vmCommand(t, "dpkg-deb", "--build", "--root-owner-group", unpacked, target)
		upgrades = append(upgrades, target)
	}
	vmCommand(t, "dpkg", append([]string{"-i"}, upgrades...)...)
	if !reflect.DeepEqual(beforePID, identities()) || !reflect.DeepEqual(beforeFiles, snapshot()) {
		t.Fatal("reinstall/reconfigure/upgrade restarted a service or changed operator files")
	}
	for _, unit := range []string{"supivpn-node", "supivpn-controller"} {
		if vmCommand(t, "systemctl", "is-enabled", unit) != "enabled" {
			t.Fatal("upgrade lost service enablement")
		}
	}
	if !vmReady(client, 8443) || !vmReady(client, 9443) {
		t.Fatal("upgrade lost readiness")
	}
	vmCommand(t, "dpkg", "-r", "supivpn")
	if !reflect.DeepEqual(beforePID, identities()) {
		t.Fatal("metapackage removal changed running services")
	}
	vmCommand(t, "dpkg", "-r", "supivpn-node")
	if vmPID(t, "supivpn-node") != "0" || vmPID(t, "supivpn-openvpn") != "0" || !vmReady(client, 8443) {
		t.Fatal("node removal did not stop only its dedicated pair")
	}
	vmCommand(t, "dpkg", "--purge", "supivpn-node", "supivpn-controller", "supivpn")
	if !reflect.DeepEqual(beforeFiles, snapshot()) {
		t.Fatal("purge removed or changed operator files")
	}
	if _, err := user.Lookup("supivpn-controller"); err != nil {
		t.Fatal("purge removed the retained controller account")
	}
	if vmReady(client, 8443) || vmReady(client, 9443) {
		t.Fatal("purged service is still serving")
	}
	for _, executable := range []string{"/usr/sbin/supivpn", "/usr/sbin/supivpn-controller"} {
		if _, err := os.Stat(executable); !os.IsNotExist(err) {
			t.Fatal("purge retained a package executable")
		}
	}
	t.Log("live reinstall/reconfigure/upgrade preserved process identities; remove/purge stopped only owned services and retained operator files")
}
