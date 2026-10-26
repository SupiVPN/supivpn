// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

// Package localcli implements the root-only Debian operator frontend.
// It has no network listener, SQL console, remote target or credential input.
package localcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"supivpn/internal/operatorapi"
	"supivpn/internal/postgres"
	"supivpn/internal/profile"
)

const Help = `Usage:
  supivpn-cli status [--instance NAME]
  supivpn-cli profiles list [--limit 1..100] [--after PROFILE_ID]
  supivpn-cli profiles status PROFILE_ID
  supivpn-cli profiles block PROFILE_ID --revision N --yes
  supivpn-cli profiles activate PROFILE_ID --revision N --yes
  supivpn-cli sessions status --user EXACT_SAML_NAMEID [--instance NAME]
  supivpn-cli sessions drop --user EXACT_SAML_NAMEID [--instance NAME] --yes

Run locally with sudo on a configured Debian host with node and controller.
Default listener: supivpn-node; use --instance bound for the migration listener.
Output is JSON. No passwords, profile proofs or owner hashes are returned.
Profiles include owner_username (verified SAML NameID); empty means unknown.
Block prevents new admission; it does not disconnect established tunnels.
Drop requests local termination, not a ban; poll sessions status until matched
and unidentified are zero. Repeat on every listener and node as necessary.
An error after a mutation can mean an unknown result: read status before retry.
`

var instanceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
var safeState = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,128}$`)
var errArguments = errors.New("invalid arguments; run supivpn-cli --help")

type request struct {
	kind, action, instance, username string
	operator                         postgres.OperatorRequest
}

func parse(args []string) (request, error) {
	var r request
	if len(args) == 0 || len(args) > 12 {
		return r, errArguments
	}
	r.kind = args[0]
	args = args[1:]
	switch r.kind {
	case "status":
		r.action = "status"
	case "profiles", "sessions":
		if len(args) == 0 {
			return r, errArguments
		}
		r.action, args = args[0], args[1:]
	default:
		return r, errArguments
	}
	if r.kind == "profiles" && r.action != "list" {
		if len(args) == 0 || !profile.ValidProfileID(args[0]) {
			return r, errArguments
		}
		r.operator.ProfileID, args = args[0], args[1:]
	}
	options := map[string]string{}
	for len(args) > 0 {
		key := args[0]
		args = args[1:]
		if _, ok := options[key]; ok {
			return r, errArguments
		}
		if key == "--yes" {
			options[key] = "yes"
			continue
		}
		if len(args) == 0 {
			return r, errArguments
		}
		options[key], args = args[0], args[1:]
	}
	take := func(key string) string { v := options[key]; delete(options, key); return v }
	if r.kind != "profiles" {
		r.instance = take("--instance")
		if r.instance != "" && !instanceName.MatchString(r.instance) {
			return r, errArguments
		}
	}
	yes := false
	switch r.kind {
	case "profiles":
		r.operator.Action = "profile-" + r.action
		switch r.action {
		case "list":
			r.operator.Limit = 50
			if n := take("--limit"); n != "" {
				v, e := strconv.Atoi(n)
				if e != nil || v < 1 || v > 100 {
					return r, errArguments
				}
				r.operator.Limit = v
			}
			r.operator.AfterID = take("--after")
			if r.operator.AfterID != "" && !profile.ValidProfileID(r.operator.AfterID) {
				return r, errArguments
			}
		case "status":
		case "block", "activate":
			v, e := strconv.ParseInt(take("--revision"), 10, 64)
			if e != nil || v < 1 {
				return r, errArguments
			}
			r.operator.ExpectedRevision = v
			yes = true
		default:
			return r, errArguments
		}
	case "sessions":
		if r.action != "status" && r.action != "drop" {
			return r, errArguments
		}
		r.username = take("--user")
		if len(r.username) == 0 || len(r.username) > 1024 || !utf8.ValidString(r.username) ||
			strings.TrimSpace(r.username) != r.username || strings.ContainsFunc(r.username, func(c rune) bool { return unicode.IsControl(c) || c == utf8.RuneError }) {
			return r, errArguments
		}
		yes = r.action == "drop"
	}
	if yes && take("--yes") != "yes" {
		return r, errors.New("mutation requires --yes; inspect status first")
	}
	if len(options) != 0 {
		return r, errArguments
	}
	return r, nil
}

type command struct {
	path  string
	args  []string
	input []byte
}
type runner func(context.Context, command) ([]byte, error)
type hostCheck func(string) error

func agentConfig(instance string) string {
	if instance == "" {
		return "/etc/supivpn/node/agent.json"
	}
	return "/etc/supivpn/nodes/" + instance + "/agent.json"
}
func services(instance string) []string {
	suffix := ".service"
	if instance != "" {
		suffix = "@" + instance + ".service"
	}
	return []string{"supivpn-controller.service", "supivpn-node" + suffix, "supivpn-openvpn" + suffix}
}
func operationCommand(r request) command {
	if r.kind == "status" {
		args := []string{"--system", "--no-pager", "show", "--property=Id,LoadState,ActiveState,SubState", "--"}
		return command{path: "/usr/bin/systemctl", args: append(args, services(r.instance)...)}
	}
	if r.kind == "sessions" {
		b, _ := json.Marshal(map[string]string{"operation": r.action, "username": r.username})
		return command{path: "/usr/sbin/supivpn", args: []string{"-config", agentConfig(r.instance), "-operator-request"}, input: b}
	}
	// systemd loads the existing credential internally. It never enters the CLI,
	// argv, shell, caller environment, logs or a new credential file.
	b, _ := json.Marshal(r.operator)
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	fields["source"] = operatorapi.Source
	b, _ = json.Marshal(fields)
	args := []string{"--system", "--quiet", "--wait", "--pipe", "--collect", "--no-ask-password", "--service-type=exec", "--expand-environment=no"}
	for _, p := range []string{
		"User=supivpn-controller", "Group=supivpn-controller",
		"EnvironmentFile=/etc/supivpn/controller/database.env",
		"RuntimeMaxSec=20s", "TimeoutStartSec=20s", "TimeoutStopSec=2s", "KillMode=control-group",
		"UMask=0077", "NoNewPrivileges=yes", "CapabilityBoundingSet=",
		"ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
		"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes",
		"RestrictSUIDSGID=yes", "RestrictRealtime=yes", "LockPersonality=yes",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
	} {
		args = append(args, "--property="+p)
	}
	args = append(args, "--", "/usr/sbin/supivpn-controller", "-config", "/etc/supivpn/controller/controller.json", "-operator-request")
	return command{path: "/usr/bin/systemd-run", args: args, input: b}
}

// Run uses fixed installed paths; injected operations exist only for unit tests.
func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help") {
		_, err := io.WriteString(out, Help)
		return err
	}
	if runtime.GOOS != "linux" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("requires a local Linux root session (sudo); not setuid")
	}
	return execute(ctx, args, out, checkHost, runCommand)
}
func execute(ctx context.Context, args []string, out io.Writer, check hostCheck, run runner) error {
	r, err := parse(args)
	if err != nil {
		return err
	}
	if err = check(r.instance); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	raw, err := run(ctx, operationCommand(r))
	if err != nil {
		return errors.New("local operation failed; mutation outcome may be unknown, inspect status before retry")
	}
	// Re-encode allowlisted fields rather than forwarding subprocess output.
	var result any
	switch r.kind {
	case "profiles":
		var reply operatorapi.Reply
		if json.Unmarshal(raw, &reply) != nil || !reply.OK || reply.State == nil {
			return errors.New("operator refused request; inspect status and revision")
		}
		if r.action == "list" {
			if len(reply.State.Profiles) > r.operator.Limit {
				return errors.New("invalid operator response")
			}
			result = struct {
				Profiles []postgres.ProfileState `json:"profiles"`
				Next     string                  `json:"next_cursor,omitempty"`
			}{reply.State.Profiles, reply.State.NextCursor}
		} else {
			p := reply.State.Profile
			if p == nil || p.ID != r.operator.ProfileID || p.Revision < 1 || p.State != "active" && p.State != "blocked" {
				return errors.New("invalid profile response")
			}
			result = p
		}
	case "sessions":
		var s struct {
			Version      int `json:"version"`
			Matched      int `json:"matched"`
			Closing      int `json:"closing"`
			Requested    int `json:"requested"`
			Unidentified int `json:"unidentified"`
		}
		if json.Unmarshal(raw, &s) != nil || s.Version != 1 || s.Matched < 0 || s.Closing < 0 || s.Requested < 0 || s.Unidentified < 0 {
			return errors.New("invalid local session response")
		}
		result = s
	default:
		var records []map[string]string
		allowed := map[string]bool{}
		for _, s := range services(r.instance) {
			allowed[s] = true
		}
		for _, block := range strings.Split(strings.TrimSpace(string(raw)), "\n\n") {
			record := map[string]string{}
			for _, line := range strings.Split(block, "\n") {
				k, v, ok := strings.Cut(line, "=")
				if !ok || (k != "Id" && k != "LoadState" && k != "ActiveState" && k != "SubState") || !safeState.MatchString(v) {
					return errors.New("invalid service response")
				}
				record[k] = v
			}
			if !allowed[record["Id"]] || len(record) != 4 {
				return errors.New("incomplete service response")
			}
			delete(allowed, record["Id"])
			records = append(records, record)
		}
		if len(allowed) != 0 {
			return errors.New("incomplete service response")
		}
		result = records
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("local response too large")
	}
	return b.Buffer.Write(p)
}
func runCommand(ctx context.Context, c command) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.path, c.args...)
	cmd.Dir = "/"
	// Neither caller-controlled PATH/pager nor DBUS/PG/loader overrides propagate.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	cmd.Stdin = bytes.NewReader(c.input)
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	var out boundedOutput
	cmd.Stdout = &out
	err := cmd.Run()
	return out.Bytes(), err
}

// All parent directories and files must be root-owned and not writable by
// anyone else. No arbitrary configuration paths or symlinks are accepted.
func safeFile(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return errors.New("local installation is incomplete")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 ||
			p == path && !info.Mode().IsRegular() || p != path && !info.IsDir() {
			return errors.New("unsafe ownership, permissions or symlink in local installation")
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func readConfig(path string, v any) error {
	if err := safeFile(path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot read local configuration")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(b) > 1<<20 || json.Unmarshal(b, v) != nil {
		return errors.New("invalid local configuration")
	}
	return nil
}
func checkHost(instance string) error {
	for _, p := range []string{"/usr/sbin/supivpn", "/usr/sbin/supivpn-controller", "/usr/sbin/openvpn", "/usr/bin/systemctl", "/usr/bin/systemd-run", "/etc/supivpn/controller/database.env"} {
		if err := safeFile(p); err != nil {
			return err
		}
	}
	envInfo, err := os.Stat("/etc/supivpn/controller/database.env")
	if err != nil || envInfo.Mode().Perm()&0077 != 0 {
		return errors.New("database.env must be root-only (0600)")
	}
	var controller struct {
		VM *struct {
			Socket     string `json:"agent_socket"`
			Node       string `json:"node_id"`
			Additional []struct {
				Socket string `json:"socket"`
				Node   string `json:"node_id"`
			} `json:"additional_agents"`
		} `json:"vm"`
	}
	if err := readConfig("/etc/supivpn/controller/controller.json", &controller); err != nil {
		return err
	}
	if controller.VM == nil {
		return errors.New("local combined VM controller configuration required; Lambda is unsupported")
	}
	var node struct {
		Remote *struct {
			Transport string `json:"transport"`
			Socket    string `json:"agent_socket"`
			Node      string `json:"node_id"`
		} `json:"remote_controller"`
	}
	if err := readConfig(agentConfig(instance), &node); err != nil {
		return err
	}
	if node.Remote == nil || node.Remote.Transport != "unix" || !strings.HasPrefix(node.Remote.Socket, "/run/supivpn-controller/") {
		return errors.New("local Unix-connected node and controller required")
	}
	matched := node.Remote.Socket == controller.VM.Socket && node.Remote.Node == controller.VM.Node
	for _, a := range controller.VM.Additional {
		matched = matched || node.Remote.Socket == a.Socket && node.Remote.Node == a.Node
	}
	if !matched {
		return errors.New("node is not configured on the local controller")
	}
	return nil
}

// Error messages are static; database or subprocess diagnostics stay private.
func Main() {
	if err := Run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "supivpn-cli:", err)
		os.Exit(1)
	}
}
