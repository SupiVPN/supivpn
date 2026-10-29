// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"supivpn/internal/controller"
	"supivpn/internal/logging"
	"supivpn/internal/metrics"
	"supivpn/internal/profile"
	"supivpn/internal/saml"
	"supivpn/internal/servicenotify"
)

type config struct {
	Metrics               *metrics.Config        `json:"metrics,omitempty"`
	TCPManagementSocket   string                 `json:"tcp_management_socket,omitempty"`
	ProfileBinding        string                 `json:"profile_binding,omitempty"`
	VPNLoginConfirmation  *bool                  `json:"vpn_login_confirmation,omitempty"`
	AssertionEncryption   *saml.EncryptionConfig `json:"assertion_encryption,omitempty"`
	Logging               *logging.Config        `json:"logging,omitempty"`
	MaxConnectionsPerUser int                    `json:"max_connections_per_user,omitempty"`
	PublicURL             string                 `json:"public_url"`
	Listen                string                 `json:"listen"`
	TLSCertificate        string                 `json:"tls_certificate"`
	TLSChain              string                 `json:"tls_chain"`
	TLSPrivateKey         string                 `json:"tls_private_key"`
	IDPMetadata           string                 `json:"idp_metadata"`
	ManagementSocket      string                 `json:"management_socket"`
	AllowedSubjects       []string               `json:"allowed_subjects"`
	PendingSeconds        int                    `json:"pending_seconds"`
	SessionSeconds        int                    `json:"session_seconds"`
	SAMLGroupsAttribute   string                 `json:"saml_groups_attribute,omitempty"`
	VPNNetwork            string                 `json:"vpn_network,omitempty"`
	GroupPools            []groupPool            `json:"group_pools,omitempty"`
	RemoteController      *remoteConfig          `json:"remote_controller,omitempty"`
}

func readConfig(path string) (config, *url.URL, error) {
	c := config{SessionSeconds: 43200}
	f, err := os.Open(path)
	if err != nil {
		return c, nil, errors.New("cannot open configuration")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 64<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, nil, errors.New("invalid configuration JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, nil, errors.New("configuration must contain one JSON object")
	}
	if err := c.Logging.Validate("agent"); err != nil {
		return c, nil, err
	}
	if err := c.Metrics.Validate(false); err != nil {
		return c, nil, err
	}
	if err := c.AssertionEncryption.Validate(); err != nil {
		return c, nil, err
	}
	if c.RemoteController != nil && c.AssertionEncryption != nil {
		return c, nil, errors.New("assertion encryption belongs to the remote controller")
	}
	if c.RemoteController != nil && c.VPNLoginConfirmation != nil {
		return c, nil, errors.New("VPN login confirmation belongs to the remote controller")
	}
	if c.AssertionEncryption != nil && c.AssertionEncryption.PrivateKeyFile != "" && c.AssertionEncryption.PrivateKeyFile == c.TLSPrivateKey {
		return c, nil, errors.New("use a dedicated SAML encryption key separate from TLS")
	}
	u, err := url.Parse(c.PublicURL)
	if c.ProfileBinding != "" && c.ProfileBinding != "required" && c.ProfileBinding != "legacy" || c.RemoteController == nil {
		return c, nil, errors.New("profile_binding requires required or explicit legacy migration mode and a remote controller")
	}
	if c.ProfileBinding == "" {
		c.ProfileBinding = "required"
	}
	if c.ProfileBinding == "legacy" && c.TCPManagementSocket != "" {
		return c, nil, errors.New("legacy migration supports only the separate UDP listener; TCP requires bound profiles")
	}
	if c.TCPManagementSocket != "" && (!filepath.IsAbs(c.TCPManagementSocket) || filepath.Clean(c.TCPManagementSocket) != c.TCPManagementSocket || c.TCPManagementSocket == c.ManagementSocket || filepath.Dir(c.TCPManagementSocket) != filepath.Dir(c.ManagementSocket) || c.SAMLGroupsAttribute == "") {
		return c, nil, errors.New("TCP management requires groups and a distinct canonical socket in the primary management directory")
	}
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" ||
		strings.ContainsAny(c.PublicURL, " \t\r\n\\\"") || len(c.PublicURL) > 300 {
		return c, nil, errors.New("public_url must be an HTTPS origin without a trailing slash")
	}
	for _, path := range []string{c.TLSCertificate, c.TLSChain, c.TLSPrivateKey, c.IDPMetadata, c.ManagementSocket} {
		if !filepath.IsAbs(path) {
			return c, nil, errors.New("certificate, metadata and socket paths must be absolute")
		}
	}
	if c.Listen == "" || c.PendingSeconds < 30 || c.PendingSeconds > 180 ||
		!controller.ValidSessionSeconds(c.SessionSeconds) {
		return c, nil, errors.New("require listen, pending_seconds 30..180 and session_seconds 0 (unlimited) or 60..43200")
	}
	for _, subject := range c.AllowedSubjects {
		if subject == "" || strings.Contains(subject, "REPLACE_") || strings.TrimSpace(subject) != subject {
			return c, nil, errors.New("replace allowed_subjects with exact test NameID values")
		}
	}
	if err := validateAuthorization(c); err != nil {
		return c, nil, err
	}
	if c.RemoteController != nil {
		if err := c.RemoteController.validate(c); err != nil {
			return c, nil, err
		}
	}
	return c, u, nil
}

type runtimeStageError struct {
	stage string
	err   error
}

func (e *runtimeStageError) Error() string { return e.err.Error() }
func (e *runtimeStageError) Unwrap() error { return e.err }

func run(ctx context.Context, path string) (runErr error) {
	stage := "startup_config"
	defer func() {
		if runErr != nil {
			runErr = &runtimeStageError{stage: stage, err: runErr}
		}
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c, origin, err := readConfig(path)
	if err != nil {
		return err
	}
	closeLogs, err := logging.Setup("agent", c.Logging)
	if err != nil {
		return err
	}
	defer closeLogs()
	if c.ProfileBinding == "legacy" {
		logging.Emit(ctx, "profile.legacy_enabled", slog.String("node_id", c.RemoteController.NodeID))
	}
	stage = "startup_tls"
	keyPair, err := tls.LoadX509KeyPair(c.TLSCertificate, c.TLSPrivateKey)
	if err != nil {
		return errors.New("cannot load server TLS certificate and key")
	}
	chain, err := os.ReadFile(c.TLSChain)
	if err != nil {
		return errors.New("cannot read server certificate chain")
	}
	for len(strings.TrimSpace(string(chain))) > 0 {
		block, rest := pem.Decode(chain)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("invalid server certificate chain")
		}
		keyPair.Certificate = append(keyPair.Certificate, block.Bytes)
		chain = rest
	}
	var sp *saml.ServiceProvider
	stage = "startup_idp"
	metadataBytes, err := os.ReadFile(c.IDPMetadata)
	if err != nil || len(metadataBytes) > 1<<20 {
		return errors.New("cannot read IdP metadata (maximum 1 MiB)")
	}
	metadata, err := saml.ParseMetadata(metadataBytes)
	if err != nil || metadata.EntityID == "" || len(metadata.IDPSSODescriptors) == 0 {
		return errors.New("invalid IdP metadata")
	}
	if c.RemoteController == nil {
		sp = &saml.ServiceProvider{
			EntityID:          origin.String() + "/saml/metadata",
			MetadataURL:       *origin.ResolveReference(&url.URL{Path: "/saml/metadata"}),
			AcsURL:            *origin.ResolveReference(&url.URL{Path: "/saml/acs"}),
			IDPMetadata:       metadata,
			AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
			AllowIDPInitiated: false,
		}
		// The SP sends unsigned AuthnRequests and requires signed responses/assertions.
		sp.AssertionEncryption, err = c.AssertionEncryption.Load()
		if err != nil {
			return err
		}
		idpURL, err := url.Parse(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding))
		if err != nil || idpURL.Scheme != "https" || idpURL.Host == "" {
			return errors.New("IdP metadata must offer HTTPS HTTP-Redirect SSO")
		}
	}

	// An existing socket is an error: never unlink another process's socket.
	stage = "startup_management_socket"
	dir := filepath.Dir(c.ManagementSocket)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("management socket directory must exist with mode 0700")
	}
	paths := []string{c.ManagementSocket}
	if c.TCPManagementSocket != "" {
		paths = append(paths, c.TCPManagementSocket)
	}
	var sockets []*net.UnixListener
	closeSockets := func() {
		for _, socket := range sockets {
			socket.Close()
		}
	}
	defer closeSockets()
	for _, path := range paths {
		socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return errors.New("cannot listen on management socket; check for an existing process")
		}
		sockets = append(sockets, socket)
		if err := os.Chmod(path, 0600); err != nil {
			return errors.New("cannot restrict management socket")
		}
	}
	a := newAgent(c, origin)
	stage = "startup_operator"
	operator, operatorStopped, err := a.listenOperator(metadata.EntityID)
	if err != nil {
		return err
	}
	defer operator.Close()
	if c.SAMLGroupsAttribute != "" {
		a.pools = newPoolAllocator(c)
	}
	stopMetrics, err := metrics.Listen(ctx, c.Metrics, a.metricsHandler())
	if err != nil {
		return err
	}
	defer stopMetrics()
	var handler http.Handler
	if c.RemoteController == nil {
		control, err := newController(a, sp)
		if err != nil {
			return err
		}
		handler = control.Handler()
	} else {
		handler = a.remoteHealth()
	}
	stage = "startup_https"
	listener, err := tls.Listen("tcp", c.Listen, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{keyPair},
	})
	if err != nil {
		return errors.New("cannot listen for HTTPS")
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// Do not emit raw HTTP/TLS errors, URLs, assertions or cookies.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	defer server.Close()
	httpStopped := make(chan struct{})
	go func() {
		server.Serve(listener)
		close(httpStopped)
		closeSockets()
	}()
	go func() {
		select {
		case <-ctx.Done():
			closeSockets()
		case <-httpStopped:
			closeSockets()
		}
	}()
	a.logEvent("agent.https_ready", nil)
	// systemd starts the paired OpenVPN unit only after these listeners exist.
	// Bound the wait in managed mode so a failed OpenVPN launch cannot leave an
	// apparently active agent waiting forever. Standalone behavior is unchanged.
	if os.Getenv("NOTIFY_SOCKET") != "" {
		for _, socket := range sockets {
			if err := socket.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				return err
			}
		}
	}
	if _, err := servicenotify.Ready(); err != nil {
		return err
	}
	var managers []*management
	stage = "startup_management_peer"
	for _, socket := range sockets {
		conn, err := socket.Accept()
		if err != nil {
			return errors.New("stopped before every OpenVPN transport connected")
		}
		child := newManagement(conn)
		defer child.close()
		managers = append(managers, child)
	}
	m := managers[0]
	if len(managers) == 2 {
		m = newTransportManagement(managers[0], managers[1])
	}
	defer m.close()
	if err := m.negotiate(); err != nil {
		return fmt.Errorf("OpenVPN management version 5 negotiation failed: %w", err)
	}
	if c.RemoteController != nil {
		stage = "startup_controller"
		cleanup, err := a.startRemote(ctx)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	a.attach(m)
	go a.events(ctx, m)
	if a.remote != nil {
		workerCtx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); a.remoteEvents(workerCtx, m) }()
		defer func() { stop(); <-done }()
	}
	stage = "management_unavailable"
	if err := m.command("state on"); err != nil {
		return fmt.Errorf("cannot enable OpenVPN readiness notifications: %w", err)
	}
	if err := m.command("hold release"); err != nil {
		return fmt.Errorf("cannot release OpenVPN startup hold: %w", err)
	}
	a.logEvent("agent.management_ready", nil)
	select {
	case <-ctx.Done():
		return nil
	case <-m.done:
		return errors.New("OpenVPN management disconnected; restart the SupiVPN pair")
	case <-httpStopped:
		stage = "listener_unavailable"
		return errors.New("HTTPS listener stopped")
	case <-operatorStopped:
		stage = "listener_unavailable"
		return errors.New("local operator listener stopped")
	}
}

// Main runs the agent command. It is called by cmd/supivpn.
func Main() {
	logging.Configure("agent")
	path := flag.String("config", "/etc/supivpn/config.json", "configuration file")
	learn := flag.Bool("learn-address", false, "validate an OpenVPN learned source address")
	routeDevice := flag.String("route-device", "", "TUN interface for shared UDP/TCP pool routes")
	routeNetwork := flag.String("route-network", "", "private VPN CIDR for shared pool routes")
	routeDisconnect := flag.Bool("route-disconnect", false, "remove this client's shared pool route on OpenVPN disconnect")
	check := flag.Bool("check-config", false, "validate configuration without starting services")
	operator := flag.Bool("operator-request", false, "send a local user-session request from stdin")
	metadataMode := flag.String("verify-profile-metadata", "", "OpenVPN tls-crypt-v2-verify mode: required or legacy (migration until v0.10.0)")
	metadataAge := flag.Duration("profile-max-age", 0, "maximum profile age; zero disables age expiry")
	flag.Parse()
	if *routeDisconnect || (*learn && (*routeDevice != "" || *routeNetwork != "")) {
		args := flag.Args()
		if *routeDisconnect {
			if *learn || len(args) != 0 {
				os.Exit(1)
			}
			args = []string{"disconnect", os.Getenv("ifconfig_pool_remote_ip")}
		}
		if err := updateClientRoute(args, os.Getenv("ifconfig_pool_remote_ip"), *routeDevice, *routeNetwork, runRouteCommand); err != nil {
			logging.Emit(context.Background(), "network.route_refused")
			os.Exit(1)
		}
		return
	}
	if *routeDevice != "" || *routeNetwork != "" {
		os.Exit(1)
	}
	if *metadataMode != "" {
		f, err := os.Open(os.Getenv("metadata_file"))
		if err != nil {
			os.Exit(1)
		}
		b, err := io.ReadAll(io.LimitReader(f, 256))
		f.Close()
		if err != nil || !profile.VerifyClientMetadata(*metadataMode, os.Getenv("metadata_type"), b, time.Now(), *metadataAge) {
			os.Exit(1)
		}
		return
	}
	if *operator {
		c, _, err := readConfig(*path)
		if err == nil {
			err = requestUserSessions(context.Background(), operatorSocket(c.ManagementSocket), os.Stdin, os.Stdout)
		}
		if err != nil {
			logging.Emit(context.Background(), "operator.request_failed")
			os.Exit(1)
		}
		return
	}
	if *learn {
		if !allowLearnedAddress(flag.Args(), os.Getenv("ifconfig_pool_remote_ip")) {
			os.Exit(1)
		}
		return
	}
	if *check {
		if _, _, err := readConfig(*path); err != nil {
			logging.Emit(context.Background(), "configuration.refused")
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *path); err != nil {
		reason := "startup_failed"
		var staged *runtimeStageError
		if errors.As(err, &staged) {
			reason = staged.stage
		}
		logging.Emit(ctx, "component.stopped", slog.String("reason", reason))
		os.Exit(1)
	}
}
