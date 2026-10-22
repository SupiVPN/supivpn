// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// Package vm serves the controller independently of the OpenVPN/agent process.
package vm

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"supivpn/internal/agentapi"
	"supivpn/internal/unixpeer"
)

type Config struct {
	Listen         string  `json:"listen"`
	TLSCertificate string  `json:"tls_certificate"`
	TLSChain       string  `json:"tls_chain"`
	TLSPrivateKey  string  `json:"tls_private_key"`
	AgentSocket    string  `json:"agent_socket"`
	AgentUID       *uint32 `json:"agent_uid"`
	NodeID         string  `json:"node_id"`
}

func (c Config) Validate() error {
	if c.Listen == "" || c.AgentUID == nil || !agentapi.ValidNode(c.NodeID) {
		return errors.New("invalid VM listener or agent identity")
	}
	for _, p := range []string{c.TLSCertificate, c.TLSChain, c.TLSPrivateKey, c.AgentSocket} {
		if !filepath.IsAbs(p) {
			return errors.New("VM paths must be absolute")
		}
	}
	return nil
}
func LoadTLS(c Config) (*tls.Config, error) {
	key, err := tls.LoadX509KeyPair(c.TLSCertificate, c.TLSPrivateKey)
	if err != nil {
		return nil, errors.New("cannot load controller TLS material")
	}
	f, err := os.Open(c.TLSChain)
	if err != nil {
		return nil, errors.New("cannot open TLS chain")
	}
	defer f.Close()
	chain, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(chain) > 1<<20 {
		return nil, errors.New("invalid TLS chain size")
	}
	for len(strings.TrimSpace(string(chain))) > 0 {
		block, rest := pem.Decode(chain)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid TLS chain")
		}
		key.Certificate = append(key.Certificate, block.Bytes)
		chain = rest
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{key}}, nil
}

// ListenAgent refuses to unlink any pre-existing socket. The private parent
// directory is created by provisioning, owned by the controller, mode 0700.
// The privileged agent may connect as root; peer UID is still checked explicitly.
func ListenAgent(path string, uid uint32, node string) (net.Listener, error) {
	if !filepath.IsAbs(path) || !agentapi.ValidNode(node) {
		return nil, errors.New("invalid agent socket")
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !unixpeer.OwnedBy(info, uint32(os.Geteuid())) {
		return nil, errors.New("agent socket parent requires controller ownership and mode 0700")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, errors.New("cannot bind agent socket; an existing socket is never removed")
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, errors.New("cannot restrict agent socket")
	}
	return &agentListener{UnixListener: listener, uid: uid, node: node}, nil
}

type peerConn struct {
	net.Conn
	node string
}
type agentListener struct {
	*net.UnixListener
	uid  uint32
	node string
}

func (l *agentListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := unixpeer.UID(conn)
		if err != nil || uid != l.uid {
			conn.Close()
			continue
		}
		return &peerConn{Conn: conn, node: l.node}, nil
	}
}
func AgentContext(ctx context.Context, c net.Conn) context.Context {
	if peer, ok := c.(*peerConn); ok {
		return agentapi.WithNode(ctx, peer.node)
	}
	return ctx
}
func httpServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
}
func Serve(ctx context.Context, c Config, public, agents http.Handler) error {
	if err := c.Validate(); err != nil {
		return err
	}
	secure, err := LoadTLS(c)
	if err != nil {
		return err
	}
	web, err := tls.Listen("tcp", c.Listen, secure)
	if err != nil {
		return errors.New("cannot bind controller HTTPS")
	}
	defer web.Close()
	local, err := ListenAgent(c.AgentSocket, *c.AgentUID, c.NodeID)
	if err != nil {
		return err
	}
	defer local.Close()
	return ServeListeners(ctx, web, local, public, agents)
}

// ServeListeners owns only controller listeners. Shutdown has no management
// socket, signal or lifecycle relationship with OpenVPN.
func ServeListeners(ctx context.Context, web, local net.Listener, public, agents http.Handler) error {
	webServer, agentServer := httpServer(public), httpServer(agents)
	agentServer.ConnContext = AgentContext
	stopped := make(chan error, 2)
	go func() { stopped <- webServer.Serve(web) }()
	go func() { stopped <- agentServer.Serve(local) }()
	defer webServer.Close()
	defer agentServer.Close()
	var err error
	select {
	case <-ctx.Done():
	case err = <-stopped:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	webServer.Shutdown(shutdown)
	agentServer.Shutdown(shutdown)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("controller listener stopped")
	}
	return nil
}
