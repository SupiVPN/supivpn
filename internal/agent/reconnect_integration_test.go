// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build integration

package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"supivpn/internal/controller"
	"supivpn/internal/postgres"
)

// A loopback-only PostgreSQL TLS endpoint with an in-memory, untrusted certificate.
// The backend is exclusively the disposable supivpn_test validated by
// integrationDatabase. Closing sockets simulates a network outage without shell
// commands, external services, certificate files, or changing the real RDS.
type postgresFaultEndpoint struct {
	listener  net.Listener
	target    string
	tlsConfig *tls.Config
	mu        sync.Mutex
	online    bool
	conns     map[net.Conn]bool
	wg        sync.WaitGroup
}

func newPostgresFaultEndpoint(t *testing.T, backend *pgxpool.Pool) *postgresFaultEndpoint {
	t.Helper()
	cfg := backend.Config().ConnConfig
	if cfg.Host != "127.0.0.1" || cfg.Database != "supivpn_test" || cfg.User != "postgres" {
		t.Fatal("fault tests require local postgres/supivpn_test")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("cannot generate ephemeral TLS fixture")
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "untrusted.invalid"}, DNSNames: []string{"untrusted.invalid"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal("cannot create ephemeral TLS fixture")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot listen on test loopback")
	}
	e := &postgresFaultEndpoint{listener: listener, target: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))),
		tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}},
		online:    true, conns: make(map[net.Conn]bool)}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if !e.track(conn) {
				continue
			}
			e.wg.Add(1)
			go e.forward(conn)
		}
	}()
	t.Cleanup(func() { listener.Close(); e.setOnline(false); e.wg.Wait() })
	return e
}
func (e *postgresFaultEndpoint) dsn(mode string) string {
	return "postgres://postgres@" + e.listener.Addr().String() + "/supivpn_test?sslmode=" + mode
}
func (e *postgresFaultEndpoint) track(conn net.Conn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.online {
		conn.Close()
		return false
	}
	e.conns[conn] = true
	return true
}
func (e *postgresFaultEndpoint) forget(conn net.Conn) {
	conn.Close()
	e.mu.Lock()
	delete(e.conns, conn)
	e.mu.Unlock()
}
func (e *postgresFaultEndpoint) setOnline(online bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.online = online
	if !online {
		for conn := range e.conns {
			conn.Close()
		}
	}
}
func (e *postgresFaultEndpoint) forward(raw net.Conn) {
	defer e.wg.Done()
	defer e.forget(raw)
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	var request [8]byte
	if _, err := io.ReadFull(raw, request[:]); err != nil ||
		!bytes.Equal(request[:], []byte{0, 0, 0, 8, 4, 210, 22, 47}) {
		return
	}
	if _, err := raw.Write([]byte("S")); err != nil {
		return
	}
	secured := tls.Server(raw, e.tlsConfig)
	if err := secured.Handshake(); err != nil {
		return
	}
	raw.SetDeadline(time.Time{})
	backend, err := net.DialTimeout("tcp", e.target, 2*time.Second)
	if err != nil {
		return
	}
	if !e.track(backend) {
		return
	}
	defer e.forget(backend)
	done := make(chan struct{})
	go func() { io.Copy(backend, secured); backend.Close(); close(done) }()
	io.Copy(secured, backend)
	raw.Close()
	<-done
}

func openTestPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	p, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal("cannot create test pool")
	}
	t.Cleanup(p.Close)
	return p
}
func assertTestTLS(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal("TLS database acquire failed")
	}
	defer c.Release()
	conn, ok := c.Conn().PgConn().Conn().(*tls.Conn)
	if !ok || !conn.ConnectionState().HandshakeComplete || conn.ConnectionState().Version < tls.VersionTLS12 {
		t.Fatal("database connection is not encrypted")
	}
	if len(conn.ConnectionState().VerifiedChains) != 0 {
		t.Fatal("fixture unexpectedly trusted")
	}
}
func pendingForReconnect(t *testing.T, s *postgres.Store) (postgres.Agent, postgres.Connection, controller.Pending, controller.Authorization) {
	t.Helper()
	ctx := context.Background()
	id := rand.Text()
	actor := postgres.Agent{NodeID: "reconnect-" + id, Generation: "generation-a"}
	conn := postgres.Connection{CID: 1, KID: 1}
	ticket := rand.Text() + rand.Text()
	browser := sha256.Sum256([]byte("browser-" + id))
	if err := s.RotateNode(ctx, actor.NodeID, "", actor.Generation); err != nil {
		t.Fatal("cannot create test node")
	}
	if err := s.Register(ctx, actor, conn, ticket, 180*time.Second); err != nil {
		t.Fatal("cannot register test login")
	}
	if err := s.Start(ctx, ticket, "request-"+id, browser); err != nil {
		t.Fatal("cannot start test login")
	}
	pending, err := s.Lookup(ctx, ticket, browser)
	if err != nil {
		t.Fatal("cannot look up test login")
	}
	now := time.Now().UTC()
	d := controller.Authorization{SubjectHash: sha256.Sum256([]byte("test-user-" + id)), MaxConnections: 1, GroupName: "admins-vpn", AssertionHash: sha256.Sum256([]byte("assertion-" + id)),
		AssertionExpiresAt: now.Add(3 * time.Minute), NotBefore: now.Add(-time.Minute),
		NotOnOrAfter: now.Add(3 * time.Minute), SessionExpiresAt: now.Add(15 * time.Minute)}
	return actor, conn, pending, d
}

func TestPostgresReconnect(t *testing.T) {
	backend, admin := integrationDatabase(t)
	e := newPostgresFaultEndpoint(t, backend)
	p := openTestPool(t, e.dsn("require"))
	s := postgres.New(p)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("TLS-required-with-untrusted-certificate", func(t *testing.T) {
		assertTestTLS(t, p)
		strict := openTestPool(t, e.dsn("verify-full"))
		if strict.Ping(ctx) == nil {
			t.Fatal("untrusted/mismatched certificate accepted with verify-full")
		}
		// A real plaintext-only PostgreSQL endpoint must not silently downgrade.
		cfg := backend.Config().ConnConfig
		plain := openTestPool(t, "postgres://postgres@127.0.0.1:"+strconv.Itoa(int(cfg.Port))+"/supivpn_test?sslmode=require")
		if plain.Ping(ctx) == nil {
			t.Fatal("TLS requirement downgraded to plaintext")
		}
	})
	t.Run("idle-backend-terminated", func(t *testing.T) {
		c, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal("acquire failed")
		}
		pid := c.Conn().PgConn().PID()
		c.Release()
		var killed bool
		if err = admin.QueryRow(ctx, "SELECT pg_terminate_backend($1)", pid).Scan(&killed); err != nil || !killed {
			t.Fatal("cannot terminate local test backend")
		}
		var next uint32
		if err = p.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&next); err != nil || next == pid {
			t.Fatal("pool did not reconnect")
		}
		assertTestTLS(t, p)
	})
	t.Run("read-only-session-replaced", func(t *testing.T) {
		c, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal("acquire failed")
		}
		pid := c.Conn().PgConn().PID()
		_, err = c.Exec(ctx, "SET default_transaction_read_only=on")
		c.Release()
		if err != nil {
			t.Fatal("cannot mark test session read-only")
		}
		var next uint32
		if err = p.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&next); err != nil || next == pid {
			t.Fatal("read-only session reused")
		}
	})
	t.Run("in-flight-transaction-is-not-replayed", func(t *testing.T) {
		tx, err := p.Begin(ctx)
		if err != nil {
			t.Fatal("begin failed")
		}
		defer tx.Rollback(context.Background())
		hash := sha256.Sum256([]byte(rand.Text()))
		if _, err = tx.Exec(ctx, "INSERT INTO supivpn.assertions(assertion_hash,expires_at) VALUES ($1,clock_timestamp()+interval '1 minute')", hash[:]); err != nil {
			t.Fatal("test write failed")
		}
		var killed bool
		if err = admin.QueryRow(ctx, "SELECT pg_terminate_backend($1)", tx.Conn().PgConn().PID()).Scan(&killed); err != nil || !killed {
			t.Fatal("cannot terminate test transaction")
		}
		if tx.Commit(ctx) == nil {
			t.Fatal("interrupted transaction reported successful")
		}
		var count int
		if err = p.QueryRow(ctx, "SELECT count(*) FROM supivpn.assertions WHERE assertion_hash=$1", hash[:]).Scan(&count); err != nil || count != 0 {
			t.Fatal("interrupted write replayed")
		}
	})
	t.Run("outage-and-startup-recover-on-same-pools", func(t *testing.T) {
		actor, conn, pending, d := pendingForReconnect(t, s)
		e.setOnline(false)
		defer e.setOnline(true)
		cold := openTestPool(t, e.dsn("require"))
		short, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		if s.Ready(short) || postgres.New(cold).Ready(short) {
			t.Fatal("unavailable database reported ready")
		}
		stop()
		short, stop = context.WithTimeout(ctx, 500*time.Millisecond)
		err := s.Complete(short, pending, d)
		stop()
		if !errors.Is(err, controller.ErrUnavailable) {
			t.Fatal("outage did not fail closed")
		}
		e.setOnline(true)
		if !s.Ready(ctx) || !postgres.New(cold).Ready(ctx) {
			t.Fatal("pool required application restart")
		}
		again, err := s.Lookup(ctx, pending.Ticket, pending.BrowserHash)
		if err != nil || again != pending {
			t.Fatal("outage changed pending state or extended deadline")
		}
		if err = s.Complete(ctx, pending, d); !errors.Is(err, controller.ErrDecisionPending) {
			t.Fatal("completion after recovery failed")
		}
		result, err := s.Fetch(ctx, actor, conn)
		if err != nil {
			t.Fatal("decision unavailable after recovery")
		}
		if err = s.Acknowledge(ctx, actor, result.ID, postgres.Applied); err != nil {
			t.Fatal("ACK after recovery failed")
		}
		assertTestTLS(t, p)
	})
	t.Run("hostname-resolved-again-after-disconnect", func(t *testing.T) {
		cfg := p.Config()
		cfg.ConnConfig.Host = "writer.test.invalid"
		var lookups atomic.Int32
		cfg.ConnConfig.LookupFunc = func(context.Context, string) ([]string, error) {
			lookups.Add(1)
			return []string{"127.0.0.1"}, nil
		}
		named, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal("cannot create hostname fixture")
		}
		defer named.Close()
		if err = named.Ping(ctx); err != nil {
			t.Fatal("initial hostname connection failed")
		}
		first := lookups.Load()
		e.setOnline(false)
		e.setOnline(true)
		if err = named.Ping(ctx); err != nil || lookups.Load() <= first {
			t.Fatal("reconnect did not resolve hostname again")
		}
		assertTestTLS(t, named)
	})
}

func TestPostgresVerifiedTLSReconnect(t *testing.T) {
	backend, _ := integrationDatabase(t)
	e := newPostgresFaultEndpoint(t, backend)
	caFile := filepath.Join(t.TempDir(), "disposable-db-ca.pem")
	publicCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.tlsConfig.Certificates[0].Certificate[0]})
	if os.WriteFile(caFile, publicCert, 0600) != nil {
		t.Fatal("cannot provision disposable public CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, name := range []string{"wrong.example.test", "untrusted.invalid"} {
		pool, err := postgres.OpenWithTLS(ctx, e.dsn("require"), nil,
			&postgres.TLSConfig{Mode: "verify-full", CAFile: caFile, ServerName: name})
		if err != nil {
			t.Fatal("cannot configure verified pool")
		}
		t.Cleanup(pool.Close)
		if name != "untrusted.invalid" {
			if pool.Ping(ctx) == nil {
				t.Fatal("real PostgreSQL accepted mismatched TLS identity")
			}
			continue
		}
		var previous uint32
		for attempt := 0; attempt < 2; attempt++ {
			c, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatal("verified PostgreSQL connection unavailable")
			}
			secure, ok := c.Conn().PgConn().Conn().(*tls.Conn)
			if !ok || len(secure.ConnectionState().VerifiedChains) == 0 || secure.ConnectionState().ServerName != name {
				c.Release()
				t.Fatal("database identity was not verified")
			}
			var pid uint32
			err = c.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid)
			c.Release()
			if err != nil || pid == previous {
				t.Fatal("verified connection did not execute SQL/reconnect")
			}
			previous = pid
			e.setOnline(false)
			e.setOnline(true)
		}
	}
}

// Optional externally orchestrated restart of ONLY the disposable container.
// No Docker command is embedded in Go tests. After READY_FOR_LOCAL_DB_RESTART,
// restart the local container; its anonymous volume must survive until cleanup.
func TestPostgresServerRestart(t *testing.T) {
	if os.Getenv("SUPIVPN_TEST_RESTART") != "1" {
		t.Skip("requires explicit local container restart")
	}
	backend, _ := integrationDatabase(t)
	e := newPostgresFaultEndpoint(t, backend)
	p := openTestPool(t, e.dsn("require"))
	s := postgres.New(p)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	actor, conn, pending, d := pendingForReconnect(t, s)
	if err := s.Complete(ctx, pending, d); !errors.Is(err, controller.ErrDecisionPending) {
		t.Fatal("cannot persist decision")
	}
	before, err := s.Fetch(ctx, actor, conn)
	if err != nil {
		t.Fatal("cannot fetch decision before restart")
	}
	var started time.Time
	if err = p.QueryRow(ctx, "SELECT pg_postmaster_start_time()").Scan(&started); err != nil {
		t.Fatal("cannot read test server start time")
	}
	t.Log("READY_FOR_LOCAL_DB_RESTART")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("local PostgreSQL restart/recovery not observed")
		case <-ticker.C:
			query, stop := context.WithTimeout(ctx, time.Second)
			var current time.Time
			err = p.QueryRow(query, "SELECT pg_postmaster_start_time()").Scan(&current)
			stop()
			if err != nil || !current.After(started) {
				continue
			}
			if !s.Ready(ctx) {
				t.Fatal("restarted database not ready")
			}
			after, err := s.Fetch(ctx, actor, conn)
			if err != nil || before != after {
				t.Fatal("restart changed committed decision")
			}
			if err = s.Complete(ctx, pending, d); !errors.Is(err, controller.ErrLoginExpired) {
				t.Fatal("restart lost replay protection")
			}
			if err = s.Acknowledge(ctx, actor, after.ID, postgres.Applied); err != nil {
				t.Fatal("ACK after restart failed")
			}
			assertTestTLS(t, p)
			t.Log("database restarted; same controller/pool recovered with decision and replay protection intact")
			return
		}
	}
}
