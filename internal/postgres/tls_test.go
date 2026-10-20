// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	file string
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate test CA")
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, c, c, pub, key)
	if err != nil {
		t.Fatal("create test CA")
	}
	c, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse test CA")
	}
	// Exercise keyword-DSN quoting as well as URL encoding of CA file paths.
	file := filepath.Join(t.TempDir(), "test CA's + bundle.pem")
	if os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600) != nil {
		t.Fatal("write test CA")
	}
	return testCA{c, key, file}
}

func (ca testCA) leaf(t *testing.T, name string, expired bool) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate test server key")
	}
	notAfter := time.Now().Add(time.Hour)
	if expired {
		notAfter = time.Now().Add(-time.Minute)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal("create test server certificate")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestDatabaseTLSConfiguration(t *testing.T) {
	ca := newTestCA(t)
	for _, dsn := range []string{
		"postgres://test@alias.example.test/supivpn_test?sslmode=require",
		"host=alias.example.test user=test dbname=supivpn_test sslmode=require",
	} {
		for _, mode := range []string{"", "require", "verify-full"} {
			options := &TLSConfig{Mode: mode}
			if mode == "verify-full" {
				options.CAFile = ca.file
				options.ServerName = "writer.example.test"
			}
			c, err := poolConfigWithTLS(dsn, options)
			if err != nil {
				t.Fatalf("valid TLS settings rejected mode=%q: %v", mode, err)
			}
			if c.ConnConfig.Host != "alias.example.test" || len(c.ConnConfig.Fallbacks) != 0 || c.ConnConfig.TLSConfig.MinVersion != tls.VersionTLS12 {
				t.Fatal("address, downgrade protection or minimum TLS changed")
			}
			verified := mode == "verify-full"
			if c.ConnConfig.TLSConfig.InsecureSkipVerify == verified {
				t.Fatal("wrong certificate verification mode")
			}
			if verified && (c.ConnConfig.TLSConfig.ServerName != options.ServerName || c.ConnConfig.TLSConfig.RootCAs == nil) {
				t.Fatal("explicit trust/name not applied")
			}
			for _, key := range []string{"server_name", "ca_file", "mode", "sslrootcert", "sslmode"} {
				if _, exists := c.ConnConfig.RuntimeParams[key]; exists {
					t.Fatal("TLS setting leaked into PostgreSQL startup parameters")
				}
			}
		}
		c, err := poolConfigWithTLS(dsn, &TLSConfig{Mode: "verify-full"})
		if err != nil || c.ConnConfig.TLSConfig.ServerName != "alias.example.test" || c.ConnConfig.TLSConfig.RootCAs != nil {
			t.Fatal("default verified identity/system trust incorrect")
		}
	}
	// Existing DSN-only callers must retain their stronger policy when no JSON
	// block is supplied. Explicit JSON settings take precedence over DSN/env TLS.
	c, err := poolConfigWithTLS("host=writer.example.test sslmode=verify-full", nil)
	if err != nil || c.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("omitted configuration weakened existing verification")
	}
	c, err = poolConfigWithTLS("postgres://test@alias.example.test/supivpn_test?password=test+only%20value&search_path=a%2Bb%20c", &TLSConfig{Mode: "verify-full"})
	if err != nil || c.ConnConfig.Password != "test+only value" || c.ConnConfig.RuntimeParams["search_path"] != "a+b c" {
		t.Fatal("TLS configuration changed unrelated URL parameters")
	}
	t.Setenv("PGSSLMODE", "disable")
	t.Setenv("PGSSLROOTCERT", "/missing-test-root.pem")
	c, err = poolConfigWithTLS("host=writer.example.test", &TLSConfig{})
	if err != nil || !c.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("environment changed explicit require policy")
	}
	c, err = poolConfigWithTLS("host=writer.example.test sslmode=disable", &TLSConfig{Mode: "verify-full", CAFile: ca.file})
	if err != nil || c.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("DSN/environment weakened explicit verify-full")
	}
	for _, options := range []*TLSConfig{
		{Mode: "disable"}, {Mode: "prefer"}, {Mode: "verify-ca"}, {Mode: "VERIFY-FULL"},
		{ServerName: "writer.example.test"}, {CAFile: ca.file},
		{Mode: "verify-full", CAFile: "relative.pem"},
		{Mode: "verify-full", ServerName: "*.example.test"},
		{Mode: "verify-full", ServerName: "writer.example.test:5432"},
		{Mode: "verify-full", ServerName: "writer.example.test\n"},
	} {
		if _, err := poolConfigWithTLS("host=alias.example.test sslmode=require", options); err == nil {
			t.Fatal("invalid TLS option accepted")
		}
	}
	for _, file := range []string{filepath.Join(t.TempDir(), "missing.pem"), filepath.Join(t.TempDir(), "invalid.pem")} {
		if strings.HasSuffix(file, "invalid.pem") && os.WriteFile(file, []byte("not a certificate"), 0600) != nil {
			t.Fatal("write invalid fixture")
		}
		if _, err := poolConfigWithTLS("host=alias.example.test", &TLSConfig{Mode: "verify-full", CAFile: file}); err == nil {
			t.Fatal("unavailable/invalid CA did not fail closed")
		}
	}
	if _, err := poolConfigWithTLS("host=one.example.test,two.example.test", &TLSConfig{Mode: "verify-full", ServerName: "writer.example.test"}); err == nil {
		t.Fatal("multiple endpoint fallback accepted")
	}
}

// A disposable loopback PostgreSQL protocol stub exercises pgx's real TLS path,
// startup, writer probe and Ping. It never forwards traffic to another database.
func tlsTestDatabase(t *testing.T, certificate *atomic.Pointer[tls.Certificate], plaintext bool) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen for disposable TLS test")
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				backend := pgproto3.NewBackend(conn, conn)
				message, err := backend.ReceiveStartupMessage()
				if err != nil {
					return
				}
				if _, ok := message.(*pgproto3.SSLRequest); !ok {
					return
				}
				if plaintext {
					_, _ = conn.Write([]byte("N"))
					return
				}
				if _, err = conn.Write([]byte("S")); err != nil {
					return
				}
				secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate.Load(), nil }})
				if secure.Handshake() != nil {
					return
				}
				backend = pgproto3.NewBackend(secure, secure)
				message, err = backend.ReceiveStartupMessage()
				if err != nil {
					return
				}
				if _, ok := message.(*pgproto3.StartupMessage); !ok {
					return
				}
				backend.Send(&pgproto3.AuthenticationOk{})
				backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "18.0"})
				backend.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
				backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if backend.Flush() != nil {
					return
				}
				for {
					message, err = backend.Receive()
					if err != nil {
						return
					}
					query, ok := message.(*pgproto3.Query)
					if !ok {
						return
					}
					if strings.EqualFold(query.String, "show transaction_read_only") {
						backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("transaction_read_only"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}}})
						backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("off")}})
						backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SHOW")})
					} else {
						backend.Send(&pgproto3.EmptyQueryResponse{})
					}
					backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
					if backend.Flush() != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; wg.Wait() })
	return "postgres://test@" + listener.Addr().String() + "/supivpn_test?sslmode=require&default_query_exec_mode=simple_protocol"
}

func TestDatabaseTLSHandshakeAndReconnect(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	valid := ca.leaf(t, "writer.example.test", false)
	wrongName := ca.leaf(t, "other.example.test", false)
	wrongCA := other.leaf(t, "writer.example.test", false)
	expired := ca.leaf(t, "writer.example.test", true)
	for _, tc := range []struct {
		name          string
		certificate   tls.Certificate
		options       *TLSConfig
		plaintext, ok bool
	}{
		{"verified-alias", valid, &TLSConfig{Mode: "verify-full", CAFile: ca.file, ServerName: "writer.example.test"}, false, true},
		{"missing-name-override", valid, &TLSConfig{Mode: "verify-full", CAFile: ca.file}, false, false},
		{"wrong-name", wrongName, &TLSConfig{Mode: "verify-full", CAFile: ca.file, ServerName: "writer.example.test"}, false, false},
		{"wrong-ca", wrongCA, &TLSConfig{Mode: "verify-full", CAFile: ca.file, ServerName: "writer.example.test"}, false, false},
		{"expired", expired, &TLSConfig{Mode: "verify-full", CAFile: ca.file, ServerName: "writer.example.test"}, false, false},
		{"require-default", wrongCA, &TLSConfig{}, false, true},
		{"require-no-plaintext", valid, &TLSConfig{}, true, false},
		{"verified-no-plaintext", valid, &TLSConfig{Mode: "verify-full", CAFile: ca.file, ServerName: "writer.example.test"}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var certificate atomic.Pointer[tls.Certificate]
			certificate.Store(&tc.certificate)
			dsn := tlsTestDatabase(t, &certificate, tc.plaintext)
			var credentials atomic.Int32
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			pool, err := OpenWithTLS(ctx, dsn, func(context.Context) (string, error) { credentials.Add(1); return "ephemeral-test-only", nil }, tc.options)
			if err != nil {
				t.Fatal("create test pool: ", err)
			}
			defer pool.Close()
			pingErr := pool.Ping(ctx)
			if (pingErr == nil) != tc.ok {
				t.Fatalf("TLS handshake acceptance differs from policy: %v", pingErr)
			}
			if !tc.ok {
				var hostname x509.HostnameError
				var authority x509.UnknownAuthorityError
				var invalid x509.CertificateInvalidError
				switch tc.name {
				case "missing-name-override", "wrong-name":
					if !errors.As(pingErr, &hostname) {
						t.Fatal("connection failed for a reason other than hostname verification")
					}
				case "wrong-ca":
					if !errors.As(pingErr, &authority) {
						t.Fatal("connection failed for a reason other than CA verification")
					}
				case "expired":
					if !errors.As(pingErr, &invalid) || invalid.Reason != x509.Expired {
						t.Fatal("connection failed for a reason other than certificate expiry")
					}
				}
				return
			}
			renewed := ca.leaf(t, "writer.example.test", false)
			certificate.Store(&renewed)
			pool.Reset()
			if pool.Ping(ctx) != nil || credentials.Load() < 2 {
				t.Fatal("verified renewal/reconnect or credential refresh failed")
			}
			if tc.options.mode() == "verify-full" {
				certificate.Store(&wrongCA)
				pool.Reset()
				if pool.Ping(ctx) == nil {
					t.Fatal("reconnect lost certificate verification")
				}
			}
		})
	}
}

func TestDatabaseTLSAliasResolvesOnEveryConnection(t *testing.T) {
	ca := newTestCA(t)
	var certificate atomic.Pointer[tls.Certificate]
	valid := ca.leaf(t, "writer.example.test", false)
	certificate.Store(&valid)
	dsn := strings.Replace(tlsTestDatabase(t, &certificate, false), "127.0.0.1", "alias.example.test", 1)
	c, err := poolConfigWithTLS(dsn, &TLSConfig{Mode: "verify-full", CAFile: ca.file, ServerName: "writer.example.test"})
	if err != nil {
		t.Fatal("configure alias")
	}
	var lookups atomic.Int32
	c.ConnConfig.LookupFunc = func(ctx context.Context, host string) ([]string, error) {
		if host != "alias.example.test" {
			t.Error("TLS identity replaced the DNS alias")
		}
		lookups.Add(1)
		return []string{"127.0.0.1"}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		t.Fatal("create alias pool")
	}
	defer pool.Close()
	if pool.Ping(ctx) != nil {
		t.Fatal("alias connection failed")
	}
	first := lookups.Load()
	pool.Reset()
	if pool.Ping(ctx) != nil || first == 0 || lookups.Load() <= first {
		t.Fatal("alias not resolved again on reconnect")
	}
}
