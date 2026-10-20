// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// TLSConfig is shared by controller and migration configuration. A nil config
// preserves explicit DSN settings; an empty config selects encryption only.
type TLSConfig struct {
	Mode       string `json:"mode,omitempty"`
	CAFile     string `json:"ca_file,omitempty"`
	ServerName string `json:"server_name,omitempty"`
}

func (c *TLSConfig) mode() string {
	if c.Mode == "" {
		return "require"
	}
	return c.Mode
}

// Validate checks configuration without opening files or contacting a server.
func (c *TLSConfig) Validate() error {
	if c == nil {
		return nil
	}
	switch c.mode() {
	case "require":
		if c.CAFile != "" || c.ServerName != "" {
			return errors.New("database TLS ca_file and server_name require verify-full")
		}
	case "verify-full":
		if c.CAFile != "" && (!filepath.IsAbs(c.CAFile) || strings.ContainsAny(c.CAFile, "\x00\r\n")) {
			return errors.New("database TLS ca_file must be an absolute PEM file path")
		}
		if c.ServerName != "" && !validTLSServerName(c.ServerName) {
			return errors.New("database TLS server_name must be an exact DNS name or IP address")
		}
	default:
		return errors.New("database TLS mode must be require or verify-full")
	}
	return nil
}

func validTLSServerName(name string) bool {
	if net.ParseIP(name) != nil {
		return true
	}
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

// connectionString supplies authoritative TLS settings to pgx's existing parser.
// Explicit empty sslrootcert prevents PGSSLROOTCERT from changing require into
// verify-ca. No application-specific keys are sent as PostgreSQL session settings.
func (c *TLSConfig) connectionString(dsn string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if c == nil {
		return dsn, nil
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", errors.New("invalid database configuration")
		}
		// PostgreSQL URLs use percent decoding, not form decoding: '+' is
		// literal, and spaces must remain %20 when passed back to pgx.
		q, err := url.ParseQuery(strings.ReplaceAll(u.RawQuery, "+", "%2B"))
		if err != nil {
			return "", errors.New("invalid database configuration")
		}
		q.Set("sslmode", c.mode())
		q.Set("sslrootcert", c.CAFile)
		u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
		return u.String(), nil
	}
	// libpq keyword values escape backslashes and single quotes, in that order.
	ca := strings.ReplaceAll(strings.ReplaceAll(c.CAFile, `\`, `\\`), `'`, `\'`)
	return dsn + " sslmode=" + c.mode() + " sslrootcert='" + ca + "'", nil
}
