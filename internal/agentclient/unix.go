// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"supivpn/internal/unixpeer"
)

// ValidSocketPath checks the configured path without accessing the filesystem.
func ValidSocketPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" &&
		!strings.ContainsAny(path, "\x00\r\n")
}

// NewUnix uses HTTP only over an explicitly configured local socket. It cannot
// resolve a hostname, use a proxy, sign with AWS credentials or fall back to TCP.
// Authenticate the controller before sending any request body, and recheck on
// every connection, including after a controller restart.
func NewUnix(path string, controllerUID uint32) (*Client, error) {
	if !ValidSocketPath(path) {
		return nil, errors.New("controller socket must be a canonical absolute path")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			for _, entry := range []struct {
				path string
				mode os.FileMode
			}{
				{filepath.Dir(path), os.ModeDir | 0700}, {path, os.ModeSocket | 0600},
			} {
				info, err := os.Lstat(entry.path)
				if err != nil || info.Mode().Type()|info.Mode().Perm() != entry.mode || !unixpeer.OwnedBy(info, controllerUID) {
					return nil, errors.New("controller socket requires private paths owned by the configured UID")
				}
			}
			conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
			if err != nil {
				return nil, errors.New("controller socket unavailable")
			}
			peer, ok := conn.(*net.UnixConn)
			if !ok {
				conn.Close()
				return nil, errors.New("controller socket is not Unix")
			}
			uid, err := unixpeer.UID(peer)
			if err != nil || uid != controllerUID {
				conn.Close()
				return nil, errors.New("controller peer UID rejected")
			}
			return conn, nil
		},
		ResponseHeaderTimeout: 5 * time.Second,
		MaxIdleConns:          2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second,
	}
	return newClient("http://controller", transport, nil), nil
}
