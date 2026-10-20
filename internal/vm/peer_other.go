// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package vm

import (
	"errors"
	"net"
	"os"
)

func ownedByCurrentUser(os.FileInfo) bool { return false }
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("unsupported Unix peer credentials")
}
