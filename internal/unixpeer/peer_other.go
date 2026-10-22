// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux && !darwin

package unixpeer

import (
	"errors"
	"net"
	"os"
)

func OwnedBy(os.FileInfo, uint32) bool { return false }
func UID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("unsupported Unix peer credentials")
}
