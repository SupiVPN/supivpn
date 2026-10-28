// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"strconv"
	"strings"
)

const clientStatusHeader = "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher"
const routeStatusHeader = "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)"

// Only a complete, bounded status-3 response is evidence of CID absence. The
// daemon lists all non-halted instances, including unauthenticated handshakes.
// Retain numeric CIDs only; names, addresses and other status data are discarded.
type managementStatus struct {
	stage, lines int
	clients      map[uint64]struct{}
}

func (s *managementStatus) line(line string) (bool, error) {
	s.lines++
	bad := errors.New("invalid management status response")
	if s.lines > 256 {
		return false, bad
	}
	f := strings.Split(line, "\t")
	switch s.stage {
	case 0:
		if len(f) != 2 || f[0] != "TITLE" || !strings.HasPrefix(f[1], "OpenVPN ") {
			return false, bad
		}
		s.stage = 1
	case 1:
		if len(f) != 3 || f[0] != "TIME" {
			return false, bad
		}
		if _, err := strconv.ParseUint(f[2], 10, 64); err != nil {
			return false, bad
		}
		s.stage = 2
	case 2:
		if line != clientStatusHeader {
			return false, bad
		}
		s.clients = make(map[uint64]struct{})
		s.stage = 3
	case 3:
		if line == routeStatusHeader {
			s.stage = 4
			return false, nil
		}
		if len(f) != 13 || f[0] != "CLIENT_LIST" || len(s.clients) >= 64 {
			return false, bad
		}
		cid, err := strconv.ParseUint(f[10], 10, 64)
		if err != nil {
			return false, bad
		}
		for _, field := range []int{5, 6, 8, 11} {
			if _, err := strconv.ParseUint(f[field], 10, 64); err != nil {
				return false, bad
			}
		}
		if _, duplicate := s.clients[cid]; duplicate {
			return false, bad
		}
		s.clients[cid] = struct{}{}
	case 4, 5:
		if line == "END" && s.stage == 5 {
			return true, nil
		}
		if s.stage == 4 && len(f) == 6 && f[0] == "ROUTING_TABLE" {
			if _, err := strconv.ParseUint(f[5], 10, 64); err != nil {
				return false, bad
			}
			return false, nil
		}
		if len(f) != 3 || f[0] != "GLOBAL_STATS" {
			return false, bad
		}
		if _, err := strconv.ParseUint(f[2], 10, 64); err != nil {
			return false, bad
		}
		s.stage = 5
	default:
		return false, bad
	}
	return false, nil
}

func (m *management) requestStatus() error {
	if len(m.children) != 0 {
		for _, child := range m.children {
			if err := child.requestStatus(); err != nil {
				m.close()
				return err
			}
		}
		return nil
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	m.statusRequested.Store(true)
	defer m.statusRequested.Store(false)
	if err := m.exchangeLocked("status 3"); err != nil {
		m.close()
		return err
	}
	return nil
}
