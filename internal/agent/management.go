// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errManagementRejected = errors.New("OpenVPN rejected command")

type clientEvent struct {
	kind    string
	cid     uint64
	kid     uint64
	sso     string
	peer    netip.AddrPort
	clients map[uint64]struct{}
}

type management struct {
	conn      net.Conn
	events    chan clientEvent
	replies   chan bool
	done      chan struct{}
	version   chan int
	closeOnce sync.Once
	writeMu   sync.Mutex
	initialized atomic.Bool
	probeMu sync.Mutex
	healthUntil atomic.Int64
	statusRequested atomic.Bool
}

func newManagement(conn net.Conn) *management {
	m := &management{conn: conn, events: make(chan clientEvent, 64),
		replies: make(chan bool, 1), done: make(chan struct{}), version: make(chan int, 1)}
	go m.read()
	return m
}

func (m *management) close() {
	m.closeOnce.Do(func() {
		close(m.done)
		m.conn.Close()
	})
}

func (m *management) negotiate() error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case version := <-m.version:
		if version < 5 {
			return errors.New("management version below 5")
		}
	case <-m.done:
		return errors.New("management disconnected")
	case <-timer.C:
		return errors.New("management greeting timed out")
	}
	// OpenVPN 2.7.7 acknowledges client version 5. Consume that ACK before
	// sending anything else, or it could satisfy the next command instead.
	return m.command("version 5")
}

// Only one command may be outstanding; its success must be acknowledged.
// A timeout closes the channel so a late ACK cannot satisfy another command.
func (m *management) command(cmd string) error {
	if strings.ContainsAny(cmd, "\r\n") {
		return errors.New("multiline management command refused")
	}
	return m.exchange(cmd)
}

func (m *management) authorizeIPv4(cid, kid uint64, address netip.Addr, netmask string) error {
	mask, err := netip.ParseAddr(netmask)
	if !address.Is4() || err != nil || !mask.Is4() {
		return errors.New("invalid client IPv4 configuration")
	}
	// One multiline transaction, one ACK after END. All interpolated values are
	// typed server-side values; no SAML subject or client-supplied option is used.
	return m.exchange(fmt.Sprintf("client-auth %d %d\nifconfig-push %s %s\nEND", cid, kid, address, mask))
}

func (m *management) exchange(cmd string) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.exchangeLocked(cmd)
}

func (m *management) exchangeLocked(cmd string) error {
	select {
	case <-m.done:
		return errors.New("management unavailable")
	default:
	}
	if err := m.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		m.close()
		return errors.New("management write deadline failed")
	}
	if _, err := fmt.Fprintln(m.conn, cmd); err != nil {
		m.close()
		return errors.New("management write failed")
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case success := <-m.replies:
		if !success {
			return errManagementRejected
		}
		return nil
	case <-m.done:
		return errors.New("management disconnected")
	case <-timer.C:
		m.close()
		return errors.New("management command timed out")
	}
}

func parseClientHeader(line string) (clientEvent, error) {
	var e clientEvent
	parts := strings.Split(strings.TrimPrefix(line, ">CLIENT:"), ",")
	if len(parts) < 2 {
		return e, errors.New("invalid client event")
	}
	e.kind = parts[0]
	var err error
	e.cid, err = strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return e, errors.New("invalid CID")
	}
	if e.kind == "CONNECT" || e.kind == "REAUTH" {
		if len(parts) != 3 {
			return e, errors.New("missing KID")
		}
		e.kid, err = strconv.ParseUint(parts[2], 10, 64)
		if err != nil {
			return e, errors.New("invalid KID")
		}
	}
	return e, nil
}

func (m *management) read() {
	defer m.close()
	defer close(m.events)
	scanner := bufio.NewScanner(m.conn)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var pending *clientEvent
	var peer peerEnvironment
	seenHold := false
	var status managementStatus
	for scanner.Scan() {
		line := scanner.Text()
		if m.statusRequested.Load() && !strings.HasPrefix(line, ">") {
			done, err := status.line(line)
			if err != nil {
				return
			}
			if done {
				if pending != nil {
					return
				}
				// Preserve wire order relative to CONNECT/ESTABLISHED/DISCONNECT.
				// A snapshot cannot remove a connection whose event arrived later.
				select {
				case m.events <- clientEvent{kind: "STATUS", clients: status.clients}:
				default:
					return
				}
				status = managementStatus{}
				select {
				case m.replies <- true:
				default:
					return
				}
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, ">INFO:OpenVPN Management Interface Version "):
			fields := strings.Fields(strings.TrimPrefix(line, ">INFO:OpenVPN Management Interface Version "))
			if len(fields) == 0 {
				return
			}
			version, err := strconv.Atoi(fields[0])
			if err != nil {
				return
			}
			select {
			case m.version <- version:
			default:
				return
			}
		case strings.HasPrefix(line, ">STATE:"):
			fields := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
			m.initialized.Store(len(fields) >= 3 && fields[1] == "CONNECTED" && fields[2] == "SUCCESS")
		case strings.HasPrefix(line, ">HOLD:"):
			m.initialized.Store(false)
			// A new server generation must not reuse old CID authorizations.
			if seenHold {
				return
			}
			seenHold = true
		case strings.HasPrefix(line, "SUCCESS:"), strings.HasPrefix(line, "ERROR:"):
			select {
			case m.replies <- strings.HasPrefix(line, "SUCCESS:"):
			default:
				return
			}
		case line == ">CLIENT:ENV,END":
			if pending != nil {
				pending.peer = peer.endpoint()
				select {
				case m.events <- *pending:
				default:
					return
				}
			}
			pending = nil
		case strings.HasPrefix(line, ">CLIENT:ENV,"):
			if pending != nil {
				if strings.HasPrefix(line, ">CLIENT:ENV,IV_SSO=") {
					pending.sso = strings.TrimPrefix(line, ">CLIENT:ENV,IV_SSO=")
				}
				peer.add(pending.kind, strings.TrimPrefix(line, ">CLIENT:ENV,"))
			}
		case strings.HasPrefix(line, ">CLIENT:"):
			e, err := parseClientHeader(line)
			if err != nil {
				return
			}
			pending = &e
			peer = peerEnvironment{}
		}
	}
}

func supportsWebAuth(value string) bool {
	for _, item := range strings.Split(value, ",") {
		if strings.TrimSpace(item) == "webauth" {
			return true
		}
	}
	return false
}
