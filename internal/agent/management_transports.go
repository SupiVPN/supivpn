// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"strconv"
	"strings"
	"sync"
)

// Reserve bit 62 for TCP. UDP IDs remain unchanged and every composite ID fits
// PostgreSQL's signed bigint. Daemon IDs outside this range fail closed.
const transportCIDBit uint64 = 1 << 62

// One agent, journal, generation, lease and allocator own both daemons. If one
// management connection fails, close both: rotating the shared generation while
// another daemon still carries tunnels would lose trustworthy slot accounting.
func newTransportManagement(udp, tcp *management) *management {
	m := &management{children: []*management{udp, tcp}, events: make(chan clientEvent, 128), done: make(chan struct{})}
	var wg sync.WaitGroup
	for index, child := range m.children {
		wg.Add(1)
		go func(index int, child *management) {
			defer wg.Done()
			defer m.close()
			for {
				select {
				case e, ok := <-child.events:
					if !ok {
						return
					}
					e.scoped, e.transport = true, index
					if e.kind == "STATUS" {
						clients := make(map[uint64]struct{}, len(e.clients))
						for cid := range e.clients {
							if cid >= transportCIDBit {
								return
							}
							clients[cid+uint64(index)*transportCIDBit] = struct{}{}
						}
						e.clients = clients
					} else {
						if e.cid >= transportCIDBit || e.kid >= transportCIDBit {
							return
						}
						e.cid += uint64(index) * transportCIDBit
					}
					// Preserve each daemon's event/snapshot order. A slow consumer
					// must not drop evidence of an active or disconnected client.
					select {
					case m.events <- e:
					case <-m.done:
						return
					}
				case <-child.done:
					return
				case <-m.done:
					return
				}
			}
		}(index, child)
	}
	go func() { wg.Wait(); close(m.events) }()
	return m
}

func (m *management) transportClient(cid uint64) (*management, uint64, error) {
	index := cid / transportCIDBit
	if index >= uint64(len(m.children)) {
		return nil, 0, errors.New("invalid transport client ID")
	}
	select {
	case <-m.done:
		return nil, 0, errors.New("management unavailable")
	default:
	}
	return m.children[index], cid % transportCIDBit, nil
}

func (m *management) transportCommand(cmd string) error {
	// Only fixed process-wide commands may be broadcast. In particular never
	// broadcast a client command whose CID may also exist in the other daemon.
	switch cmd {
	case "pid", "state on", "hold release":
		for _, child := range m.children {
			if err := child.command(cmd); err != nil {
				m.close()
				return err
			}
		}
		return nil
	}
	parts := strings.SplitN(cmd, " ", 3)
	if len(parts) < 2 {
		return errors.New("unsupported transport command")
	}
	switch parts[0] {
	case "client-auth-nt", "client-deny", "client-kill", "client-pending-auth":
	default:
		return errors.New("unsupported transport command")
	}
	cid, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return errors.New("invalid transport client ID")
	}
	child, local, err := m.transportClient(cid)
	if err != nil {
		return err
	}
	parts[1] = strconv.FormatUint(local, 10)
	return child.command(strings.Join(parts, " "))
}

func (m *management) tunnelsInitialized() bool {
	if len(m.children) == 0 {
		return m.initialized.Load()
	}
	for _, child := range m.children {
		if !child.initialized.Load() {
			return false
		}
	}
	return true
}
