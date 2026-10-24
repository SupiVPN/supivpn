// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"strings"
	"supivpn/internal/profile"
)

// Credentials come from the daemon's exact CID/KID environment, never UV_ peer
// labels or network address/time correlation. Duplicate fields fail closed.
type proofEnvironment struct {
	proof                         profile.Credential
	userSeen, secretSeen, invalid bool
}

func (p *proofEnvironment) add(kind, env string) {
	if kind != "CONNECT" && kind != "REAUTH" {
		return
	}
	name, value, ok := strings.Cut(env, "=")
	if !ok {
		return
	}
	switch name {
	case "username":
		if p.userSeen || !profile.ValidProfileID(value) {
			p.invalid = true
		} else {
			p.proof.ID = value
		}
		p.userSeen = true
	case "password":
		if p.secretSeen || len(value) != 43 {
			p.invalid = true
		} else {
			p.proof.Secret = value
		}
		p.secretSeen = true
	}
}
func (p proofEnvironment) credential() profile.Credential {
	if p.invalid || !p.userSeen || !p.secretSeen || !p.proof.Valid() {
		return profile.Credential{}
	}
	return p.proof
}
