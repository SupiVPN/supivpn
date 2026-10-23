// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"time"

	"supivpn/internal/controller"

	"supivpn/internal/saml"
)

// Wiring only: authorization policy has no node CIDRs or management socket.
func controllerPolicy(c config) controller.Policy {
	p := controller.Policy{AllowedSubjects: c.AllowedSubjects, SAMLGroupsAttribute: c.SAMLGroupsAttribute, MaxConnectionsPerUser: c.MaxConnectionsPerUser}
	for _, group := range c.GroupPools {
		p.Groups = append(p.Groups, controller.Group{GroupName: group.GroupName, Priority: group.Priority, MaxConnectionsPerUser: group.MaxConnectionsPerUser, SessionSeconds: group.SessionSeconds})
	}
	return p
}

func newController(a *agent, sp *saml.ServiceProvider) (*controller.Controller, error) {
	return controller.New(controller.Config{Policy: controllerPolicy(a.config),
		PendingSeconds: a.config.PendingSeconds, SessionSeconds: a.config.SessionSeconds, VPNLoginConfirmation: a.config.VPNLoginConfirmation},
		a.origin, sp, a, func() time.Time { return a.now() })
}
