// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"errors"
	"regexp"
	"strings"

	"supivpn/internal/saml"
)

// Okta custom claims use Unspecified. An omitted NameFormat has the same
// meaning in SAML; the exact Attribute Name is still required.
const groupAttributeFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"

type Group struct {
	GroupName string
	Priority  int
	MaxConnectionsPerUser int
	SessionSeconds *int
}

type Policy struct {
	MaxConnectionsPerUser int
	AllowedSubjects     []string
	SAMLGroupsAttribute string
	Groups              []Group
}

var (
	groupNamePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	attributeNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:/-]{0,255}$`)
	ErrNoGroup           = errors.New("no permitted VPN group")
	errGroupsClaim       = errors.New("missing or invalid SAML groups attribute")
)

// ValidatePolicy is independent of a node's network and IP pools.
func ValidatePolicy(p Policy) error {
	if p.MaxConnectionsPerUser < 0 || p.MaxConnectionsPerUser > 16 {
		return errors.New("max_connections_per_user must be 1..16, or omitted for 1")
	}
	for _, g := range p.Groups {
		if g.SessionSeconds != nil && !ValidSessionSeconds(*g.SessionSeconds) {
			return errors.New("group session_seconds must be 0 (unlimited) or 60..43200; omitted inherits")
		}
		if g.MaxConnectionsPerUser < 0 || g.MaxConnectionsPerUser > 16 {
			return errors.New("group max_connections_per_user must be 1..16, or omitted to inherit")
		}
	}
	if p.SAMLGroupsAttribute == "" {
		if len(p.AllowedSubjects) == 0 || len(p.Groups) != 0 {
			return errors.New("allowlist mode requires allowed_subjects and no groups")
		}
		for _, subject := range p.AllowedSubjects {
			if subject == "" || strings.Contains(subject, "REPLACE_") || strings.TrimSpace(subject) != subject {
				return errors.New("replace allowed_subjects with exact test NameID values")
			}
		}
		return nil
	}
	if !attributeNamePattern.MatchString(p.SAMLGroupsAttribute) {
		return errors.New("invalid saml_groups_attribute name")
	}
	if len(p.AllowedSubjects) != 0 || len(p.Groups) == 0 || len(p.Groups) > 100 {
		return errors.New("group mode requires 1..100 groups and an empty allowed_subjects list")
	}
	names, priorities := map[string]bool{}, map[int]bool{}
	for _, group := range p.Groups {
		if !groupNamePattern.MatchString(group.GroupName) || names[group.GroupName] || group.Priority < 0 || priorities[group.Priority] {
			return errors.New("use unique VPN group names and unique non-negative priorities")
		}
		names[group.GroupName], priorities[group.Priority] = true, true
	}
	return nil
}

// Zero means omitted/inherit; it never disables the limit.
func (p Policy) ConnectionLimit(group string) int {
	limit := p.MaxConnectionsPerUser
	if limit == 0 {
		limit = 1
	}
	for _, g := range p.Groups {
		if g.GroupName == group && g.MaxConnectionsPerUser != 0 {
			return g.MaxConnectionsPerUser
		}
	}
	return limit
}

// SessionLimit uses the selected group's override, or the global duration.
// The signed IdP deadline is applied separately, after selecting this policy.
func (c Config) SessionLimit(group string) int {
	for _, g := range c.Groups {
		if g.GroupName == group && g.SessionSeconds != nil {
			return *g.SessionSeconds
		}
	}
	return c.SessionSeconds
}

// Call only with the assertion returned by ServiceProvider.ParseXMLResponse after
// signature and session validation. Each AttributeValue is one exact group name;
// FriendlyName, CSV strings and attributes outside this assertion are not used.
func assertionGroups(assertion *saml.Assertion, attributeName string) (map[string]bool, error) {
	if assertion == nil || attributeName == "" {
		return nil, errGroupsClaim
	}
	memberships := make(map[string]bool)
	found := false
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			if attribute.Name != attributeName {
				continue
			}
			if found || (attribute.NameFormat != "" && attribute.NameFormat != groupAttributeFormat) || len(attribute.Values) == 0 || len(attribute.Values) > 1024 {
				return nil, errGroupsClaim
			}
			found = true
			for _, value := range attribute.Values {
				if value.NameID != nil || !groupNamePattern.MatchString(value.Value) {
					return nil, errGroupsClaim
				}
				memberships[value.Value] = true
			}
		}
	}
	if !found {
		return nil, errGroupsClaim
	}
	return memberships, nil
}

// The assertion lists positive memberships. Other groups grant no VPN access;
// an absent configured group is not a membership, regardless of priority.
func selectGroup(groups []Group, memberships map[string]bool) (Group, error) {
	var selected Group
	found := false
	for _, group := range groups {
		if memberships[group.GroupName] && (!found || group.Priority < selected.Priority) {
			selected, found = group, true
		}
	}
	if !found {
		return Group{}, ErrNoGroup
	}
	return selected, nil
}

// Zero explicitly disables the local deadline; signed IdP bounds remain.
func ValidSessionSeconds(n int) bool { return n == 0 || n >= 60 && n <= 43200 }

func (c Config) HasUnlimitedSessions() bool {
	if len(c.Groups) == 0 { return c.SessionSeconds == 0 }
	for _, g := range c.Groups {
		if c.SessionLimit(g.GroupName) == 0 { return true }
	}
	return false
}
