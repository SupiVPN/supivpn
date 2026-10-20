-- Copyright (c) 2026 SupiVPN. All rights reserved.
-- See LICENSE for copyright ownership and licensing terms.
-- SPDX-License-Identifier: LicenseRef-SupiVPN-Commercial

-- Separate purpose and lifecycle from node-bound VPN connection requests.
-- Profiles, wrapping keys, SAML assertions and raw cookies are never stored here.
CREATE TABLE supivpn.profile_logins (
    ticket_hash bytea PRIMARY KEY CHECK (octet_length(ticket_hash) = 32),
    request_id text UNIQUE NOT NULL CHECK (length(request_id) BETWEEN 1 AND 256),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash) = 32),
    expires_at timestamptz NOT NULL,
    consumed boolean NOT NULL DEFAULT false
);
CREATE INDEX profile_logins_expiry ON supivpn.profile_logins (expires_at);

