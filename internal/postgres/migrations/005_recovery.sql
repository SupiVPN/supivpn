-- Copyright (c) 2026 SupiVPN. All rights reserved.
-- See LICENSE for copyright ownership and licensing terms.
-- SPDX-License-Identifier: LicenseRef-SupiVPN-Commercial

ALTER TABLE supivpn.nodes ADD COLUMN healthy_since timestamptz;
CREATE TABLE supivpn.node_recovery (
    node_id text PRIMARY KEY REFERENCES supivpn.nodes(node_id) ON DELETE CASCADE,
    generation text NOT NULL,
    phase text NOT NULL CHECK (phase IN ('inspect','stop','start','verify','complete','blocked')),
    tries integer NOT NULL DEFAULT 0,
    next_at timestamptz NOT NULL DEFAULT 'epoch',
    deadline timestamptz NOT NULL,
    claim text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX one_active_recovery ON supivpn.node_recovery ((true))
    WHERE phase IN ('inspect','stop','start','verify');
CREATE TABLE supivpn.node_recovery_starts (
    node_id text NOT NULL REFERENCES supivpn.nodes(node_id) ON DELETE CASCADE,
    attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(node_id,attempted_at)
);
REVOKE ALL ON supivpn.node_recovery,supivpn.node_recovery_starts FROM PUBLIC;

