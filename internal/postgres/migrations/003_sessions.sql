-- Copyright (c) 2026 SupiVPN. All rights reserved.
-- See LICENSE for copyright ownership and licensing terms.
-- SPDX-License-Identifier: LicenseRef-SupiVPN-Commercial

ALTER TABLE supivpn.nodes
    ADD COLUMN lease_expires_at timestamptz NOT NULL DEFAULT 'epoch';
ALTER TABLE supivpn.nodes
    ADD COLUMN fence_state text NOT NULL DEFAULT 'ready' CHECK (fence_state IN ('ready','stopping','stopped')),
    ADD COLUMN fence_retry_at timestamptz NOT NULL DEFAULT 'epoch';
ALTER TABLE supivpn.logins
    ADD COLUMN subject_hash bytea CHECK (octet_length(subject_hash) = 32);
CREATE INDEX logins_subject_sessions ON supivpn.logins(subject_hash, session_expires_at)
    WHERE denial_reason = '' AND state IN ('decided', 'acknowledged');

-- Legacy grants must drain during this protocol upgrade. NOT VALID preserves
-- their tombstones while rejecting new writes from older controllers.
ALTER TABLE supivpn.logins ADD CONSTRAINT grant_requires_subject
    CHECK (state NOT IN ('decided', 'acknowledged') OR denial_reason <> '' OR subject_hash IS NOT NULL)
    NOT VALID;
