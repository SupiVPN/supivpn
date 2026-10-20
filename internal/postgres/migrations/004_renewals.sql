-- Copyright (c) 2026 SupiVPN. All rights reserved.
-- See LICENSE for copyright ownership and licensing terms.
-- SPDX-License-Identifier: LicenseRef-SupiVPN-Commercial


ALTER TABLE supivpn.logins
    ADD COLUMN renewal_of bytea REFERENCES supivpn.logins(ticket_hash) ON DELETE CASCADE;
ALTER TABLE supivpn.logins DROP CONSTRAINT logins_node_id_generation_cid_kid_key;
CREATE UNIQUE INDEX logins_connection ON supivpn.logins(node_id, generation, cid, kid)
    WHERE renewal_of IS NULL;
CREATE UNIQUE INDEX logins_pending_renewal ON supivpn.logins(renewal_of)
    WHERE renewal_of IS NOT NULL AND state IN ('pending', 'started', 'decided');
