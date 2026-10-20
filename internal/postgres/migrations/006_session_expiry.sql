-- Copyright (c) 2026 SupiVPN. All rights reserved.
-- See LICENSE for copyright ownership and licensing terms.
-- SPDX-License-Identifier: LicenseRef-SupiVPN-Commercial

-- Deployment must stop the previous agents before this protocol upgrade.
DELETE FROM supivpn.logins WHERE renewal_of IS NOT NULL;
DROP INDEX supivpn.logins_pending_renewal;
DROP INDEX supivpn.logins_connection;
ALTER TABLE supivpn.logins DROP COLUMN renewal_of;
CREATE UNIQUE INDEX logins_connection ON supivpn.logins(node_id,generation,cid,kid);

ALTER TABLE supivpn.logins ADD COLUMN session_unlimited boolean NOT NULL DEFAULT false;
ALTER TABLE supivpn.logins DROP CONSTRAINT logins_check2;
ALTER TABLE supivpn.logins ADD CONSTRAINT logins_decision_bounds CHECK (
    state NOT IN ('decided','acknowledged') OR
    (decision_id IS NOT NULL AND not_before IS NOT NULL AND not_after IS NOT NULL
     AND not_before < not_after
     AND ((session_unlimited AND session_expires_at IS NULL)
       OR (NOT session_unlimited AND session_expires_at IS NOT NULL)))
);
ALTER TABLE supivpn.logins ADD CONSTRAINT logins_unlimited_bounds
    CHECK (NOT session_unlimited OR session_expires_at IS NULL);
