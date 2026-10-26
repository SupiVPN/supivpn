-- Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
-- SPDX-License-Identifier: AGPL-3.0-only

-- Audit metadata only: proof, subject, state and revision remain unchanged.
-- Empty means unknown; never infer an owner from a client-supplied username.
ALTER TABLE supivpn.issued_profiles
    ADD COLUMN owner_username text NOT NULL DEFAULT ''
    CHECK (octet_length(owner_username) <= 1024);
ALTER TABLE supivpn.profile_imports
    ADD COLUMN owner_username text NOT NULL DEFAULT ''
    CHECK (octet_length(owner_username) <= 1024);

-- Retained verified SAML decisions can recover pre-upgrade owner labels.
-- Preserve unknown when no evidence remains or labels disagree.
WITH owners AS (
    SELECT subject_hash, min(username) AS username
    FROM supivpn.logins
    WHERE subject_hash IS NOT NULL AND username <> ''
    GROUP BY subject_hash
    HAVING count(DISTINCT username) = 1
)
UPDATE supivpn.issued_profiles p SET owner_username = o.username
FROM owners o WHERE p.subject_hash = o.subject_hash;
