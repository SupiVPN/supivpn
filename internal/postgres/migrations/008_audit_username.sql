-- Copyright (c) 2026 SupiVPN. All rights reserved.
-- See LICENSE for copyright ownership and licensing terms.
-- SPDX-License-Identifier: LicenseRef-SupiVPN-Commercial

-- Audit metadata only; authorization and session limits still use subject_hash.
ALTER TABLE supivpn.logins
    ADD COLUMN username text NOT NULL DEFAULT ''
    CHECK (octet_length(username) <= 1024);
