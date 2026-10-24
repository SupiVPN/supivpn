-- Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
-- Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE supivpn.issued_profiles (
    profile_id text PRIMARY KEY CHECK (profile_id ~ '^svp1_[0-9a-f]{32}$'),
    secret_hash bytea NOT NULL CHECK (octet_length(secret_hash)=32),
    subject_hash bytea NOT NULL CHECK (octet_length(subject_hash)=32),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','blocked')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX issued_profiles_subject ON supivpn.issued_profiles(subject_hash);
CREATE TABLE supivpn.profile_bindings (
    ticket_hash bytea PRIMARY KEY REFERENCES supivpn.logins(ticket_hash) ON DELETE CASCADE,
    profile_id text NOT NULL REFERENCES supivpn.issued_profiles(profile_id)
);
REVOKE ALL ON supivpn.issued_profiles,supivpn.profile_bindings FROM PUBLIC;

-- Agents can verify a proof without reading the registry or its digests.
-- The row lock serializes the check with an operator blocking the profile.
CREATE FUNCTION supivpn.profile_proof_valid(p_id text,p_digest bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE p supivpn.issued_profiles;
BEGIN
    SELECT * INTO p FROM supivpn.issued_profiles WHERE profile_id=p_id FOR SHARE;
    RETURN FOUND AND p.state='active' AND p.secret_hash=p_digest;
END
$$;
CREATE FUNCTION supivpn.profile_is_active(p_id text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE active boolean;
BEGIN
    SELECT state='active' INTO active FROM supivpn.issued_profiles WHERE profile_id=p_id FOR SHARE;
    RETURN COALESCE(active,false);
END
$$;
REVOKE ALL ON FUNCTION supivpn.profile_proof_valid(text,bytea),supivpn.profile_is_active(text) FROM PUBLIC;

CREATE FUNCTION supivpn.profile_owner_active(p_id text,p_subject bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE active boolean;
BEGIN
    SELECT state='active' AND subject_hash=p_subject INTO active
    FROM supivpn.issued_profiles WHERE profile_id=p_id FOR SHARE;
    RETURN COALESCE(active,false);
END
$$;
REVOKE ALL ON FUNCTION supivpn.profile_owner_active(text,bytea) FROM PUBLIC;

-- Short-lived, single-use handoff from the authenticated browser to Connect.
-- Neither a profile nor an unwrapped credential is persisted here.
CREATE TABLE supivpn.profile_imports (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash)=32),
    subject_hash bytea NOT NULL CHECK (octet_length(subject_hash)=32),
    expires_at timestamptz NOT NULL
);
REVOKE ALL ON supivpn.profile_imports FROM PUBLIC;
