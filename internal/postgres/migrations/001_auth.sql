CREATE SCHEMA IF NOT EXISTS supivpn;
REVOKE ALL ON SCHEMA supivpn FROM PUBLIC;

CREATE TABLE supivpn.nodes (
    node_id text PRIMARY KEY CHECK (length(node_id) BETWEEN 1 AND 128),
    generation text NOT NULL CHECK (length(generation) BETWEEN 1 AND 128)
);

-- Keep retired generation names so a rotation cannot resurrect old requests.
CREATE TABLE supivpn.node_generations (
    node_id text NOT NULL REFERENCES supivpn.nodes(node_id),
    generation text NOT NULL,
    PRIMARY KEY (node_id, generation)
);

CREATE TABLE supivpn.logins (
    ticket_hash bytea PRIMARY KEY CHECK (octet_length(ticket_hash) = 32),
    purpose text NOT NULL DEFAULT 'vpn_connect' CHECK (purpose = 'vpn_connect'),
    node_id text NOT NULL REFERENCES supivpn.nodes(node_id),
    generation text NOT NULL,
    cid bigint NOT NULL CHECK (cid >= 0),
    kid bigint NOT NULL CHECK (kid >= 0),
    revision bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    expires_at timestamptz NOT NULL,
    request_id text UNIQUE CHECK (length(request_id) BETWEEN 1 AND 256),
    browser_hash bytea CHECK (octet_length(browser_hash) = 32),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'started', 'decided', 'acknowledged', 'cancelled')),
    decision_id text UNIQUE,
    group_name text NOT NULL DEFAULT '',
    denial_reason text NOT NULL DEFAULT '',
    not_before timestamptz,
    not_after timestamptz,
    session_expires_at timestamptz,
    ack_result text CHECK (ack_result IN ('applied', 'denied', 'failed')),
    UNIQUE (node_id, generation, cid, kid),
    CHECK ((request_id IS NULL) = (browser_hash IS NULL)),
    CHECK (state NOT IN ('started', 'decided', 'acknowledged') OR request_id IS NOT NULL),
    CHECK (state NOT IN ('decided', 'acknowledged') OR
        (decision_id IS NOT NULL AND not_before IS NOT NULL AND not_after IS NOT NULL
         AND session_expires_at IS NOT NULL AND not_before < not_after)),
    CHECK ((state = 'acknowledged') = (ack_result IS NOT NULL))
);
CREATE INDEX logins_expiry ON supivpn.logins (expires_at);

-- Separate replay retention: an assertion can outlive the short pending login.
-- No raw assertion, subject, cookie or bearer ticket is stored.
CREATE TABLE supivpn.assertions (
    assertion_hash bytea PRIMARY KEY CHECK (octet_length(assertion_hash) = 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX assertions_expiry ON supivpn.assertions (expires_at);
