-- Copyright (c) 2026 SupiVPN. All rights reserved.
-- See LICENSE for copyright ownership and licensing terms.
-- SPDX-License-Identifier: LicenseRef-SupiVPN-Commercial

ALTER TABLE supivpn.node_recovery
    ADD COLUMN operation_id text NOT NULL DEFAULT '',
    ADD COLUMN revision bigint NOT NULL DEFAULT 1,
    ADD COLUMN stop_reserved boolean NOT NULL DEFAULT false,
    ADD COLUMN inflight_until timestamptz NOT NULL DEFAULT 'epoch',
    ADD COLUMN reason text NOT NULL DEFAULT '';
UPDATE supivpn.node_recovery
    SET operation_id='legacy-' || md5(node_id || generation),
        stop_reserved=phase NOT IN ('inspect','complete') OR tries>0,
        inflight_until=clock_timestamp()+interval '60 seconds';
ALTER TABLE supivpn.node_recovery ALTER COLUMN operation_id DROP DEFAULT;
ALTER TABLE supivpn.node_recovery ADD CHECK (length(operation_id) BETWEEN 1 AND 128);
-- Legacy inspect only observed EC2; no Stop could have been submitted yet.
UPDATE supivpn.nodes n SET fence_state='ready'
    FROM supivpn.node_recovery r WHERE r.node_id=n.node_id AND r.generation=n.generation
    AND r.phase='inspect' AND r.tries=0 AND n.fence_state='stopping';
CREATE TABLE supivpn.node_recovery_stops (
    node_id text NOT NULL REFERENCES supivpn.nodes(node_id) ON DELETE CASCADE,
    attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(node_id,attempted_at)
);
-- The former stop-only path had no recovery job. Preserve its uncertain Stop
-- as blocked rather than treating it as a fresh, cancellable observation.
INSERT INTO supivpn.node_recovery(node_id,generation,phase,deadline,operation_id,
    stop_reserved,inflight_until,reason)
    SELECT n.node_id,n.generation,'blocked',clock_timestamp(),
        'legacy-' || md5(n.node_id || n.generation),true,
        clock_timestamp()+interval '60 seconds','legacy_stop_unknown'
    FROM supivpn.nodes n LEFT JOIN supivpn.node_recovery r USING(node_id)
    WHERE n.fence_state='stopping' AND (r.node_id IS NULL OR r.phase='complete')
    ON CONFLICT(node_id) DO UPDATE SET generation=EXCLUDED.generation,
        phase='blocked',operation_id=EXCLUDED.operation_id,stop_reserved=true,
        inflight_until=EXCLUDED.inflight_until,reason=EXCLUDED.reason;
INSERT INTO supivpn.node_recovery_stops(node_id,attempted_at)
    SELECT r.node_id,clock_timestamp()-n*interval '1 millisecond'
    FROM supivpn.node_recovery r CROSS JOIN generate_series(1,3) n WHERE r.stop_reserved;
CREATE INDEX recovery_stops_time ON supivpn.node_recovery_stops(attempted_at);
CREATE INDEX recovery_starts_time ON supivpn.node_recovery_starts(attempted_at);
CREATE TABLE supivpn.node_maintenance (
    operation_id text PRIMARY KEY CHECK (length(operation_id) BETWEEN 32 AND 128),
    node_id text NOT NULL,
    generation text NOT NULL,
    replacement_id text NOT NULL DEFAULT '',
    reason text NOT NULL,
    expires_at timestamptz NOT NULL,
    ended_at timestamptz,
    expired_reported boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX one_active_maintenance ON supivpn.node_maintenance ((true))
    WHERE ended_at IS NULL;
CREATE TABLE supivpn.operator_requests (
    request_id text PRIMARY KEY CHECK (length(request_id) BETWEEN 32 AND 128),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash)=32),
    action text NOT NULL,
    node_id text NOT NULL,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON supivpn.node_recovery_stops,supivpn.node_maintenance,supivpn.operator_requests FROM PUBLIC;
