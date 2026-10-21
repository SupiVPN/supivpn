-- Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
-- Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
-- SPDX-License-Identifier: AGPL-3.0-only

-- Preserve the restricted function's owner and grants. Acquire the row lock
-- before checking the lease, even when a previous locker made no row change.
CREATE OR REPLACE FUNCTION supivpn.agent_heartbeat(p_node text, p_generation text, p_ready boolean)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM 1 FROM supivpn.nodes WHERE node_id=p_node FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE supivpn.nodes
       SET lease_expires_at=clock_timestamp()+interval '60 seconds',
           healthy_since=CASE WHEN p_ready THEN COALESCE(healthy_since,clock_timestamp()) ELSE NULL END
     WHERE node_id=p_node AND generation=p_generation
       AND lease_expires_at>clock_timestamp() AND fence_state='ready';
    RETURN FOUND;
END
$$;

-- A fixed cutoff per cleanup statement permits an expiry index range scan.
-- It can defer newly expired rows until the next batch; admission and lease
-- checks continue to use fresh clocks independently of garbage collection.
CREATE OR REPLACE FUNCTION supivpn.prune_auth(p_limit integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE n bigint; total bigint := 0;
BEGIN
    IF p_limit IS NULL OR p_limit<1 OR p_limit>1000 THEN
        RAISE EXCEPTION 'invalid cleanup limit' USING ERRCODE='22023';
    END IF;
    WITH expired AS (
        SELECT ticket_hash FROM supivpn.logins
        WHERE expires_at<(SELECT clock_timestamp()-interval '24 hours')
          AND NOT (denial_reason='' AND state IN ('decided','acknowledged')
            AND (ack_result IS NULL OR ack_result='applied')
            AND EXISTS (SELECT 1 FROM supivpn.nodes n WHERE n.node_id=logins.node_id
              AND n.generation=logins.generation AND n.fence_state<>'stopped'))
        ORDER BY expires_at LIMIT p_limit FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.logins USING expired WHERE logins.ticket_hash=expired.ticket_hash;
    GET DIAGNOSTICS n = ROW_COUNT; total := total+n;
    WITH expired AS (
        SELECT assertion_hash FROM supivpn.assertions WHERE expires_at<=(SELECT clock_timestamp())
        ORDER BY expires_at LIMIT p_limit FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.assertions USING expired WHERE assertions.assertion_hash=expired.assertion_hash;
    GET DIAGNOSTICS n = ROW_COUNT; total := total+n;
    WITH expired AS (
        SELECT ticket_hash FROM supivpn.profile_logins WHERE expires_at<=(SELECT clock_timestamp())
        ORDER BY expires_at LIMIT p_limit FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.profile_logins USING expired WHERE profile_logins.ticket_hash=expired.ticket_hash;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN total+n;
END
$$;
