-- Copyright (c) 2026 SupiVPN. All rights reserved.
-- See LICENSE for copyright ownership and licensing terms.
-- SPDX-License-Identifier: LicenseRef-SupiVPN-Commercial

-- Fixed SQL only. Callers cannot choose a query, schema, deadline or fence state.
-- PUBLIC must not inherit the default EXECUTE privilege on definer functions.
CREATE FUNCTION supivpn.lock_node(p_node text) RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT generation FROM supivpn.nodes WHERE node_id=p_node FOR SHARE
$$;
REVOKE ALL ON FUNCTION supivpn.lock_node(text) FROM PUBLIC;

CREATE FUNCTION supivpn.agent_heartbeat(p_node text, p_generation text, p_ready boolean)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE supivpn.nodes
       SET lease_expires_at=clock_timestamp()+interval '60 seconds',
           healthy_since=CASE WHEN p_ready THEN COALESCE(healthy_since,clock_timestamp()) ELSE NULL END
     WHERE node_id=p_node AND generation=p_generation
       AND lease_expires_at>clock_timestamp() AND fence_state='ready';
    RETURN FOUND;
END
$$;
REVOKE ALL ON FUNCTION supivpn.agent_heartbeat(text,text,boolean) FROM PUBLIC;

CREATE FUNCTION supivpn.agent_rotate(p_node text, p_previous text, p_next text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    created boolean;
    current_generation text;
    current_fence text;
BEGIN
    IF p_node IS NULL OR p_next IS NULL OR p_previous IS NULL
       OR p_node !~ '^[A-Za-z0-9_.-]{1,128}$' OR p_next !~ '^[A-Za-z0-9_.-]{1,128}$'
       OR (p_previous<>'' AND p_previous !~ '^[A-Za-z0-9_.-]{1,128}$')
       OR p_next=p_previous THEN RETURN false; END IF;
    INSERT INTO supivpn.nodes(node_id,generation)
        SELECT p_node,p_next WHERE p_previous='' ON CONFLICT DO NOTHING;
    created := FOUND;
    SELECT generation,fence_state INTO current_generation,current_fence
        FROM supivpn.nodes WHERE node_id=p_node FOR UPDATE;
    IF NOT FOUND OR current_fence='stopping'
       OR (current_fence='stopped' AND current_generation=p_next) THEN RETURN false; END IF;
    IF NOT created AND current_generation=p_next THEN RETURN true; END IF;
    IF NOT created AND current_generation<>p_previous THEN RETURN false; END IF;
    INSERT INTO supivpn.node_generations(node_id,generation)
        VALUES(p_node,p_next) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE supivpn.nodes SET generation=p_next,
        lease_expires_at=clock_timestamp()+interval '60 seconds', fence_state='ready',
        fence_retry_at='epoch',healthy_since=NULL WHERE node_id=p_node;
    RETURN true;
END
$$;
REVOKE ALL ON FUNCTION supivpn.agent_rotate(text,text,text) FROM PUBLIC;

-- Recovery may delete expired authentication state, but cannot create or edit
-- authorizations. Active slots remain until disconnect or confirmed fencing.
CREATE FUNCTION supivpn.prune_auth(p_limit integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE n bigint; total bigint := 0;
BEGIN
    IF p_limit IS NULL OR p_limit<1 OR p_limit>1000 THEN
        RAISE EXCEPTION 'invalid cleanup limit' USING ERRCODE='22023';
    END IF;
    WITH expired AS (
        SELECT ticket_hash FROM supivpn.logins
        WHERE expires_at<clock_timestamp()-interval '24 hours'
          AND NOT (denial_reason='' AND state IN ('decided','acknowledged')
            AND (ack_result IS NULL OR ack_result='applied')
            AND EXISTS (SELECT 1 FROM supivpn.nodes n WHERE n.node_id=logins.node_id
              AND n.generation=logins.generation AND n.fence_state<>'stopped'))
        ORDER BY expires_at LIMIT p_limit FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.logins USING expired WHERE logins.ticket_hash=expired.ticket_hash;
    GET DIAGNOSTICS n = ROW_COUNT; total := total+n;
    WITH expired AS (
        SELECT assertion_hash FROM supivpn.assertions WHERE expires_at<=clock_timestamp()
        ORDER BY expires_at LIMIT p_limit FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.assertions USING expired WHERE assertions.assertion_hash=expired.assertion_hash;
    GET DIAGNOSTICS n = ROW_COUNT; total := total+n;
    WITH expired AS (
        SELECT ticket_hash FROM supivpn.profile_logins WHERE expires_at<=clock_timestamp()
        ORDER BY expires_at LIMIT p_limit FOR UPDATE SKIP LOCKED
    ) DELETE FROM supivpn.profile_logins USING expired WHERE profile_logins.ticket_hash=expired.ticket_hash;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN total+n;
END
$$;
REVOKE ALL ON FUNCTION supivpn.prune_auth(integer) FROM PUBLIC;
