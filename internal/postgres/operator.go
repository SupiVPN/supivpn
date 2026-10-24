// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
    "context"
    "crypto/sha256"
    "encoding/json"
    "errors"
    "log/slog"
    "supivpn/internal/logging"
    "time"

    "github.com/jackc/pgx/v5"
)

// OperatorRequest is accepted only by a deployment-authenticated operator
// transport, never by the public SAML or node API.
type OperatorRequest struct {
    ProfileID string `json:"profile_id,omitempty"`
    Action string `json:"action"`
    NodeID string `json:"node_id"`
    ExpectedGeneration string `json:"expected_generation,omitempty"`
    RecoveryID string `json:"recovery_id,omitempty"`
    ExpectedRevision int64 `json:"expected_revision,omitempty"`
    MaintenanceID string `json:"maintenance_id,omitempty"`
    RequestID string `json:"request_id,omitempty"`
    Reason string `json:"reason,omitempty"`
}
type RecoveryState struct {
    ID string `json:"id"`
    Generation string `json:"generation"`
    Phase string `json:"phase"`
    Revision int64 `json:"revision"`
    StopAttempts int `json:"stop_attempts"`
    StopReserved bool `json:"stop_reserved"`
    InflightUntil time.Time `json:"inflight_until"`
    Reason string `json:"reason"`
}
type MaintenanceState struct {
    ID string `json:"id"`
    NodeID string `json:"node_id"`
    Generation string `json:"generation"`
    ExpiresAt time.Time `json:"expires_at"`
    ReplacementID string `json:"replacement_id"`
    Expired bool `json:"expired"`
}
type OperatorState struct {
    Profile *ProfileState `json:"profile,omitempty"`
    SchemaVersion int `json:"schema_version"`
    NodeID string `json:"node_id"`
    Exists bool `json:"exists"`
    Generation string `json:"generation"`
    FenceState string `json:"fence_state"`
    Healthy bool `json:"healthy"`
    Recovery *RecoveryState `json:"recovery,omitempty"`
    Maintenance *MaintenanceState `json:"maintenance,omitempty"`
    HourlyStops int `json:"hourly_stops"`
    HourlyStarts int `json:"hourly_starts"`
}

func validOperator(q OperatorRequest) bool {
    if q.ProfileID!="" || !validName(q.NodeID){return false}
    switch q.Action {
    case "status":
        return q.ExpectedGeneration=="" && q.RecoveryID=="" && q.ExpectedRevision==0 &&
            q.MaintenanceID=="" && q.RequestID=="" && q.Reason==""
    case "maintenance-check":
        return validName(q.MaintenanceID) && q.ExpectedGeneration=="" &&
            q.RecoveryID=="" && q.ExpectedRevision==0 && q.RequestID=="" && q.Reason==""
    case "maintenance-begin","maintenance-end","maintenance-renew","maintenance-replace","recovery-resume","recovery-resolve":
        if !validName(q.RequestID) || len(q.RequestID)<32 || !validName(q.Reason) ||
            q.ExpectedGeneration!="" && !validName(q.ExpectedGeneration){return false}
    default:
        return false
    }
    switch q.Action {
    case "maintenance-begin":
        return q.MaintenanceID=="" && q.RecoveryID=="" && q.ExpectedRevision==0
    case "maintenance-end","maintenance-renew","maintenance-replace":
        return validName(q.MaintenanceID) && q.RecoveryID=="" && q.ExpectedRevision==0
    default:
        return q.ExpectedGeneration!="" && validName(q.RecoveryID) &&
            q.ExpectedRevision>0 && q.MaintenanceID==""
    }
}

type operatorQuery interface { QueryRow(context.Context,string,...any) pgx.Row }

func operatorState(ctx context.Context,db operatorQuery,node string)(OperatorState,error) {
    out:=OperatorState{NodeID:node}
    if err:=db.QueryRow(ctx,"SELECT max(version) FROM public.supivpn_schema_migrations").Scan(&out.SchemaVersion);err!=nil{return out,err}
    err:=db.QueryRow(ctx,`SELECT generation,fence_state,
        COALESCE(fence_state='ready' AND healthy_since<=clock_timestamp()-interval '30 seconds'
          AND lease_expires_at>clock_timestamp()+interval '30 seconds',false)
        FROM supivpn.nodes WHERE node_id=$1`,node).Scan(&out.Generation,&out.FenceState,&out.Healthy)
    if err!=nil && !errors.Is(err,pgx.ErrNoRows){return out,err}
    out.Exists=err==nil
    r:=&RecoveryState{}
    err=db.QueryRow(ctx,`SELECT operation_id,generation,phase,revision,tries,stop_reserved,inflight_until,reason
        FROM supivpn.node_recovery WHERE node_id=$1`,node).Scan(&r.ID,&r.Generation,&r.Phase,&r.Revision,&r.StopAttempts,&r.StopReserved,&r.InflightUntil,&r.Reason)
    if err==nil{out.Recovery=r}else if !errors.Is(err,pgx.ErrNoRows){return out,err}
    m:=&MaintenanceState{}
    err=db.QueryRow(ctx,`SELECT operation_id,node_id,generation,expires_at,expires_at<=clock_timestamp(),replacement_id
        FROM supivpn.node_maintenance WHERE ended_at IS NULL`).Scan(&m.ID,&m.NodeID,&m.Generation,&m.ExpiresAt,&m.Expired,&m.ReplacementID)
    if err==nil{out.Maintenance=m}else if !errors.Is(err,pgx.ErrNoRows){return out,err}
    err=db.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM supivpn.node_recovery_stops WHERE attempted_at>clock_timestamp()-interval '1 hour'),
        (SELECT count(*) FROM supivpn.node_recovery_starts WHERE attempted_at>clock_timestamp()-interval '1 hour')`).Scan(&out.HourlyStops,&out.HourlyStarts)
    return out,err
}

func(s *Store) Operate(ctx context.Context,q OperatorRequest)(OperatorState,error) {
    var empty OperatorState
    if q.ProfileID!="" {return s.operateProfile(ctx,q)}
    if s==nil || s.pool==nil || s.fencer==nil || !validOperator(q){return empty,ErrConflict}
    ctx,cancel:=context.WithTimeout(ctx,8*time.Second);defer cancel()
    before,err:=operatorState(ctx,s.pool,q.NodeID)
    if err!=nil{return empty,publicError(err)}
    if !before.Exists && !s.fencer.Managed(q.NodeID){return empty,ErrConflict}
    if q.Action=="status"{return before,nil}
    if q.Action=="maintenance-check" {
        if err=s.checkMaintenanceScope(ctx,q,before);err!=nil{return empty,publicError(err)}
        // Re-read the durable lock after any provider observation.
        latest,e:=operatorState(ctx,s.pool,q.NodeID)
        if e!=nil{return empty,publicError(e)}
        if latest.Maintenance==nil || latest.Maintenance.ID!=q.MaintenanceID || latest.Maintenance.Expired || !maintenanceTarget(latest.Maintenance,q.NodeID){return empty,ErrConflict}
        return latest,nil
    }
    data,_:=json.Marshal(q)
    hash:=sha256.Sum256(data)
    // A lost response after a committed mutation must not reserve another cycle.
    var oldHash []byte
    e:=s.pool.QueryRow(ctx,"SELECT request_hash FROM supivpn.operator_requests WHERE request_id=$1",q.RequestID).Scan(&oldHash)
    if e==nil {
        if string(oldHash)!=string(hash[:]){return empty,ErrConflict}
        if q.Action=="maintenance-begin" && (before.Maintenance==nil || before.Maintenance.ID!=q.RequestID){return empty,ErrConflict}
        return before,nil
    }
    if !errors.Is(e,pgx.ErrNoRows){return empty,publicError(e)}

    power:=""
    switch q.Action {
    case "maintenance-end","maintenance-renew","maintenance-replace":
        if err=s.checkMaintenanceScope(ctx,q,before);err!=nil{return empty,publicError(err)}
    }
    if q.Action=="recovery-resume" || q.Action=="recovery-resolve" || q.Action=="maintenance-end" {
        power,err=s.operatorPower(ctx,q.NodeID)
        if err!=nil{return empty,publicError(err)}
    }
    tx,err:=s.begin(ctx);if err!=nil{return empty,publicError(err)}
    defer tx.Rollback(context.Background())
    if err=recoveryLocked(ctx,tx);err!=nil{return empty,publicError(err)}
    // Concurrent duplicate requests may have committed during the cloud read.
    err=tx.QueryRow(ctx,"SELECT request_hash FROM supivpn.operator_requests WHERE request_id=$1",q.RequestID).Scan(&oldHash)
    if err==nil {
        if string(oldHash)!=string(hash[:]){return empty,ErrConflict}
        current,e:=operatorState(ctx,tx,q.NodeID)
        if e!=nil{return empty,publicError(e)}
        if q.Action=="maintenance-begin" && (current.Maintenance==nil || current.Maintenance.ID!=q.RequestID){return empty,ErrConflict}
        return current,nil
    }
    if !errors.Is(err,pgx.ErrNoRows){return empty,publicError(err)}
    // Same lock order as the power reservation. Missing nodes are allowed only
    // for fresh bootstrap maintenance; no node/slot is invented by the operator.
    var locked string
    err=tx.QueryRow(ctx,"SELECT generation FROM supivpn.nodes WHERE node_id=$1 FOR UPDATE",q.NodeID).Scan(&locked)
    if err!=nil && !errors.Is(err,pgx.ErrNoRows){return empty,publicError(err)}
    current,err:=operatorState(ctx,tx,q.NodeID);if err!=nil{return empty,publicError(err)}
    if current.Generation!=q.ExpectedGeneration{return empty,ErrGeneration}
    switch q.Action {
    case "maintenance-begin":
        err=s.beginMaintenance(ctx,tx,q,current)
    case "maintenance-end":
        err=s.endMaintenance(ctx,tx,q,current,power)
    case "maintenance-replace":
        if current.Maintenance==nil || current.Maintenance.ID!=q.MaintenanceID ||
            current.Maintenance.NodeID==q.NodeID ||
            current.Maintenance.ReplacementID!="" && current.Maintenance.ReplacementID!=q.NodeID {
            err=ErrConflict
        } else {
            _,err=tx.Exec(ctx,"UPDATE supivpn.node_maintenance SET replacement_id=$2 WHERE operation_id=$1 AND ended_at IS NULL",q.MaintenanceID,q.NodeID)
        }
    case "maintenance-renew":
        if current.Maintenance==nil || current.Maintenance.ID!=q.MaintenanceID ||
            !maintenanceTarget(current.Maintenance,q.NodeID) {
            err=ErrConflict
        } else {
            _,err=tx.Exec(ctx,`UPDATE supivpn.node_maintenance SET expires_at=clock_timestamp()+interval '30 minutes',
                expired_reported=false WHERE operation_id=$1 AND ended_at IS NULL`,q.MaintenanceID)
        }
    case "recovery-resume","recovery-resolve":
        err=s.resumeRecovery(ctx,tx,q,current,power)
    }
    if err!=nil{return empty,publicError(err)}
    if _,err=tx.Exec(ctx,`INSERT INTO supivpn.operator_requests(request_id,request_hash,action,node_id,reason)
        VALUES ($1,$2,$3,$4,$5)`,q.RequestID,hash[:],q.Action,q.NodeID,q.Reason);err!=nil{return empty,publicError(err)}
    after,err:=operatorState(ctx,tx,q.NodeID);if err!=nil{return empty,publicError(err)}
    if err=tx.Commit(ctx);err!=nil{return empty,publicError(err)}
    // The free-form operator reason stays in the protected receipt, not logs.
    logging.Emit(ctx, "operator.action_completed", slog.String("action", q.Action), slog.String("node_id", q.NodeID), slog.String("operator_request_id", q.RequestID))
    return after,nil
}

func(s *Store) operatorPower(ctx context.Context,node string)(string,error) {
    ctx,cancel:=context.WithTimeout(ctx,3*time.Second);defer cancel()
    return s.fencer.Power(ctx,node)
}

func(s *Store) checkMaintenanceScope(ctx context.Context,q OperatorRequest,state OperatorState)error {
    m:=state.Maintenance
    if m==nil || m.ID!=q.MaintenanceID || q.Action=="maintenance-check" && m.Expired{return ErrConflict}
    if !s.fencer.Managed(q.NodeID){return ErrConflict}
    if maintenanceTarget(m,q.NodeID){return nil}
    if q.Action!="maintenance-replace" || m.ReplacementID!=""{return ErrConflict}
    // Only the operator-selected replacement may reuse an outer rollout lock.
    // The old EC2 must be terminated, not merely stopped or absent in Describe.
    old,err:=s.operatorPower(ctx,m.NodeID)
    if err!=nil{return err}
    if old!="terminated"{return ErrConflict}
    return nil
}

func maintenanceTarget(m *MaintenanceState,node string)bool {
    if m.ReplacementID!=""{return m.ReplacementID==node}
    return m.NodeID==node
}

func(s *Store) beginMaintenance(ctx context.Context,tx pgx.Tx,q OperatorRequest,state OperatorState)error {
    if !s.fencer.Managed(q.NodeID) || state.Maintenance!=nil{return ErrConflict}
    var busy bool
    err:=tx.QueryRow(ctx,`SELECT EXISTS (SELECT 1 FROM supivpn.node_recovery
        WHERE phase<>'complete' OR inflight_until>clock_timestamp())`).Scan(&busy)
    if err!=nil{return err}
    if busy{return ErrConflict}
    _,err=tx.Exec(ctx,`INSERT INTO supivpn.node_maintenance(operation_id,node_id,generation,reason,expires_at)
        VALUES ($1,$2,$3,$4,clock_timestamp()+interval '30 minutes')`,q.RequestID,q.NodeID,q.ExpectedGeneration,q.Reason)
    return err
}

func(s *Store) endMaintenance(ctx context.Context,tx pgx.Tx,q OperatorRequest,state OperatorState,power string)error {
    if state.Maintenance==nil || state.Maintenance.ID!=q.MaintenanceID ||
        !maintenanceTarget(state.Maintenance,q.NodeID) ||
        power!="running" || !state.Exists || !state.Healthy{return ErrConflict}
    _,err:=tx.Exec(ctx,"UPDATE supivpn.node_maintenance SET ended_at=clock_timestamp() WHERE operation_id=$1 AND ended_at IS NULL",q.MaintenanceID)
    return err
}

func(s *Store) resumeRecovery(ctx context.Context,tx pgx.Tx,q OperatorRequest,state OperatorState,power string)error {
    r:=state.Recovery
    if state.Maintenance!=nil || r==nil || r.Phase!="blocked" ||
        r.ID!=q.RecoveryID || r.Revision!=q.ExpectedRevision{return ErrConflict}
    var quiet bool
    if err:=tx.QueryRow(ctx,"SELECT inflight_until<=clock_timestamp() FROM supivpn.node_recovery WHERE node_id=$1 FOR UPDATE",q.NodeID).Scan(&quiet);err!=nil{return err}
    if !quiet{return ErrConflict}
    var other bool
    if err:=tx.QueryRow(ctx,`SELECT EXISTS (SELECT 1 FROM supivpn.node_recovery
        WHERE node_id<>$1 AND phase IN ('inspect','stop','start','verify'))`,q.NodeID).Scan(&other);err!=nil{return err}
    if other{return ErrConflict}
    stopped:=power=="stopped" || power=="terminated"
    recovered:=power=="running" && state.Generation!=r.Generation && state.Healthy
    phase:="complete"
    if q.Action=="recovery-resolve" {
        if !stopped && !recovered && r.StopReserved{return ErrConflict}
    } else if !recovered && power!="terminated" {
        if !s.fencer.Managed(q.NodeID){return ErrConflict}
        if stopped {
            _,canStart:=s.fencer.(RecoveryDriver)
            if canStart && r.StopReserved {
                if state.HourlyStarts>=3{return ErrConflict}
                phase="start"
            }
        } else if power=="running" && r.StopReserved {
            var witness bool
            if err:=tx.QueryRow(ctx,"SELECT "+recoveryWitness,q.NodeID).Scan(&witness);err!=nil{return err}
            if !witness || state.HourlyStops>=3 || state.HourlyStarts>=3{return ErrConflict}
            phase="inspect"
        } else if r.StopReserved {return ErrConflict}
    }
    // Never erase attempts or grants. A new operation ID makes stale operator
    // approvals unusable; global rolling budgets still include all prior calls.
    _,err:=tx.Exec(ctx,`UPDATE supivpn.node_recovery SET generation=$2,phase=$3,
        operation_id=$4,claim='',revision=revision+1,tries=0,reason='operator_reviewed',
        stop_reserved=$5,inflight_until='epoch',next_at='epoch',deadline=clock_timestamp()+interval '10 minutes'
        WHERE node_id=$1`,q.NodeID,state.Generation,phase,q.RequestID,phase=="start")
    if err!=nil{return err}
    if stopped {
        _,err=tx.Exec(ctx,"UPDATE supivpn.nodes SET fence_state='stopped',healthy_since=NULL WHERE node_id=$1",q.NodeID)
    } else if phase=="inspect" || !r.StopReserved {
        // This permission to rotate is only safe when no previous Stop was
        // reserved. A reviewed retry after unknown Stop keeps rotation closed.
        if !r.StopReserved {
            _,err=tx.Exec(ctx,"UPDATE supivpn.nodes SET fence_state='ready' WHERE node_id=$1",q.NodeID)
        } else {
            _,err=tx.Exec(ctx,"UPDATE supivpn.node_recovery SET stop_reserved=true WHERE node_id=$1",q.NodeID)
        }
    }
    return err
}
