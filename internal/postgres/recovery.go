// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package postgres

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "errors"
    "log/slog"
    "supivpn/internal/logging"

    "github.com/jackc/pgx/v5"
)

const recoveryLock int64 = 7273182103
const recoveryWitness = `EXISTS (SELECT 1 FROM supivpn.nodes w
    WHERE w.node_id<>$1 AND w.fence_state='ready'
      AND w.healthy_since<=clock_timestamp()-interval '30 seconds'
      AND w.lease_expires_at>clock_timestamp()+interval '30 seconds')`
const noMaintenance = `NOT EXISTS (SELECT 1 FROM supivpn.node_maintenance WHERE ended_at IS NULL)`

type recoveryJob struct {
    node, generation, phase, claim, operation string
    tries int
    stopReserved bool
}

func operationID() (string,error) {
    var b [16]byte
    if _,err:=rand.Read(b[:]);err!=nil{return "",err}
    return hex.EncodeToString(b[:]),nil
}

func recoveryLocked(ctx context.Context, tx pgx.Tx) error {
    var ok bool
    if err:=tx.QueryRow(ctx,"SELECT pg_try_advisory_xact_lock($1)",recoveryLock).Scan(&ok);err!=nil{return err}
    if !ok{return ErrConflict}
    return nil
}

func (s *Store) recoverExpired(ctx context.Context,d Fencer) error {
    j,err:=s.claimRecovery(ctx)
    if err!=nil || j==nil{return publicError(err)}
    if !j.stopReserved {
        // A clean restart/witness loss can cancel observation. No power
        // operation has been reserved, so invalidating this claim is safe.
        var eligible bool
        err=s.pool.QueryRow(ctx,`SELECT generation=$2 AND lease_expires_at<=clock_timestamp()
            AND `+recoveryWitness+` FROM supivpn.nodes WHERE node_id=$1`,j.node,j.generation).Scan(&eligible)
        if err!=nil{return publicError(err)}
        if !eligible{return s.abandonUnstartedRecovery(ctx,j,"observation_cancelled")}
    }
    power,err:=d.Power(ctx,j.node)
    if err!=nil {
        if !j.stopReserved {
            if e:=s.abandonUnstartedRecovery(ctx,j,"observation_unavailable");e!=nil{return e}
        }
        return publicError(err)
    }
    if !d.Managed(j.node) {
        if power=="stopped" || power=="terminated"{return s.recoveryMove(ctx,j,"complete",true,"retired_stopped")}
        return s.recoveryMove(ctx,j,"blocked",false,"retired_running")
    }
    switch j.phase {
    case "inspect":
        if power=="stopped" || power=="terminated" {
            // A reviewed retry may observe a delayed Stop from its previous
            // operation. Preserve ownership and continue Start, not a new Stop.
            if _,canStart:=d.(RecoveryDriver);power=="stopped" && j.stopReserved && canStart {
                return s.recoveryMove(ctx,j,"start",true,"")
            }
            return s.recoveryMove(ctx,j,"complete",true,"already_stopped")
        }
        if power=="running"{return s.recoveryMove(ctx,j,"stop",false,"")}
    case "stop":
        if power=="stopped" || power=="terminated" {
            _,canStart:=d.(RecoveryDriver)
            if power=="stopped" && j.stopReserved && canStart {
                return s.recoveryMove(ctx,j,"start",true,"")
            }
            return s.recoveryMove(ctx,j,"complete",true,"fenced")
        }
        if power!="running"{return nil}
        allowed,e:=s.reservePower(ctx,j,"stop")
        if e!=nil || !allowed{return publicError(e)}
        return publicError(d.Stop(ctx,j.node))
    case "start":
        if power=="terminated"{return s.recoveryMove(ctx,j,"complete",true,"terminated")}
        if power=="running" || power=="pending"{return s.recoveryMove(ctx,j,"verify",false,"")}
        if power!="stopped"{return nil}
        driver,canStart:=d.(RecoveryDriver)
        if !canStart{return s.recoveryMove(ctx,j,"complete",true,"start_disabled")}
        allowed,e:=s.reservePower(ctx,j,"start")
        if e!=nil || !allowed{return publicError(e)}
        return publicError(driver.Start(ctx,j.node))
    case "verify":
        var healthy bool
        err=s.pool.QueryRow(ctx,`SELECT COALESCE(generation<>$2 AND fence_state='ready'
            AND healthy_since<=clock_timestamp()-interval '30 seconds'
            AND lease_expires_at>clock_timestamp()+interval '30 seconds',false)
            FROM supivpn.nodes WHERE node_id=$1`,j.node,j.generation).Scan(&healthy)
        if err!=nil{return publicError(err)}
        if healthy && power=="running"{return s.recoveryMove(ctx,j,"complete",false,"healthy")}
        if power=="stopped"{return s.recoveryMove(ctx,j,"start",false,"")}
        if power=="terminated"{return s.recoveryMove(ctx,j,"complete",true,"terminated")}
    }
    return nil
}

// Observation never changes fence_state. Only a committed Stop reservation
// closes clean rotation, under the same node lock used by RotateNode.
func (s *Store) claimRecovery(ctx context.Context)(*recoveryJob,error) {
    tx,err:=s.begin(ctx);if err!=nil{return nil,err}
    defer tx.Rollback(context.Background())
    if err=recoveryLocked(ctx,tx);errors.Is(err,ErrConflict){return nil,nil}else if err!=nil{return nil,err}
    var maintenance bool
    if err=tx.QueryRow(ctx,"SELECT NOT ("+noMaintenance+")").Scan(&maintenance);err!=nil{return nil,err}
    if maintenance {
        tag,e:=tx.Exec(ctx,`UPDATE supivpn.node_maintenance SET expired_reported=true
            WHERE ended_at IS NULL AND expires_at<=clock_timestamp() AND NOT expired_reported`)
        if e!=nil{return nil,e}
        if tag.RowsAffected()>0{logging.Emit(ctx, "maintenance.expired")}
        return nil,tx.Commit(ctx)
    }
    j:=&recoveryJob{}
    var due,expired bool
    err=tx.QueryRow(ctx,`SELECT node_id,generation,phase,tries,claim,operation_id,stop_reserved,
        next_at<=clock_timestamp(),deadline<=clock_timestamp()
        FROM supivpn.node_recovery WHERE phase IN ('inspect','stop','start','verify') FOR UPDATE`).
        Scan(&j.node,&j.generation,&j.phase,&j.tries,&j.claim,&j.operation,&j.stopReserved,&due,&expired)
    if errors.Is(err,pgx.ErrNoRows) {
        err=tx.QueryRow(ctx,`SELECT n.node_id,n.generation FROM supivpn.nodes n
            LEFT JOIN supivpn.node_recovery r ON r.node_id=n.node_id
            WHERE n.lease_expires_at<=clock_timestamp() AND n.fence_state<>'stopped'
              AND n.fence_retry_at<=clock_timestamp()
              AND (r.node_id IS NULL OR r.phase='complete')
              AND NOT EXISTS (SELECT 1 FROM supivpn.node_recovery WHERE phase='blocked')
              AND EXISTS (SELECT 1 FROM supivpn.nodes w WHERE w.node_id<>n.node_id
                AND w.fence_state='ready' AND w.healthy_since<=clock_timestamp()-interval '30 seconds'
                AND w.lease_expires_at>clock_timestamp()+interval '30 seconds')
              AND (SELECT count(*) FROM supivpn.node_recovery_stops WHERE attempted_at>clock_timestamp()-interval '1 hour')<3
              AND (SELECT count(*) FROM supivpn.node_recovery_starts WHERE attempted_at>clock_timestamp()-interval '1 hour')<3
            ORDER BY n.node_id LIMIT 1 FOR UPDATE OF n`).Scan(&j.node,&j.generation)
        if errors.Is(err,pgx.ErrNoRows){return nil,nil}
        if err!=nil{return nil,err}
        j.phase="inspect"
        j.operation,err=operationID();if err!=nil{return nil,err}
        _,err=tx.Exec(ctx,`INSERT INTO supivpn.node_recovery(node_id,generation,phase,deadline,operation_id)
            VALUES ($1,$2,'inspect',clock_timestamp()+interval '10 minutes',$3)
            ON CONFLICT(node_id) DO UPDATE SET generation=$2,phase='inspect',tries=0,
              stop_reserved=false,inflight_until='epoch',reason='',operation_id=$3,revision=node_recovery.revision+1,
              deadline=clock_timestamp()+interval '10 minutes'`,j.node,j.generation,j.operation)
        if err!=nil{return nil,err}
    } else {
        if err!=nil{return nil,err}
        if !due{return nil,nil}
        if expired {
            phase,reason:="blocked","deadline"
            if !j.stopReserved{phase,reason="complete","observation_timeout"}
            if _,err=tx.Exec(ctx,`UPDATE supivpn.node_recovery SET phase=$2,reason=$3,revision=revision+1 WHERE node_id=$1`,j.node,phase,reason);err!=nil{return nil,err}
            if !j.stopReserved {
                if _,err=tx.Exec(ctx,"UPDATE supivpn.nodes SET fence_retry_at=clock_timestamp()+interval '30 seconds' WHERE node_id=$1",j.node);err!=nil{return nil,err}
            }
            if err=tx.Commit(ctx);err!=nil{return nil,err}
            logging.Emit(ctx, "recovery.transition", slog.String("node_id", j.node), slog.String("generation", j.generation), slog.String("phase", phase), slog.String("reason", reason))
            return nil,nil
        }
    }
    j.claim,err=operationID();if err!=nil{return nil,err}
    _,err=tx.Exec(ctx,`UPDATE supivpn.node_recovery SET claim=$2,next_at=clock_timestamp()+interval '30 seconds',revision=revision+1
        WHERE node_id=$1`,j.node,j.claim)
    if err!=nil{return nil,err}
    if err=tx.Commit(ctx);err!=nil{return nil,err}
    return j,nil
}

func(s *Store) abandonUnstartedRecovery(ctx context.Context,j *recoveryJob,reason string)error {
    tx,err:=s.begin(ctx);if err!=nil{return publicError(err)}
    defer tx.Rollback(context.Background())
    if err=recoveryLocked(ctx,tx);errors.Is(err,ErrConflict){return nil}else if err!=nil{return publicError(err)}
    tag,err:=tx.Exec(ctx,`UPDATE supivpn.node_recovery SET phase='complete',reason=$3,revision=revision+1
        WHERE node_id=$1 AND claim=$2 AND NOT stop_reserved AND phase IN ('inspect','stop')`,j.node,j.claim,reason)
    if err!=nil{return publicError(err)}
    if tag.RowsAffected()==1 {
        _,err=tx.Exec(ctx,`UPDATE supivpn.nodes SET fence_retry_at=clock_timestamp()+interval '30 seconds'
            WHERE node_id=$1 AND generation=$2`,j.node,j.generation)
        if err!=nil{return publicError(err)}
    }
    return publicError(tx.Commit(ctx))
}

func(s *Store) recoveryMove(ctx context.Context,j *recoveryJob,phase string,stopped bool,reason string)error {
    tx,err:=s.begin(ctx);if err!=nil{return publicError(err)}
    defer tx.Rollback(context.Background())
    if err=recoveryLocked(ctx,tx);errors.Is(err,ErrConflict){return nil}else if err!=nil{return publicError(err)}
    tag,err:=tx.Exec(ctx,`UPDATE supivpn.node_recovery SET phase=$3,reason=$5,revision=revision+1
        WHERE node_id=$1 AND claim=$2 AND phase=$4 AND `+noMaintenance,j.node,j.claim,phase,j.phase,reason)
    if err!=nil{return publicError(err)}
    if tag.RowsAffected()!=1{return nil}
    if stopped {
        _,err=tx.Exec(ctx,`UPDATE supivpn.nodes SET fence_state='stopped',healthy_since=NULL
            WHERE node_id=$1 AND generation=$2`,j.node,j.generation)
        if err!=nil{return publicError(err)}
    }
    if err=tx.Commit(ctx);err!=nil{return publicError(err)}
    logging.Emit(ctx, "recovery.transition", slog.String("node_id", j.node), slog.String("generation", j.generation), slog.String("phase", phase), slog.String("reason", reason))
    return nil
}

func(s *Store) reservePower(ctx context.Context,j *recoveryJob,action string)(bool,error) {
    tx,err:=s.begin(ctx);if err!=nil{return false,err}
    defer tx.Rollback(context.Background())
    if err=recoveryLocked(ctx,tx);errors.Is(err,ErrConflict){return false,nil}else if err!=nil{return false,err}
    var generation,fenceState string
    var expired bool
    if err=tx.QueryRow(ctx,"SELECT generation,fence_state,lease_expires_at<=clock_timestamp() FROM supivpn.nodes WHERE node_id=$1 FOR UPDATE",j.node).Scan(&generation,&fenceState,&expired);err!=nil{return false,err}
    var eligible bool
    err=tx.QueryRow(ctx,`SELECT true FROM supivpn.node_recovery WHERE node_id=$1 AND claim=$2
        AND phase=$3 AND generation=$4 AND operation_id=$5 AND stop_reserved=$6
        AND deadline>clock_timestamp() AND inflight_until<=clock_timestamp() AND `+noMaintenance+` FOR UPDATE`,
        j.node,j.claim,action,j.generation,j.operation,j.stopReserved).Scan(&eligible)
    if errors.Is(err,pgx.ErrNoRows){return false,nil}
    if err!=nil{return false,err}
    if generation!=j.generation {
        // A clean restart won before any Stop was reserved.
        if !j.stopReserved {
            _,err=tx.Exec(ctx,"UPDATE supivpn.node_recovery SET phase='complete',reason='generation_changed',revision=revision+1 WHERE node_id=$1",j.node)
            if err!=nil{return false,err}
            return false,tx.Commit(ctx)
        }
        return false,nil
    }
    if action=="stop" {
        // Recheck the lease under the node lock immediately before reserving
        // power; an earlier observation is not authority to stop a revived node.
        if !expired || fenceState=="stopped" { return false,nil }
        var witness bool
        if err=tx.QueryRow(ctx,"SELECT "+recoveryWitness,j.node).Scan(&witness);err!=nil{return false,err}
        if !witness{return false,nil}
        if s.component==Recovery {
            rows,e:=tx.Query(ctx,`SELECT node_id FROM supivpn.nodes WHERE node_id<>$1
                AND fence_state='ready' AND healthy_since<=clock_timestamp()-interval '30 seconds'
                AND lease_expires_at>clock_timestamp()+interval '30 seconds'`,j.node)
            if e!=nil{return false,e}
            managed:=false
            for rows.Next(){var node string;if e=rows.Scan(&node);e!=nil{rows.Close();return false,e};if s.fencer.Managed(node){managed=true}}
            e=rows.Err();rows.Close();if e!=nil{return false,e};if !managed{return false,nil}
        }
    }
    if action=="start" && (!j.stopReserved || fenceState!="stopped") { return false,nil }
    table:="supivpn.node_recovery_stops"
    if action=="start"{table="supivpn.node_recovery_starts"}
    var count int
    if err=tx.QueryRow(ctx,"SELECT count(*) FROM "+table+" WHERE attempted_at>clock_timestamp()-interval '1 hour'").Scan(&count);err!=nil{return false,err}
    if count>=3 || action=="stop" && j.tries>=3 {
        _,err=tx.Exec(ctx,"UPDATE supivpn.node_recovery SET phase='blocked',reason=$2,revision=revision+1 WHERE node_id=$1",j.node,action+"_budget")
        if err!=nil{return false,err}
        if err=tx.Commit(ctx);err!=nil{return false,err}
        logging.Emit(ctx, "recovery.transition", slog.String("node_id", j.node), slog.String("generation", j.generation), slog.String("phase", "blocked"), slog.String("reason", action+"_budget"))
        return false,nil
    }
    // This window exceeds the entire bounded reconciliation context. Operator
    // operations cannot proceed while an earlier SDK request may still run.
    if _,err=tx.Exec(ctx,"UPDATE supivpn.node_recovery SET inflight_until=clock_timestamp()+interval '30 seconds',revision=revision+1 WHERE node_id=$1",j.node);err!=nil{return false,err}
    if action=="stop" {
        if _,err=tx.Exec(ctx,"UPDATE supivpn.node_recovery SET stop_reserved=true,tries=tries+1 WHERE node_id=$1",j.node);err!=nil{return false,err}
        if _,err=tx.Exec(ctx,"UPDATE supivpn.nodes SET fence_state='stopping',healthy_since=NULL WHERE node_id=$1",j.node);err!=nil{return false,err}
    }
    if _,err=tx.Exec(ctx,"INSERT INTO "+table+"(node_id) VALUES ($1)",j.node);err!=nil{return false,err}
    return true,tx.Commit(ctx)
}
