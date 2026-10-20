// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
    "context"
    "errors"
    "testing"
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/ec2"
    "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type recoveryEC2Stub struct {fenceEC2Stub; starts int; failStart, hibernation bool}
func(s *recoveryEC2Stub)DescribeInstances(ctx context.Context,q *ec2.DescribeInstancesInput,opts ...func(*ec2.Options))(*ec2.DescribeInstancesOutput,error){
    out,err:=s.fenceEC2Stub.DescribeInstances(ctx,q,opts...)
    if err==nil && out!=nil && s.hibernation{
        out.Reservations[0].Instances[0].HibernationOptions=&types.HibernationOptions{Configured:aws.Bool(true)}
    }
    return out,err
}
func(s *recoveryEC2Stub)StartInstances(_ context.Context,q *ec2.StartInstancesInput,_ ...func(*ec2.Options))(*ec2.StartInstancesOutput,error){
    s.starts++
    if len(q.InstanceIds)!=1 || q.InstanceIds[0]!="i-00000000000000001" || s.failStart{return nil,errors.New("private SDK error")}
    return &ec2.StartInstancesOutput{},nil
}
func TestEC2RecoveryExactTargetsAndBoundedCalls(t *testing.T){
    const node="i-00000000000000001"
    s:=&recoveryEC2Stub{fenceEC2Stub:fenceEC2Stub{state:types.InstanceStateNameRunning}}
    f,err:=NewEC2Recovery(s,[]string{node});if err!=nil{t.Fatal(err)}
    ctx:=context.Background()
    for _,state:=range []types.InstanceStateName{types.InstanceStateNameRunning,types.InstanceStateNameStopped,types.InstanceStateNamePending,types.InstanceStateNameTerminated}{
        s.state=state;p,e:=f.Power(ctx,node)
        if e!=nil || p!=string(state){t.Fatal("incorrect power state")}
    }
    if s.stops!=0 || s.starts!=0{t.Fatal("observation mutated EC2")}
    s.hibernation=true
    if _,err=f.Power(ctx,node);err==nil{t.Fatal("hibernation-enabled EC2 accepted as safely stopped")}
    s.hibernation=false
    for _,n:=range []string{"invalid","i-00000000000000002"}{
        if f.Managed(n) || f.Stop(ctx,n)==nil || f.Start(ctx,n)==nil{t.Fatal("unmanaged node mutated")}
    }
    if s.stops!=0 || s.starts!=0{t.Fatal("unmanaged request reached EC2")}
    if f.Stop(ctx,node)!=nil || f.Start(ctx,node)!=nil || s.stops!=1 || s.starts!=1{t.Fatal("wrong bounded power calls")}
    s.wrong=true
    if _,err=f.Power(ctx,node);err==nil{t.Fatal("wrong EC2 ID accepted")}
    s.wrong=false;s.failStart=true
    if err=f.Start(ctx,node);err==nil || err.Error()!="EC2 recovery unavailable"{t.Fatal("SDK error not opaque")}
    cancelled,cancel:=context.WithCancel(ctx);cancel()
    before:=s.starts
    if f.Start(cancelled,node)==nil || s.starts!=before{t.Fatal("cancelled start reached EC2")}
}
