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

type fenceEC2Stub struct {
	state types.InstanceStateName
	describes, stops int
	fail bool
	wrong bool
}
func (s *fenceEC2Stub) DescribeInstances(_ context.Context, q *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	s.describes++
	if s.fail { return nil, errors.New("private SDK details") }
	id := q.InstanceIds[0]
	if s.wrong { id = "i-00000000000000002" }
	return &ec2.DescribeInstancesOutput{Reservations: []types.Reservation{{Instances: []types.Instance{{
		InstanceId: aws.String(id), State: &types.InstanceState{Name: s.state},
	}}}}}, nil
}
func (s *fenceEC2Stub) StopInstances(_ context.Context, q *ec2.StopInstancesInput, _ ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error) {
	s.stops++
	if len(q.InstanceIds) != 1 || q.InstanceIds[0] != "i-00000000000000001" ||
		!aws.ToBool(q.Force) || !aws.ToBool(q.SkipOsShutdown) || aws.ToBool(q.Hibernate) {
		return nil, errors.New("unsafe stop parameters")
	}
	return &ec2.StopInstancesOutput{}, nil
}
func TestEC2FencingObservationsNeverMutate(t *testing.T) {
 node := "i-00000000000000001"
 s := &fenceEC2Stub{}
 f,err := NewEC2Fencer(s,[]string{node}); if err!=nil{t.Fatal(err)}
 for _,state:=range []types.InstanceStateName{types.InstanceStateNameRunning,types.InstanceStateNameStopping,types.InstanceStateNameStopped,types.InstanceStateNameTerminated}{
   s.state=state
   got,err:=f.Power(context.Background(),node)
   if err!=nil || got!=string(state){t.Fatal("incorrect power observation")}
 }
 if s.stops!=0{t.Fatal("Describe initiated Stop")}
 if err=f.Stop(context.Background(),node);err!=nil || s.stops!=1{t.Fatal("explicit Stop failed")}
 if err=f.Stop(context.Background(),"i-00000000000000002");err==nil || s.stops!=1{t.Fatal("unmanaged node stopped")}
 before:=s.describes
 if _,err=f.Power(context.Background(),"invalid");err==nil || s.describes!=before{t.Fatal("invalid node reached EC2")}
 s.state=types.InstanceStateNameTerminated
 if got,err:=f.Power(context.Background(),"i-00000000000000002");err!=nil || got!="terminated"{t.Fatal("retired node cannot be observed")}
 s.wrong=true
 if _,err=f.Power(context.Background(),node);err==nil{t.Fatal("wrong instance accepted")}
 s.wrong,s.fail=false,true
 if _,err=f.Power(context.Background(),node);err==nil || err.Error()!="EC2 fencing unavailable"{t.Fatal("SDK details leaked")}
 ctx,cancel:=context.WithCancel(context.Background());cancel()
 before=s.describes
 if _,err=f.Power(ctx,node);err==nil || s.describes!=before{t.Fatal("cancelled observation reached EC2")}
 if err=f.Stop(ctx,node);err==nil || s.stops!=1{t.Fatal("cancelled Stop reached EC2")}
}
