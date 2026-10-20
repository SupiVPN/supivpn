// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
    "context"
    "errors"
    "regexp"
    "slices"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/ec2"
    "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EC2FenceAPI interface {
    DescribeInstances(context.Context,*ec2.DescribeInstancesInput,...func(*ec2.Options))(*ec2.DescribeInstancesOutput,error)
    StopInstances(context.Context,*ec2.StopInstancesInput,...func(*ec2.Options))(*ec2.StopInstancesOutput,error)
}
type EC2Fencer struct { api EC2FenceAPI; nodes []string }
var ec2NodeID=regexp.MustCompile(`^i-([0-9a-f]{8}|[0-9a-f]{17})$`)
func NewEC2Fencer(api EC2FenceAPI,nodes []string)(*EC2Fencer,error){
    if api==nil || len(nodes)==0 || len(nodes)>100{return nil,errors.New("invalid EC2 fencing configuration")}
    for _,node:=range nodes{if !ec2NodeID.MatchString(node){return nil,errors.New("fencing requires explicit EC2 instance IDs")}}
    return &EC2Fencer{api:api,nodes:slices.Clone(nodes)},nil
}
func(f *EC2Fencer)Managed(node string)bool{return slices.Contains(f.nodes,node)}
func(f *EC2Fencer)Power(ctx context.Context,node string)(string,error){
    refused:=errors.New("EC2 fencing unavailable")
    if !ec2NodeID.MatchString(node) || ctx.Err()!=nil{return "",refused}
    out,err:=f.api.DescribeInstances(ctx,&ec2.DescribeInstancesInput{InstanceIds:[]string{node}})
    if err!=nil || out==nil || len(out.Reservations)!=1 || len(out.Reservations[0].Instances)!=1{return "",refused}
    i:=out.Reservations[0].Instances[0]
    if aws.ToString(i.InstanceId)!=node || i.State==nil ||
        i.HibernationOptions!=nil && aws.ToBool(i.HibernationOptions.Configured){return "",refused}
    switch i.State.Name{
    case types.InstanceStateNameRunning,types.InstanceStateNameStopped,types.InstanceStateNameTerminated,
        types.InstanceStateNameStopping,types.InstanceStateNameShuttingDown,types.InstanceStateNamePending:
        return string(i.State.Name),nil
    }
    return "",refused
}
func(f *EC2Fencer)Stop(ctx context.Context,node string)error{
    refused:=errors.New("EC2 fencing unavailable")
    if !f.Managed(node) || ctx.Err()!=nil{return refused}
    _,err:=f.api.StopInstances(ctx,&ec2.StopInstancesInput{InstanceIds:[]string{node},
        Force:aws.Bool(true),SkipOsShutdown:aws.Bool(true),Hibernate:aws.Bool(false)})
    if err!=nil{return refused}
    return nil
}
