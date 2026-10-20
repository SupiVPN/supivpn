// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package awsruntime

import (
    "context"
    "errors"
    "github.com/aws/aws-sdk-go-v2/service/ec2"
)

type EC2RecoveryAPI interface {
    EC2FenceAPI
    StartInstances(context.Context,*ec2.StartInstancesInput,...func(*ec2.Options))(*ec2.StartInstancesOutput,error)
}
type EC2Recovery struct { *EC2Fencer; recoveryAPI EC2RecoveryAPI }
func NewEC2Recovery(api EC2RecoveryAPI,nodes []string)(*EC2Recovery,error){
    f,err:=NewEC2Fencer(api,nodes)
    if err!=nil{return nil,err}
    return &EC2Recovery{EC2Fencer:f,recoveryAPI:api},nil
}
func(f *EC2Recovery)Start(ctx context.Context,node string)error{
    refused:=errors.New("EC2 recovery unavailable")
    if !f.Managed(node) || ctx.Err()!=nil{return refused}
    _,err:=f.recoveryAPI.StartInstances(ctx,&ec2.StartInstancesInput{InstanceIds:[]string{node}})
    if err!=nil{return refused}
    return nil
}
