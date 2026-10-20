// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agentclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"time"
)

// EC2Signer uses only the instance role, with IMDSv2 required. Environment/profile
// credentials and HTTP proxies cannot change the node identity.
func EC2Signer(region string) Sign {
	metadataHTTP := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	provider := ec2rolecreds.New(func(o *ec2rolecreds.Options) {
		o.Client = imds.New(imds.Options{Endpoint: "http://169.254.169.254",
			EnableFallback: aws.FalseTernary, HTTPClient: metadataHTTP})
	})
	return SigV4(region, aws.NewCredentialsCache(provider))
}

func SigV4(region string, credentials aws.CredentialsProvider) Sign {
	signer := v4.NewSigner()
	return func(ctx context.Context, r *http.Request, body []byte) error {
		creds, err := credentials.Retrieve(ctx)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		return signer.SignHTTP(ctx, creds, r, hex.EncodeToString(digest[:]), "execute-api", region, time.Now())
	}
}
