// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// supivpn-agent-lambda serves only the IAM-authorized agent API.
package main

import "supivpn/internal/lambdaruntime"

func main() { lambdaruntime.MainAgent() }
