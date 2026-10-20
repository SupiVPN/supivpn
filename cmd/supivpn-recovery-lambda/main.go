// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

// supivpn-recovery-lambda accepts scheduled reconciliation and operator invocations.
package main

import "supivpn/internal/lambdaruntime"

func main() { lambdaruntime.MainRecovery() }
