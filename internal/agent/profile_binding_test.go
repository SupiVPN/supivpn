// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"supivpn/internal/profile"
	"testing"
)

func TestProfileProofExactManagementEnvironment(t *testing.T) {
	c, err := profile.NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	good := "username=" + c.ID + "\npassword=" + c.Secret
	for _, tc := range []struct {
		env   string
		valid bool
	}{
		{good, true}, {"password=" + c.Secret + "\nusername=" + c.ID, true},
		{"UV_USERNAME=" + c.ID + "\nUV_PASSWORD=" + c.Secret, false},
		{good + "\npassword=" + c.Secret, false}, {good + "\nusername=" + c.ID, false},
		{"username=" + c.ID, false}, {"password=" + c.Secret, false}, {"username=" + c.ID + "\npassword=" + c.Secret[:20] + "\r" + c.Secret[20:], false},
	} {
		for _, kind := range []string{"CONNECT,7,2", "REAUTH,7,3"} {
			got := envEvent(t, kind, tc.env).proof
			if got.Valid() != tc.valid {
				t.Fatal("credential environment validation")
			}
			if tc.valid && got != c {
				t.Fatal("credential changed")
			}
		}
		if envEvent(t, "DISCONNECT,7", tc.env).proof.Valid() {
			t.Fatal("later event supplied proof")
		}
	}
}
