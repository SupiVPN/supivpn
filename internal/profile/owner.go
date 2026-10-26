// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package profile

import (
	"strings"
	"unicode/utf8"
)

// Owner comes only from verified, authorized SAML. Username is audit metadata;
// SubjectHash remains the authorization identity. Neither belongs in the file.
type Owner struct {
	SubjectHash [32]byte
	Username    string
}

func (o Owner) Valid() bool {
	return o.SubjectHash != [32]byte{} && len(o.Username) <= 1024 &&
		utf8.ValidString(o.Username) && !strings.ContainsRune(o.Username, '\x00')
}
