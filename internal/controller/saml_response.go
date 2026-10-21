// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"encoding/base64"
	"errors"
	"supivpn/internal/saml"
)

const maxSAMLXMLBytes = 1 << 20

var errSAMLXML = errors.New("invalid or excessive SAML XML")

func parseSAMLResponse(sp *saml.ServiceProvider, encoded, requestID string) (*saml.Assertion, error) {
	if len(encoded) > base64.StdEncoding.EncodedLen(maxSAMLXMLBytes) {
		return nil, errSAMLXML
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errSAMLXML
	}
	return sp.ParseXMLResponse(data, []string{requestID}, sp.AcsURL)
}
