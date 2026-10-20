// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"fmt"
	"strings"
	"testing"
)

func TestSAMLXMLComplexityLimits(t *testing.T) {
	attrs := func(count int) string {
		var b strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&b, " a%d=\"v\"", i)
		}
		return b.String()
	}
	cases := []struct {
		name, xml string
		valid     bool
	}{
		{"ordinary", `<?xml version="1.0"?><r><!-- comment --><v>text</v></r>`, true},
		{"depth-limit", strings.Repeat("<r>", maxSAMLXMLDepth) + strings.Repeat("</r>", maxSAMLXMLDepth), true},
		{"depth-exceeded", strings.Repeat("<r>", maxSAMLXMLDepth+1) + strings.Repeat("</r>", maxSAMLXMLDepth+1), false},
		{"elements-limit", "<r>" + strings.Repeat("<v/>", maxSAMLXMLElements-1) + "</r>", true},
		{"elements-exceeded", "<r>" + strings.Repeat("<v/>", maxSAMLXMLElements) + "</r>", false},
		{"tokens-limit", "<r>" + strings.Repeat("x<!---->", (maxSAMLXMLTokens-2)/2) + "</r>", true},
		{"tokens-exceeded", "<r>" + strings.Repeat("x<!---->", maxSAMLXMLTokens/2) + "</r>", false},
		{"attributes-limit", "<r" + attrs(maxSAMLAttrsPerNode) + "/>", true},
		{"attributes-exceeded", "<r" + attrs(maxSAMLAttrsPerNode+1) + "/>", false},
		{"total-attributes-limit", "<r>" + strings.Repeat("<v"+attrs(64)+"/>", 64) + "</r>", true},
		{"total-attributes-exceeded", "<r>" + strings.Repeat("<v"+attrs(64)+"/>", 65) + "</r>", false},
		{"bytes-limit", "<r>" + strings.Repeat("x", maxSAMLXMLBytes-7) + "</r>", true},
		{"bytes-exceeded", "<r>" + strings.Repeat("x", maxSAMLXMLBytes-6) + "</r>", false},
		{"empty", "", false},
		{"unclosed", "<r>", false},
		{"multiple-roots", "<r/><r/>", false},
		{"outside-text", "<r/>text", false},
		{"doctype", "<!DOCTYPE r><r/>", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if valid := checkSAMLXML([]byte(tc.xml)) == nil; valid != tc.valid {
				t.Fatalf("XML accepted = %v, want %v", valid, tc.valid)
			}
		})
	}
}
