// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"math"
	"strings"
	"testing"
)

func TestMetricsTextEscapingAndBounds(t *testing.T) {
	family := Gauge("supivpn_example", "First\nsecond\\line", 1, Label{Name: "group", Value: "quoted\"\\\nname"})
	b, err := Encode([]Family{family})
	want := "# HELP supivpn_example First\\nsecond\\\\line\n# TYPE supivpn_example gauge\nsupivpn_example{group=\"quoted\\\"\\\\\\nname\"} 1\n"
	if err != nil || string(b) != want {
		t.Fatalf("incorrect escaping: %q", b)
	}
	for _, f := range []Family{
		Gauge("bad\nname", "help", 1), Gauge("ok", "help", math.NaN()),
		Gauge("ok", "help", 1, Label{Name: "group", Value: strings.Repeat("x", 257)}),
		Gauge("ok", "help", 1, Label{Name: "__name__", Value: "bad"}),
		Gauge("ok", "help", 1, Label{Name: "group", Value: "a"}, Label{Name: "group", Value: "b"}),
		{Name: "ok", Type: "summary", Help: "unsupported"},
		{Name: "ok", Type: "gauge", Samples: []Sample{{Suffix: "_bucket", Value: 1}}},
	} {
		if _, err := Encode([]Family{f}); err == nil {
			t.Fatal("invalid exposition accepted")
		}
	}
	if _, err := Encode([]Family{family, family}); err == nil {
		t.Fatal("duplicate family accepted")
	}
	tooMany := Family{Name: "ok", Help: "too many", Type: "gauge", Samples: make([]Sample, 4097)}
	if _, err := Encode([]Family{tooMany}); err == nil {
		t.Fatal("sample limit not enforced")
	}
}
