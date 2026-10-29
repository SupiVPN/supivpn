// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// SPDX-License-Identifier: AGPL-3.0-only

package metrics

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"strings"
)

type Label struct{ Name, Value string }
type Sample struct {
	Suffix string
	Labels []Label
	Value  float64
}
type Family struct {
	Name, Help, Type string
	Samples          []Sample
}

func Gauge(name, help string, value float64, labels ...Label) Family {
	return Family{Name: name, Help: help, Type: "gauge", Samples: []Sample{{Labels: labels, Value: value}}}
}

// Encode emits the Prometheus text 0.0.4 subset used by SupiVPN. Names are
// internal constants; escaping label values prevents newlines/quotes in a
// configured group name from introducing additional samples. No timestamps,
// exemplars, summaries, negotiation or compression are implemented.
func Encode(families []Family) ([]byte, error) {
	var b bytes.Buffer
	names := map[string]bool{}
	count := 0
	for _, f := range families {
		if !validName(f.Name, false) || names[f.Name] || len(f.Help) > 1024 {
			return nil, errors.New("invalid metric family")
		}
		names[f.Name] = true
		if f.Type != "gauge" && f.Type != "counter" && f.Type != "histogram" {
			return nil, errors.New("invalid metric type")
		}
		b.WriteString("# HELP " + f.Name + " " + escape(f.Help, false) + "\n# TYPE " + f.Name + " " + f.Type + "\n")
		for _, s := range f.Samples {
			count++
			if count > 4096 || len(s.Labels) > 4 || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) {
				return nil, errors.New("invalid metric sample")
			}
			if (f.Type != "histogram" && s.Suffix != "") || (f.Type == "histogram" && s.Suffix != "_bucket" && s.Suffix != "_count" && s.Suffix != "_sum") {
				return nil, errors.New("invalid metric suffix")
			}
			b.WriteString(f.Name + s.Suffix)
			if len(s.Labels) > 0 {
				b.WriteByte('{')
				labelNames := map[string]bool{}
				for i, l := range s.Labels {
					if !validName(l.Name, true) || strings.HasPrefix(l.Name, "__") || labelNames[l.Name] || len(l.Value) > 256 {
						return nil, errors.New("invalid metric label")
					}
					labelNames[l.Name] = true
					if i > 0 {
						b.WriteByte(',')
					}
					b.WriteString(l.Name + "=\"" + escape(l.Value, true) + "\"")
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(strconv.FormatFloat(s.Value, 'g', -1, 64))
			b.WriteByte('\n')
			if b.Len() > 512<<10 {
				return nil, errors.New("metrics response too large")
			}
		}
	}
	return b.Bytes(), nil
}

func validName(s string, label bool) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, c := range []byte(s) {
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || !label && c == ':' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func escape(s string, label bool) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\n", "\\n")
	if label {
		s = strings.ReplaceAll(s, "\"", "\\\"")
	}
	return s
}
