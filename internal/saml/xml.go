// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/beevik/etree"
)

const dsNamespace = "http://www.w3.org/2000/09/xmldsig#"
const exclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
const xmlNamespace = "http://www.w3.org/XML/1998/namespace"
const maxXMLBytes = 1 << 20

var errSAML = errors.New("invalid or unsupported SAML")
var xmlName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// CheckXML bounds work before DOM allocation and rejects ambiguous attributes,
// DTDs, processing instructions and XML constructs outside our SSO subset.
// Only UTF-8 XML is accepted. Literal whitespace inside attribute values is
// refused (numeric character references remain supported).
func CheckXML(data []byte) error {
	if len(data) == 0 || len(data) > maxXMLBytes {
		return errSAML
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	depth, roots, elements, tokens, attrs := 0, 0, 0, 0, 0
	for {
		start := d.InputOffset()
		t, err := d.Token()
		if err == io.EOF {
			if depth != 0 || roots != 1 {
				return errSAML
			}
			return nil
		}
		if err != nil {
			return errSAML
		}
		tokens++
		if tokens > 4096 {
			return errSAML
		}
		switch v := t.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			elements++
			attrs += len(v.Attr)
			if roots > 1 || depth > 64 || elements > 512 || attrs > 4096 || len(v.Attr) > 64 {
				return errSAML
			}
			seen := map[xml.Name]bool{}
			for _, a := range v.Attr {
				if seen[a.Name] {
					return errSAML
				}
				seen[a.Name] = true
			}
			var quote byte
			for _, b := range data[start:d.InputOffset()] {
				if quote != 0 {
					if b == quote {
						quote = 0
					} else if b == '\t' || b == '\n' || b == '\r' {
						return errSAML
					}
				} else if b == '\'' || b == '"' {
					quote = b
				}
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return errSAML
		case xml.ProcInst:
			if v.Target != "xml" || start != 0 || roots != 0 {
				return errSAML
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(v)) != 0 {
				return errSAML
			}
		}
	}
}
func parseXML(data []byte) (*etree.Element, error) {
	if err := CheckXML(data); err != nil {
		return nil, err
	}
	d := etree.NewDocument()
	d.ReadSettings.MaxDepth = 64
	d.ReadSettings.PreserveDuplicateAttrs = true
	d.ReadSettings.ValidateInput = true
	// CheckXML validates the original document first. etree's ValidateInput
	// rejects even whitespace after the root; trimming outside-root whitespace
	// cannot change the signed subtree or its canonical representation.
	if err := d.ReadFromBytes(bytes.TrimSpace(data)); err != nil {
		return nil, errors.New("invalid XML DOM")
	}
	root := d.Root()
	if root == nil {
		return nil, errSAML
	}
	ids := map[string]bool{}
	var walk func(*etree.Element, map[string]string) error
	walk = func(e *etree.Element, parent map[string]string) error {
		ns, err := namespaces(e, parent)
		if err != nil {
			return errors.New("invalid XML namespace declaration")
		}
		if !xmlName.MatchString(e.Tag) || (e.Space != "" && (!xmlName.MatchString(e.Space) || ns[e.Space] == "")) {
			return errors.New("invalid XML element name")
		}
		seen := map[string]bool{}
		for _, a := range e.Attr {
			if isNS(a) {
				continue
			}
			// encoding/xml matches struct attributes by local name. Do not let a
			// prefixed protocol attribute shadow the unqualified signed attribute.
			if a.Space != "" && !(ns[a.Space] == xmlNamespace && (a.Key == "lang" || a.Key == "space")) &&
				!(ns[a.Space] == "http://www.w3.org/2001/XMLSchema-instance" && (a.Key == "type" || a.Key == "nil" || a.Key == "schemaLocation")) {
				return errors.New("unsupported namespaced XML attribute")
			}
			if !xmlName.MatchString(a.Key) || (a.Space != "" && (!xmlName.MatchString(a.Space) || ns[a.Space] == "")) {
				return errors.New("invalid XML attribute name")
			}
			key := a.Key
			if a.Space != "" {
				key = ns[a.Space] + "|" + key
			}
			if seen[key] {
				return errors.New("duplicate XML attribute")
			}
			seen[key] = true
			if strings.EqualFold(a.Key, "id") {
				if a.Value == "" || !xmlName.MatchString(a.Value) || ids[a.Value] {
					return errors.New("invalid or duplicate XML ID")
				}
				ids[a.Value] = true
			}
		}
		for _, c := range e.ChildElements() {
			if err := walk(c, ns); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, map[string]string{"xml": xmlNamespace}); err != nil {
		return nil, err
	}
	return root, nil
}
func isNS(a etree.Attr) bool { return a.Space == "xmlns" || a.Space == "" && a.Key == "xmlns" }
func cloneNS(m map[string]string) map[string]string {
	n := make(map[string]string, len(m)+2)
	for k, v := range m {
		n[k] = v
	}
	return n
}
func namespaces(e *etree.Element, parent map[string]string) (map[string]string, error) {
	n := cloneNS(parent)
	seen := map[string]bool{}
	for _, a := range e.Attr {
		if !isNS(a) {
			continue
		}
		prefix := a.Key
		if a.Space == "" {
			prefix = ""
		}
		if seen[prefix] || prefix == "xmlns" || (prefix != "" && !xmlName.MatchString(prefix)) ||
			a.Value == "http://www.w3.org/2000/xmlns/" || (prefix == "xml") != (a.Value == xmlNamespace) {
			return nil, errSAML
		}
		if a.Value != "" {
			u, err := url.Parse(a.Value)
			if err != nil || !u.IsAbs() {
				return nil, errSAML
			}
		} else if prefix != "" {
			return nil, errSAML
		}
		seen[prefix] = true
		n[prefix] = a.Value
	}
	return n, nil
}
func parentNS(e *etree.Element) (map[string]string, error) {
	var path []*etree.Element
	for p := e.Parent(); p != nil; p = p.Parent() {
		path = append(path, p)
	}
	ns := map[string]string{"xml": xmlNamespace}
	var err error
	for i := len(path) - 1; i >= 0; i-- {
		ns, err = namespaces(path[i], ns)
		if err != nil {
			return nil, err
		}
	}
	return ns, nil
}
func namespace(e *etree.Element) string {
	if e == nil {
		return ""
	}
	ns, err := parentNS(e)
	if err != nil {
		return ""
	}
	ns, err = namespaces(e, ns)
	if err != nil {
		return ""
	}
	return ns[e.Space]
}
func named(e *etree.Element, ns, local string) bool {
	return e != nil && e.Tag == local && namespace(e) == ns
}
func children(e *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element
	if e != nil {
		for _, c := range e.ChildElements() {
			if named(c, ns, local) {
				out = append(out, c)
			}
		}
	}
	return out
}
func one(e *etree.Element, ns, local string) (*etree.Element, error) {
	es := children(e, ns, local)
	if len(es) != 1 {
		return nil, errSAML
	}
	return es[0], nil
}
func attribute(e *etree.Element, name string) string {
	if e != nil {
		for _, a := range e.Attr {
			if a.Space == "" && a.Key == name {
				return a.Value
			}
		}
	}
	return ""
}
func textValue(e *etree.Element) (string, error) {
	if e == nil || len(e.ChildElements()) != 0 {
		return "", errSAML
	}
	var s strings.Builder
	for _, t := range e.Child {
		if c, ok := t.(*etree.CharData); ok {
			s.WriteString(c.Data)
		}
	}
	return s.String(), nil
}
func onlyChildren(e *etree.Element, allowed map[string]int) error {
	counts := map[string]int{}
	for _, t := range e.Child {
		switch c := t.(type) {
		case *etree.Element:
			key := namespace(c) + "|" + c.Tag
			max, ok := allowed[key]
			counts[key]++
			if !ok || (max > 0 && counts[key] > max) {
				return errSAML
			}
		case *etree.CharData:
			if strings.TrimSpace(c.Data) != "" {
				return errSAML
			}
		}
	}
	return nil
}
func allowed(ns string, names ...string) map[string]int {
	m := map[string]int{}
	for _, name := range names {
		m[ns+"|"+name] = 1
	}
	return m
}
func escaped(s string, attr bool) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;")
	if attr {
		r = strings.NewReplacer("&", "&amp;", "<", "&lt;", "\"", "&quot;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")
	}
	return r.Replace(s)
}

// canonicalize implements only Exclusive XML C14N 1.0 without comments, over a
// complete subtree, optionally excluding exactly the enveloped Signature node.
// It never mutates or detaches the tree. In-scope and rendered namespaces are
// separate maps; a child's declarations cannot leak into a sibling.
func canonicalize(root, omit *etree.Element, prefixes string) ([]byte, error) {
	scope, err := parentNS(root)
	if err != nil {
		return nil, err
	}
	inclusive := map[string]bool{}
	for _, p := range strings.Fields(prefixes) {
		if p == "#default" {
			p = ""
		} else if !xmlName.MatchString(p) {
			return nil, errSAML
		}
		inclusive[p] = true
	}
	var out bytes.Buffer
	var visit func(*etree.Element, map[string]string, map[string]string, int) error
	visit = func(e *etree.Element, parent, rendered map[string]string, depth int) error {
		if e == omit {
			return nil
		}
		if depth > 64 {
			return errSAML
		}
		ns, err := namespaces(e, parent)
		if err != nil {
			return err
		}
		visible := map[string]bool{e.Space: true}
		for p := range inclusive {
			if _, ok := ns[p]; ok {
				visible[p] = true
			}
		}
		attrs := []etree.Attr{}
		for _, a := range e.Attr {
			if !isNS(a) {
				attrs = append(attrs, a)
				if a.Space != "" {
					visible[a.Space] = true
				}
			}
		}
		next := cloneNS(rendered)
		decl := []string{}
		for p := range visible {
			if p == "xml" {
				continue
			}
			v := ns[p]
			if p != "" && v == "" {
				return errSAML
			}
			if rendered[p] != v {
				decl = append(decl, p)
				next[p] = v
			}
		}
		sort.Strings(decl)
		q := e.Tag
		if e.Space != "" {
			q = e.Space + ":" + q
		}
		out.WriteString("<" + q)
		for _, p := range decl {
			name := "xmlns"
			if p != "" {
				name += ":" + p
			}
			out.WriteString(" " + name + "=\"" + escaped(ns[p], true) + "\"")
		}
		sort.Slice(attrs, func(i, j int) bool {
			uri := func(a etree.Attr) string {
				if a.Space == "" {
					return ""
				}
				return ns[a.Space]
			}
			a, b := uri(attrs[i]), uri(attrs[j])
			if a != b {
				return a < b
			}
			return attrs[i].Key < attrs[j].Key
		})
		for _, a := range attrs {
			name := a.Key
			if a.Space != "" {
				name = a.Space + ":" + name
			}
			out.WriteString(" " + name + "=\"" + escaped(a.Value, true) + "\"")
		}
		out.WriteByte('>')
		for _, t := range e.Child {
			switch c := t.(type) {
			case *etree.Element:
				if err := visit(c, ns, next, depth+1); err != nil {
					return err
				}
			case *etree.CharData:
				out.WriteString(escaped(c.Data, false))
			case *etree.Comment:
			default:
				return errSAML
			}
			if out.Len() > 4*maxXMLBytes {
				return errSAML
			}
		}
		out.WriteString("</" + q + ">")
		return nil
	}
	err = visit(root, scope, map[string]string{"xml": xmlNamespace}, 1)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
