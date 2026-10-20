// Copyright (c) 2026 Stanislav Kazachkov (SupiVPN).
// Licensed under AGPL-3.0-only. See LICENSE and COPYRIGHT.md.
// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Runtime events are an allowlist: a misspelled name would be dropped. Also
// prevent reintroducing the unstructured standard logger in product sources.
func TestProductionLogCallsUseKnownEvents(t *testing.T) {
	for _, root := range []string{"..", "../../cmd"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(source, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == "logConnection" && len(call.Args) > 1 {
						if lit, ok := call.Args[1].(*ast.BasicLit); ok {
							name, _ := strconv.Unquote(lit.Value)
							if _, ok := events[name]; !ok { t.Errorf("%s: unknown store log event %s", path, name) }
						}
					}
					return true
				}
				pkg, _ := sel.X.(*ast.Ident)
				if pkg != nil && pkg.Name == "log" && sel.Sel.Name != "New" {
					t.Errorf("%s: use the bounded structured logger", path)
				}
				index := -1
				if pkg != nil && pkg.Name == "logging" && sel.Sel.Name == "Emit" {
					index = 1
				}
				if sel.Sel.Name == "logEvent" || sel.Sel.Name == "logTunnelEvent" {
					index = 0
				}
				if index < 0 || len(call.Args) <= index {
					return true
				}
				literal, ok := call.Args[index].(*ast.BasicLit)
				if !ok {
					return true
				} // The logger/agent forwarding helpers are tested separately.
				name, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Error(err)
					return true
				}
				if _, ok := events[name]; !ok {
					t.Errorf("%s: unknown log event %s", path, name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
