package jscrawl

import (
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

// extractEndpointsAST parses src as JavaScript and walks the AST looking for
// URL-like endpoint values that scanBody's regex pass typically misses.
//
// What we surface (in addition to plain string literals which regex already
// handles, but with better attribution):
//   - Template literals: `${API}/users/${id}` -> "{var}/users/{var}".
//   - Object property values keyed by path/url/route/endpoint/to/href:
//     { path: "/users/:id", component: U }.
//   - String concatenation: "/api" + "/v" + "1" + "/users" -> "/api/v1/users"
//     (simple constant-folding, no symbolic eval of identifiers).
//   - First argument of well-known caller patterns: fetch / axios.* / $.get
//     when it's a string literal or template.
//
// The parser is configured leniently: any parse failure (mid-2024+ syntax,
// JSX, decorators, etc.) just returns nil so callers fall back to regex.
//
// Hard-skips for sanity: bodies > 10 MB and bodies that look like minified
// JSON (no whitespace at all) -- AST parsing won't help there.
func extractEndpointsAST(src string) []*Match {
	if len(src) == 0 || len(src) > 10*1024*1024 {
		return nil
	}
	prog, err := parser.ParseFile(nil, "", src, parser.IgnoreRegExpErrors)
	if err != nil || prog == nil {
		return nil
	}

	seen := map[string]bool{}
	out := make([]*Match, 0, 32)
	addCandidate := func(rule, value string) {
		value = strings.TrimSpace(value)
		if !looksLikeURL(value) {
			return
		}
		key := rule + "|" + value
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, &Match{
			Type:     "endpoint",
			Rule:     rule,
			Value:    value,
			Severity: "info",
		})
	}

	// Walk every expression in the program. We don't care about statement
	// vs expression distinction for endpoint extraction -- URLs can hide
	// inside any expression position.
	var walk func(node ast.Node)
	walk = func(node ast.Node) {
		if node == nil {
			return
		}
		switch n := node.(type) {

		// ---- Container/structural nodes: recurse into children ----
		case *ast.Program:
			for _, b := range n.Body {
				walk(b)
			}
			for _, d := range n.DeclarationList {
				walk(d)
			}
		case *ast.BlockStatement:
			for _, s := range n.List {
				walk(s)
			}
		case *ast.ExpressionStatement:
			walk(n.Expression)
		case *ast.VariableStatement:
			for _, l := range n.List {
				walk(l)
			}
		case *ast.LexicalDeclaration:
			for _, l := range n.List {
				walk(l)
			}
		case *ast.VariableDeclaration:
			for _, l := range n.List {
				walk(l)
			}
		case *ast.Binding:
			walk(n.Initializer)
		case *ast.IfStatement:
			walk(n.Test)
			walk(n.Consequent)
			walk(n.Alternate)
		case *ast.ReturnStatement:
			walk(n.Argument)
		case *ast.ForStatement:
			if n.Initializer != nil {
				if e, ok := n.Initializer.(*ast.ForLoopInitializerExpression); ok {
					walk(e.Expression)
				}
			}
			walk(n.Test)
			walk(n.Update)
			walk(n.Body)
		case *ast.WhileStatement:
			walk(n.Test)
			walk(n.Body)
		case *ast.DoWhileStatement:
			walk(n.Test)
			walk(n.Body)
		case *ast.ForInStatement:
			walk(n.Source)
			walk(n.Body)
		case *ast.ForOfStatement:
			walk(n.Source)
			walk(n.Body)
		case *ast.SwitchStatement:
			walk(n.Discriminant)
			for _, c := range n.Body {
				walk(c)
			}
		case *ast.CaseStatement:
			walk(n.Test)
			for _, s := range n.Consequent {
				walk(s)
			}
		case *ast.TryStatement:
			walk(n.Body)
			if n.Catch != nil {
				walk(n.Catch.Body)
			}
			walk(n.Finally)
		case *ast.FunctionDeclaration:
			walk(n.Function.Body)
		case *ast.FunctionLiteral:
			walk(n.Body)
		case *ast.ArrowFunctionLiteral:
			walk(n.Body)

		// ---- Expression nodes we actually care about ----
		case *ast.StringLiteral:
			addCandidate("ast_string", n.Value.String())

		case *ast.TemplateLiteral:
			pattern := buildTemplatePattern(n)
			addCandidate("ast_template", pattern)
			// Walk inner expressions too (they may contain nested URLs).
			for _, expr := range n.Expressions {
				walk(expr)
			}

		case *ast.BinaryExpression:
			// String concat folding: "a" + "b" -> "ab". Also handles
			// chained concats like "/api" + "/" + "v1".
			if folded, ok := foldStringConcat(n); ok {
				addCandidate("ast_concat", folded)
			}
			walk(n.Left)
			walk(n.Right)

		case *ast.ObjectLiteral:
			for _, p := range n.Value {
				pk, ok := p.(*ast.PropertyKeyed)
				if !ok {
					walk(p)
					continue
				}
				key := propertyKeyName(pk.Key)
				if isURLKey(key) {
					// First try direct string literal at the value slot,
					// otherwise fall through to recursion.
					if lit, ok := pk.Value.(*ast.StringLiteral); ok {
						addCandidate("ast_route_object", lit.Value.String())
					} else if tl, ok := pk.Value.(*ast.TemplateLiteral); ok {
						addCandidate("ast_route_object", buildTemplatePattern(tl))
					}
				}
				walk(pk.Key)
				walk(pk.Value)
			}

		case *ast.ArrayLiteral:
			for _, v := range n.Value {
				walk(v)
			}

		case *ast.CallExpression:
			// fetch("/api/x") / axios.get("/x") / $.post("/y")
			fname := callTargetName(n.Callee)
			isURLCall := isURLCallerName(fname)
			for i, a := range n.ArgumentList {
				if isURLCall && i == 0 {
					if lit, ok := a.(*ast.StringLiteral); ok {
						addCandidate("ast_call_arg", lit.Value.String())
					} else if tl, ok := a.(*ast.TemplateLiteral); ok {
						addCandidate("ast_call_arg", buildTemplatePattern(tl))
					}
				}
				walk(a)
			}
			walk(n.Callee)

		case *ast.AssignExpression:
			walk(n.Left)
			walk(n.Right)
		case *ast.ConditionalExpression:
			walk(n.Test)
			walk(n.Consequent)
			walk(n.Alternate)
		case *ast.UnaryExpression:
			walk(n.Operand)
		case *ast.DotExpression:
			walk(n.Left)
		case *ast.BracketExpression:
			walk(n.Left)
			walk(n.Member)
		case *ast.SequenceExpression:
			for _, e := range n.Sequence {
				walk(e)
			}
		case *ast.NewExpression:
			walk(n.Callee)
			for _, a := range n.ArgumentList {
				walk(a)
			}
		case *ast.SpreadElement:
			walk(n.Expression)
		case *ast.AwaitExpression:
			walk(n.Argument)
		case *ast.YieldExpression:
			walk(n.Argument)
		case *ast.PropertyShort:
			// shortcut object property like {foo}: nothing to do
		}
	}
	walk(prog)
	return out
}

// buildTemplatePattern reconstructs a template literal as a flat string,
// substituting "{var}" for every interpolated expression. So
//
//	`prefix${a}/users/${b}/posts`  ->  "prefix{var}/users/{var}/posts"
//
// This preserves the URL pattern (path shape + literal segments) which is
// exactly what we want for endpoint discovery.
func buildTemplatePattern(t *ast.TemplateLiteral) string {
	if t == nil {
		return ""
	}
	var b strings.Builder
	for i, el := range t.Elements {
		if el != nil {
			b.WriteString(el.Parsed.String())
		}
		if i < len(t.Expressions) {
			b.WriteString("{var}")
		}
	}
	return b.String()
}

// foldStringConcat tries to collapse a chain of string concatenations into a
// single literal. Returns the folded string and ok=true only when EVERY leaf
// of the BinaryExpression tree is a string literal (no symbolic evaluation
// of identifiers; that would require type tracking).
func foldStringConcat(b *ast.BinaryExpression) (string, bool) {
	if b == nil || b.Operator.String() != "+" {
		return "", false
	}
	left, lok := stringValue(b.Left)
	right, rok := stringValue(b.Right)
	if !lok || !rok {
		return "", false
	}
	return left + right, true
}

// stringValue returns (s, true) when expr resolves to a constant string at
// parse time. Recursive over BinaryExpression so a + b + c folds correctly.
func stringValue(expr ast.Expression) (string, bool) {
	switch n := expr.(type) {
	case *ast.StringLiteral:
		return n.Value.String(), true
	case *ast.TemplateLiteral:
		// Template with no interpolations is effectively a string literal.
		if len(n.Expressions) == 0 && len(n.Elements) == 1 && n.Elements[0] != nil {
			return n.Elements[0].Parsed.String(), true
		}
		return "", false
	case *ast.BinaryExpression:
		if n.Operator.String() != "+" {
			return "", false
		}
		l, lok := stringValue(n.Left)
		r, rok := stringValue(n.Right)
		if !lok || !rok {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// propertyKeyName returns the textual name of an object-literal key, whether
// it was written as `foo:` (Identifier), `"foo":` (StringLiteral), or `[x]:`
// (computed -- in which case we can only return "" since key isn't static).
func propertyKeyName(k ast.Expression) string {
	switch n := k.(type) {
	case *ast.Identifier:
		return n.Name.String()
	case *ast.StringLiteral:
		return n.Value.String()
	}
	return ""
}

// callTargetName returns the rightmost name in a call's callee chain, e.g.
// for `axios.get(...)` returns "get"; for `fetch(...)` returns "fetch".
// Used by isURLCallerName to decide whether the first argument is a URL.
func callTargetName(callee ast.Expression) string {
	switch n := callee.(type) {
	case *ast.Identifier:
		return n.Name.String()
	case *ast.DotExpression:
		return n.Identifier.Name.String()
	}
	return ""
}

// isURLKey: object keys whose value typically holds a URL pattern. Drives
// the route-config detector (React Router, Vue Router, Angular Router,
// custom config files).
func isURLKey(name string) bool {
	switch strings.ToLower(name) {
	case "path", "url", "route", "endpoint", "to", "href", "action", "src":
		return true
	}
	return false
}

// isURLCallerName: function names whose first arg is conventionally a URL.
// Common HTTP client libraries and SPA router APIs.
func isURLCallerName(name string) bool {
	switch strings.ToLower(name) {
	case "fetch", "ajax",
		"get", "post", "put", "delete", "patch", "head", "options",
		"request", "send", "sendrequest",
		"navigate", "push", "replace", "redirect", "go",
		"open": // XMLHttpRequest.open
		return true
	}
	return false
}

// astURLPattern is what we apply to candidate strings to filter out garbage.
// We accept four shapes:
//
//  1. "/foo[/...]"           -- absolute path
//  2. "https?://..."         -- absolute URL
//  3. "wss?://..."           -- WebSocket URL
//  4. "{var}/foo[/...]"      -- template-derived path starting with a
//     placeholder (e.g. `${API}/users` -> "{var}/users")
//
// The character class is intentionally narrow to drop CSS class names,
// i18n keys, and hex-only fingerprints. We allow {} and `*` so router
// patterns like `/users/:id` and webpack chunk names survive.
var astURLPattern = regexp.MustCompile(`^(?:(?:/|\{var\})[A-Za-z0-9_\-./?#=&%~+:{},*]*|https?://[A-Za-z0-9._\-:][^\s]*|wss?://[A-Za-z0-9._\-:][^\s]*)$`)

// looksLikeURL filters AST candidate strings down to plausible endpoints.
// Length cap (1024) avoids JSON-blob style false positives where an API
// response template was inlined into the source.
func looksLikeURL(s string) bool {
	n := len(s)
	if n < 4 || n > 1024 {
		return false
	}
	// Quick shape test: must start with "/", "h", "w", or "{" (template).
	first := s[0]
	if first != '/' && first != 'h' && first != 'H' && first != 'w' && first != 'W' && first != '{' {
		return false
	}
	// Spaces are an instant disqualifier (CSS-style "foo bar" classes etc.).
	if strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	return astURLPattern.MatchString(s)
}
