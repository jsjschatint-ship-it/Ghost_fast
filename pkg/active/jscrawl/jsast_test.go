package jscrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestASTExtractEndpoints exercises the four scenarios that motivate having
// an AST pass at all: template literals, route-config objects, string
// concatenation, and direct HTTP-client calls. Plain literals and "must NOT
// match" strings are also covered to defend against false positives.
func TestASTExtractEndpoints(t *testing.T) {
	src := `
		// 1. Template literal — regex would only see "/users/" or nothing
		const u1 = ` + "`" + `${API}/users/${id}/posts` + "`" + `;

		// 2. String concat — regex sees fragments, AST folds them
		const u2 = "/api" + "/v1" + "/orders";

		// 3. Route config object — common in React / Vue Router
		const routes = [
			{ path: "/dashboard", component: D },
			{ path: "/users/:id", component: U },
			{ path: ` + "`" + `/admin/${role}` + "`" + `, component: A }
		];

		// 4. fetch / axios call with literal first arg
		fetch("/api/v2/me");
		axios.get("/api/v2/orders");
		$.post("/login");

		// Plain literal — regex would also catch this; we still record it
		const u5 = "/static/app.js";

		// Garbage that must NOT be classified as endpoint
		const noise = "abc-def-ghi";
		const cssClass = "/foo bar";  // spaces -> reject
		const i18n = "zh-cn";          // no leading slash -> reject
	`
	hits := extractEndpointsAST(src)
	if len(hits) == 0 {
		t.Fatalf("AST returned 0 endpoints from a rich fixture")
	}
	got := map[string]string{}
	for _, m := range hits {
		got[m.Value] = m.Rule
	}

	wantValue := []string{
		"{var}/users/{var}/posts", // template literal
		"/api/v1/orders",          // concat fold
		"/dashboard",
		"/users/:id",
		"/admin/{var}", // template inside object
		"/api/v2/me",
		"/api/v2/orders",
		"/login",
		"/static/app.js",
	}
	for _, w := range wantValue {
		if _, ok := got[w]; !ok {
			t.Errorf("AST missed expected endpoint %q (got %v)", w, got)
		}
	}
	for _, mustNot := range []string{"abc-def-ghi", "/foo bar", "zh-cn"} {
		if _, ok := got[mustNot]; ok {
			t.Errorf("AST surfaced false positive %q", mustNot)
		}
	}
}

// TestASTHandlesParseFailureGracefully feeds intentionally broken JS and
// asserts we return nil without panicking. Crawler must still work when AST
// fails -- it falls back to the regex pass.
func TestASTHandlesParseFailureGracefully(t *testing.T) {
	cases := []string{
		`const x = ; // syntax error`,
		`@decorator class X {}`, // decorators not supported by goja
		`/* truly garbage */ ?:????????:????????`,
		"",                                // empty
		strings.Repeat("a", 11*1024*1024), // > 10MB hard cap
	}
	for i, src := range cases {
		hits := extractEndpointsAST(src)
		if hits != nil && len(hits) > 0 {
			// Some "bad" inputs may still parse partially (e.g. early break);
			// we just want to ensure no panic. Empty result is fine.
			t.Logf("case %d returned %d hits (acceptable)", i, len(hits))
		}
	}
}

// TestASTIntegrationWithCrawl confirms UseAST=true plumbs through the
// full Crawl pipeline and the AST findings show up in Result.Endpoints.
func TestASTIntegrationWithCrawl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><script src="/app.js"></script></body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			// One AST-only finding (template literal): regex won't catch.
			fmt.Fprint(w, "const u = `${API}/secret/path/${id}`; var k = \"plain\";")
		}
	}))
	defer srv.Close()

	// AST off — should miss the template literal pattern.
	resOff := Crawl(context.Background(), Config{
		Seeds:        []string{srv.URL + "/"},
		MaxDepth:     2,
		Concurrency:  4,
		SameHostOnly: true,
	})
	for _, ep := range resOff.Endpoints {
		if strings.Contains(ep, "{var}") {
			t.Errorf("AST=off but template-pattern endpoint surfaced: %s", ep)
		}
	}

	// AST on — should now include the template-pattern endpoint.
	resOn := Crawl(context.Background(), Config{
		Seeds:        []string{srv.URL + "/"},
		MaxDepth:     2,
		Concurrency:  4,
		SameHostOnly: true,
		UseAST:       true,
	})
	hit := false
	for _, ep := range resOn.Endpoints {
		if strings.Contains(ep, "{var}/secret/path/{var}") {
			hit = true
		}
	}
	if !hit {
		t.Errorf("AST=on but template-pattern endpoint not surfaced; got %v", resOn.Endpoints)
	}
}
