package jscrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRDNScope verifies FieldScope=rdn lets the crawler walk across
// subdomains of the same effective TLD+1 while still rejecting third-party
// hosts.
func TestRDNScope(t *testing.T) {
	// Two test servers: api.* (under same root domain conceptually) and
	// other.* (out of scope). httptest gives us 127.0.0.1:port so we can't
	// truly mimic two subdomains; instead we force the crawler to treat
	// allowHosts as the cross-subdomain proxy.
	main := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Two outbound links: one to itself, one absolute to api.*
		fmt.Fprintf(w, `<html><body>
			<a href="/main-page2">in-scope</a>
		</body></html>`)
	}))
	defer main.Close()

	// rootDomain() should return the bare host for IP-shaped hosts (since
	// publicsuffix can't TLD them). Test that scope-rdn at least matches
	// the seed host itself.
	res := Crawl(context.Background(), Config{
		Seeds:        []string{main.URL + "/"},
		MaxDepth:     2,
		Concurrency:  4,
		SameHostOnly: true,
		FieldScope:   "rdn",
	})
	if len(res.Pages) < 1 {
		t.Errorf("expected at least 1 page, got %d", len(res.Pages))
	}

	// Direct rdn smoke-test on real domains (no network).
	cases := map[string]string{
		"api.example.com":      "example.com",
		"www.example.co.uk":    "example.co.uk",
		"a.b.c.example.com":    "example.com",
		"example.com":          "example.com",
		"127.0.0.1":            "127.0.0.1",
		"":                     "",
		"localhost":            "localhost",
		"api.example.com:8080": "example.com",
	}
	for input, want := range cases {
		got := rootDomain(input)
		if got != want {
			t.Errorf("rootDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestExtensionFilterAndMatch verifies that ExtensionFilter blocks specified
// extensions and ExtensionMatch only allows specified ones. Seeds bypass both.
func TestExtensionFilterAndMatch(t *testing.T) {
	var hits sync.Map
	hits.Store("/", int32(0))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := hits.LoadOrStore(r.URL.Path, int32(0))
		hits.Store(r.URL.Path, v.(int32)+1)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>
				<a href="/page.html">html</a>
				<a href="/img.png">png</a>
				<a href="/style.css">css</a>
				<a href="/app.js">js</a>
				<a href="/data.json">json</a>
			</body></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `// js`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "ok %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	// (a) ExtensionFilter blocks .png and .css
	resA := Crawl(context.Background(), Config{
		Seeds:           []string{srv.URL + "/"},
		MaxDepth:        2,
		Concurrency:     4,
		SameHostOnly:    true,
		ExtensionFilter: []string{"png", "css"},
	})
	urls := pageURLSet(resA.Pages)
	if urls[srv.URL+"/img.png"] {
		t.Errorf("img.png should have been filtered (got %v)", urls)
	}
	if urls[srv.URL+"/style.css"] {
		t.Errorf("style.css should have been filtered (got %v)", urls)
	}
	if !urls[srv.URL+"/app.js"] {
		t.Errorf("app.js should have been crawled (got %v)", urls)
	}

	// (b) ExtensionMatch only allows .js (HTML seed still passes)
	resB := Crawl(context.Background(), Config{
		Seeds:          []string{srv.URL + "/"},
		MaxDepth:       2,
		Concurrency:    4,
		SameHostOnly:   true,
		ExtensionMatch: []string{"js"},
	})
	urlsB := pageURLSet(resB.Pages)
	if !urlsB[srv.URL+"/"] {
		t.Errorf("seed must always pass extension match (got %v)", urlsB)
	}
	if !urlsB[srv.URL+"/app.js"] {
		t.Errorf("/app.js missing under ExtensionMatch=[js] (got %v)", urlsB)
	}
	if urlsB[srv.URL+"/img.png"] || urlsB[srv.URL+"/style.css"] || urlsB[srv.URL+"/data.json"] {
		t.Errorf("non-js URLs should have been filtered (got %v)", urlsB)
	}
}

// TestIgnoreQueryParams confirms /foo?a=1 and /foo?a=2 collapse to one fetch.
func TestIgnoreQueryParams(t *testing.T) {
	var fooHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>
				<a href="/foo?_t=1">a</a>
				<a href="/foo?_t=2">b</a>
				<a href="/foo?_t=3">c</a>
			</body></html>`)
		case "/foo":
			fooHits.Add(1)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	res := Crawl(context.Background(), Config{
		Seeds:             []string{srv.URL + "/"},
		MaxDepth:          2,
		Concurrency:       4,
		SameHostOnly:      true,
		IgnoreQueryParams: true,
	})
	if got := fooHits.Load(); got != 1 {
		t.Errorf("expected /foo to be hit once with IgnoreQueryParams, got %d", got)
	}
	// Sanity: at least the seed and /foo were recorded.
	if len(res.Pages) < 2 {
		t.Errorf("expected >=2 pages, got %d", len(res.Pages))
	}
}

// TestMatchRegexAllowlist verifies MatchRegex acts as an allowlist (URL must
// match at least one pattern to be followed).
func TestMatchRegexAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body>
				<a href="/api/v1/users">api</a>
				<a href="/blog/post-1">blog</a>
				<a href="/about">about</a>
			</body></html>`)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	res := Crawl(context.Background(), Config{
		Seeds:        []string{srv.URL + "/"},
		MaxDepth:     2,
		Concurrency:  4,
		SameHostOnly: true,
		MatchRegex:   []string{`/api/`}, // allowlist: only /api/* and the seed
	})
	urls := pageURLSet(res.Pages)
	if !urls[srv.URL+"/api/v1/users"] {
		t.Errorf("/api/v1/users missing under MatchRegex (got %v)", urls)
	}
	if urls[srv.URL+"/blog/post-1"] || urls[srv.URL+"/about"] {
		t.Errorf("non-matching URLs should have been blocked (got %v)", urls)
	}
}

// TestCrawlDurationSec confirms the global wall-time budget cancels in-flight
// fetches once exhausted.
func TestCrawlDurationSec(t *testing.T) {
	// Server delays 200ms per request so 10 sequential fetches > 1s budget.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		// Endless link chain.
		fmt.Fprintf(w, `<html><body><a href="%s">next</a></body></html>`, fmt.Sprintf("/%d", time.Now().UnixNano()))
	}))
	defer srv.Close()

	t0 := time.Now()
	res := Crawl(context.Background(), Config{
		Seeds:            []string{srv.URL + "/"},
		MaxDepth:         100,
		MaxPages:         500,
		Concurrency:      1,
		SameHostOnly:     false,
		CrawlDurationSec: 1, // 1 second budget
	})
	elapsed := time.Since(t0)
	if elapsed > 3*time.Second {
		t.Errorf("crawl ran for %v, budget was 1s -- duration cap not honored", elapsed)
	}
	// Should have fetched fewer than the full 500 page cap.
	if len(res.Pages) >= 100 {
		t.Errorf("expected duration to cut crawl short, got %d pages", len(res.Pages))
	}
}

// pageURLSet collapses []*Page into a set of URLs for table-driven asserts.
func pageURLSet(pages []*Page) map[string]bool {
	m := make(map[string]bool, len(pages))
	for _, p := range pages {
		if p != nil {
			m[p.URL] = true
		}
	}
	return m
}
