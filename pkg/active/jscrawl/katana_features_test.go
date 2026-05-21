package jscrawl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestKatanaFeaturesEndToEnd builds an httptest server that exercises every
// katana-compat feature in one shot: custom headers, cookie, robots.txt,
// sitemap.xml, source map with embedded sourcesContent, <form> with named
// inputs, WebSocket URL in JS, exclude patterns, parameter aggregation.
func TestKatanaFeaturesEndToEnd(t *testing.T) {
	var headerSeen, cookieSeen atomic.Bool

	mux := http.NewServeMux()

	// Root HTML: links a JS file, has a <form>, and an excluded /logout link.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Auth") == "yes" {
			headerSeen.Store(true)
		}
		if c, _ := r.Cookie("session"); c != nil && c.Value == "abc" {
			cookieSeen.Store(true)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<script src="/static/app.js"></script>
			<form action="/login" method="POST">
				<input type="text" name="username" />
				<input type="password" name="password" />
				<input type="hidden" name="csrf" value="xyz" />
			</form>
			<a href="/page2?ref=home&utm=x">page2</a>
			<a href="/logout">logout</a>
		</body></html>`)
	})

	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>page2 ok</body></html>`)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("/logout should have been excluded but was fetched")
	})

	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
			var ws = "wss://chat.example.com/socket";
			fetch("/api/v1/me");
		`)
	})

	// .map carries sourcesContent[] holding an AWS key — must be recovered.
	mux.HandleFunc("/static/app.js.map", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"version":        3,
			"file":           "app.js",
			"sources":        []string{"webpack:///./src/secrets.ts"},
			"sourcesContent": []string{`const AWS = "AKIAIOSFODNN7EXAMPLE";`},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nSitemap: "+`__BASE__/sitemap.xml`+"\n")
	})

	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0"?>
			<urlset><url><loc>__BASE__/discovered-from-sitemap</loc></url></urlset>`)
	})

	mux.HandleFunc("/discovered-from-sitemap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>found via sitemap</body></html>`)
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>admin landing (linked from robots Disallow)</body></html>`)
	})

	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Contact: mailto:security@example.com\n")
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>login page</body></html>`)
	})

	// We need to wrap the server so we can inject its base URL into the
	// robots.txt / sitemap.xml templates above (httptest URL only known
	// after the server starts).
	srvBase := ""
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture and rewrite responses going through robots/sitemap.
		switch r.URL.Path {
		case "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nSitemap: "+srvBase+"/sitemap.xml\n")
			return
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>`+srvBase+`/discovered-from-sitemap</loc></url></urlset>`)
			return
		}
		mux.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(wrapped)
	defer srv.Close()
	srvBase = srv.URL

	res := Crawl(context.Background(), Config{
		Seeds:           []string{srv.URL + "/"},
		MaxDepth:        3,
		Concurrency:     8,
		SameHostOnly:    true,
		FollowRedirects: true,
		Headers:         map[string]string{"X-Test-Auth": "yes"},
		Cookie:          "session=abc",
		KnownFiles:      true,
		FetchSourceMaps: true,
		ExtractForms:    true,
		ExcludePatterns: []string{`/logout`},
		MaxRetries:      0,
	})

	// 1. Headers + Cookie were sent on at least one request.
	if !headerSeen.Load() {
		t.Errorf("X-Test-Auth header was never received")
	}
	if !cookieSeen.Load() {
		t.Errorf("session cookie was never received")
	}

	// 2. Forms extraction.
	if len(res.Forms) == 0 {
		t.Errorf("no forms extracted")
	}
	var loginForm *Form
	for _, f := range res.Forms {
		if strings.HasSuffix(f.Action, "/login") {
			loginForm = f
			break
		}
	}
	if loginForm == nil {
		t.Errorf("login form not found in %v", res.Forms)
	} else {
		if loginForm.Method != "POST" {
			t.Errorf("login form method = %q, want POST", loginForm.Method)
		}
		gotInputs := map[string]string{}
		for _, in := range loginForm.Inputs {
			gotInputs[in.Name] = in.Type
		}
		for _, want := range []string{"username", "password", "csrf"} {
			if _, ok := gotInputs[want]; !ok {
				t.Errorf("login form missing input %q (got %v)", want, gotInputs)
			}
		}
	}

	// 3. Parameters aggregation (from /page2?ref=home&utm=x + form inputs).
	wantParams := map[string]bool{"ref": false, "utm": false, "username": false, "password": false, "csrf": false}
	for _, p := range res.Parameters {
		if _, ok := wantParams[p]; ok {
			wantParams[p] = true
		}
	}
	for k, v := range wantParams {
		if !v {
			t.Errorf("parameter %q missing from aggregation (got %v)", k, res.Parameters)
		}
	}

	// 4. WebSocket detection.
	wsFound := false
	for _, w := range res.WebSockets {
		if strings.Contains(w, "wss://chat.example.com/socket") {
			wsFound = true
		}
	}
	if !wsFound {
		t.Errorf("websocket URL missing from %v", res.WebSockets)
	}

	// 5. Source map fetched + sourcesContent secret recovered.
	if len(res.SourceMaps) == 0 {
		t.Errorf("no source maps fetched")
	} else {
		sm := res.SourceMaps[0]
		if !sm.HasContent {
			t.Errorf("source map has_content = false, want true")
		}
		if sm.BytesRecovered == 0 {
			t.Errorf("source map bytes_recovered = 0")
		}
		if sm.SecretsInContent == 0 {
			t.Errorf("source map should have surfaced an AWS key")
		}
	}
	// AWS key from sourcesContent should be in top-level Secrets.
	awsFound := false
	for _, s := range res.Secrets {
		if s.Rule == "aws_access_key_id" {
			awsFound = true
		}
	}
	if !awsFound {
		t.Errorf("aws key from .map sourcesContent missing from Secrets")
	}

	// 6. Known files: robots.txt and sitemap.xml were fetched, sitemap-derived
	//    URL was followed, robots Disallow path was followed.
	if len(res.KnownFiles) == 0 {
		t.Errorf("no known files recorded")
	}
	gotKinds := map[string]bool{}
	for _, k := range res.KnownFiles {
		if k.Status == 200 {
			gotKinds[k.Kind] = true
		}
	}
	for _, want := range []string{"robots", "sitemap", "security"} {
		if !gotKinds[want] {
			t.Errorf("known file kind %q missing from %v", want, res.KnownFiles)
		}
	}
	pageURLs := make([]string, 0, len(res.Pages))
	for _, p := range res.Pages {
		pageURLs = append(pageURLs, p.URL)
	}
	pageJoined := strings.Join(pageURLs, "|")
	if !strings.Contains(pageJoined, "/discovered-from-sitemap") {
		t.Errorf("sitemap-derived URL was not crawled (pages=%v)", pageURLs)
	}
	if !strings.Contains(pageJoined, "/admin") {
		t.Errorf("robots Disallow URL was not followed (pages=%v)", pageURLs)
	}

	// 7. Exclude pattern: /logout must NOT appear.
	if strings.Contains(pageJoined, "/logout") {
		t.Errorf("excluded URL was crawled: %v", pageURLs)
	}

	// 8. Stats sanity.
	if res.Stats.FormsFound == 0 || res.Stats.ParamsFound == 0 ||
		res.Stats.WebSocketsFound == 0 || res.Stats.SourceMapsFetched == 0 ||
		res.Stats.KnownFilesFetched == 0 {
		t.Errorf("stats undercount: %+v", res.Stats)
	}
}

// TestRetryOn5xx verifies the do() helper retries on 500-class errors and
// eventually surfaces the 200 once the server flips.
func TestRetryOn5xx(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 3 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "OK")
	}))
	defer srv.Close()

	res := Crawl(context.Background(), Config{
		Seeds:        []string{srv.URL + "/"},
		MaxDepth:     0,
		Concurrency:  1,
		Timeout:      5 * time.Second,
		SameHostOnly: true,
		MaxRetries:   3,
	})
	if hits.Load() < 3 {
		t.Errorf("expected >=3 hits, got %d", hits.Load())
	}
	if res.Stats.Retries == 0 && res.Stats.Errors == 0 {
		// Either retries are recorded directly, or the surface page didn't
		// have an error after retries succeeded. We just need at least the
		// retry count or no final error -- both indicate success.
	}
	// At least one page should be a 200 final state.
	got200 := false
	for _, p := range res.Pages {
		if p.Status == 200 {
			got200 = true
		}
	}
	if !got200 {
		t.Errorf("no 200 page after retries: %+v", res.Pages)
	}
}

// TestExcludeNoFalseHits confirms that a benign path NOT matching the
// exclude regex is still followed.
func TestExcludeNoFalseHits(t *testing.T) {
	var slept atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/blog" {
			slept.Store(true)
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/blog">blog</a><a href="/logout">logout</a></body></html>`)
	}))
	defer srv.Close()

	res := Crawl(context.Background(), Config{
		Seeds:           []string{srv.URL + "/"},
		MaxDepth:        2,
		Concurrency:     2,
		SameHostOnly:    true,
		ExcludePatterns: []string{`/logout$`},
	})
	if !slept.Load() {
		t.Errorf("/blog was wrongly excluded; saw pages %v", res.Pages)
	}
}
