package jscrawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestScanBodyHitsRules feeds a fixture body containing several known
// patterns and verifies each rule fires. This is the unit-level coverage
// for patterns.go without requiring network IO.
func TestScanBodyHitsRules(t *testing.T) {
	githubToken := "ghp_" + strings.Repeat("a", 36)
	stripeToken := strings.Join([]string{"sk", "live", "abcdefghij1234567890abcdefghij"}, "_")
	body := fmt.Sprintf(`
		var awsKey = "AKIAIOSFODNN7EXAMPLE";
		var googleKey = "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz0123456";
		var ghToken = "%s";
		var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
		var slackHook = "https://hooks.slack.com/services/T12345678/B12345678/abcdefghij1234567890ab";
		var stripe = "%s";
		var apiPath = "/api/v2/users/me";
		var url = "https://api.example.com/internal/orders";
		//# sourceMappingURL=app.js.map
	`, githubToken, stripeToken)
	matches := scanBody(body)
	if len(matches) < 6 {
		t.Fatalf("expected >=6 matches, got %d:\n%v", len(matches), matchesToStr(matches))
	}
	want := map[string]bool{
		"aws_access_key_id": false,
		"google_api_key":    false,
		"github_token":      false,
		"jwt":               false,
		"slack_webhook":     false,
		"stripe_live_key":   false,
		"api_path":          false,
		"absolute_url":      false,
		"source_map":        false,
	}
	for _, m := range matches {
		if _, ok := want[m.Rule]; ok {
			want[m.Rule] = true
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("rule %s did not fire", k)
		}
	}
}

// TestRedaction confirms secret values are masked in the middle.
func TestRedaction(t *testing.T) {
	got := maybeRedact("secret", "AKIAIOSFODNN7EXAMPLE")
	if !strings.HasPrefix(got, "AKIA") || !strings.HasSuffix(got, "MPLE") || !strings.Contains(got, "***") {
		t.Errorf("expected masked, got %q", got)
	}
	if maybeRedact("endpoint", "https://example.com/api") != "https://example.com/api" {
		t.Errorf("endpoints must not be redacted")
	}
}

// TestExtractReferencesHTML covers the goquery branch.
func TestExtractReferencesHTML(t *testing.T) {
	html := `<html><head>
		<script src="/static/app.js"></script>
		<script src="https://cdn.example.com/lib.js"></script>
		<link rel="modulepreload" href="/static/chunk-abc.js">
		</head><body>
		<a href="/about">About</a>
		<a href="https://other.com/foo">External</a>
		</body></html>`
	refs := extractReferences("https://my.test/", html, "text/html")
	if len(refs) < 4 {
		t.Fatalf("expected >=4 refs, got %d: %v", len(refs), refs)
	}
	joined := strings.Join(refs, "|")
	for _, want := range []string{"https://my.test/static/app.js", "https://cdn.example.com/lib.js", "https://my.test/about"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing ref %q in %v", want, refs)
		}
	}
}

// TestCrawlIntegration spins up an httptest server with one HTML page that
// links a JS file containing a fake AWS key, runs Crawl, and verifies the
// secret bubbles to the aggregated Result.Secrets.
func TestCrawlIntegration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><script src="/app.js"></script></body></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `var k = "AKIAIOSFODNN7EXAMPLE"; fetch("/api/v1/users");`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Crawl(context.Background(), Config{
		Seeds:        []string{srv.URL + "/"},
		MaxDepth:     2,
		Concurrency:  4,
		SameHostOnly: true,
	})
	if len(res.Pages) != 2 {
		t.Errorf("expected 2 pages, got %d", len(res.Pages))
	}
	if res.Stats.SecretsFound == 0 {
		t.Errorf("expected at least 1 secret, got 0")
	}
	if res.Stats.EndpointsFound == 0 {
		t.Errorf("expected at least 1 endpoint, got 0")
	}
	foundAWS := false
	for _, s := range res.Secrets {
		if s.Rule == "aws_access_key_id" {
			foundAWS = true
			break
		}
	}
	if !foundAWS {
		t.Errorf("aws_access_key_id missing from %v", res.Secrets)
	}
}

func matchesToStr(m []*Match) string {
	parts := make([]string, len(m))
	for i, x := range m {
		parts[i] = fmt.Sprintf("%s/%s=%s", x.Type, x.Rule, x.Value)
	}
	return strings.Join(parts, ", ")
}
