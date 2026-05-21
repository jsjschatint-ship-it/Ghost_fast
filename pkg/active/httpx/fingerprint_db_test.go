package httpx

import (
	"net/http"
	"testing"
)

// TestFingerprintDBLoad sanity-checks that the embedded databases parse and
// produce a non-trivial rule count. We don't pin an exact number (upstream
// data files churn), only assert it is in a plausible range.
func TestFingerprintDBLoad(t *testing.T) {
	d := db()
	if d == nil {
		t.Fatal("db() returned nil")
	}
	got := len(d.rules)
	if got < 500 {
		t.Fatalf("expected >=500 compiled rules, got %d (embed broken?)", got)
	}
	t.Logf("loaded %d compiled fingerprint rules", got)

	// Count by origin for quick visibility.
	counts := map[string]int{}
	for _, r := range d.rules {
		counts[r.origin]++
	}
	for k, v := range counts {
		t.Logf("  origin=%-12s rules=%d", k, v)
	}
}

// TestNginxFingerprint verifies the simplest header rule matches: any response
// with `Server: nginx` should yield "Nginx" or "nginx" in the matched product list.
func TestNginxFingerprint(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.20.1")
	hits := matchFingerprints(h, []byte("<html></html>"), "", "")
	if !containsCI(hits, "nginx") {
		t.Errorf("expected nginx-like product in matches, got %v", hits)
	}
}

// TestWordPressFingerprint validates the WordPress body rule.
func TestWordPressFingerprint(t *testing.T) {
	body := []byte(`<html><head><link href="/wp-content/themes/twentytwentyfour/style.css"></head></html>`)
	hits := matchFingerprints(http.Header{}, body, "", "")
	if !containsCI(hits, "wordpress") {
		t.Errorf("expected WordPress match, got %v", hits)
	}
}

func containsCI(haystack []string, needle string) bool {
	for _, s := range haystack {
		if equalFold(s, needle) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
