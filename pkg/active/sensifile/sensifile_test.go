package sensifile

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestConfirmEnvFile_PositiveAndNegative pins the dotenv detector logic.
func TestConfirmEnvFile_PositiveAndNegative(t *testing.T) {
	pos := "DB_HOST=localhost\nDB_USER=root\nAPI_KEY=secret"
	if !confirmEnvFile(pos) {
		t.Error("should confirm dotenv body")
	}
	if confirmEnvFile("<html><body>not env</body></html>") {
		t.Error("should reject HTML body")
	}
	if confirmEnvFile("# just a comment\n\n# another") {
		t.Error("should reject comment-only body")
	}
}

// TestConfirmJSONy ensures we accept real JSON and reject HTML-y fallback.
func TestConfirmJSONy(t *testing.T) {
	if !confirmJSONy(`{"a":1}`) {
		t.Error("should accept JSON object")
	}
	if !confirmJSONy(` [1,2]`) {
		t.Error("should accept JSON array with leading space")
	}
	if confirmJSONy(`<html>spa fallback</html>`) {
		t.Error("should reject HTML")
	}
	if confirmJSONy("") {
		t.Error("should reject empty body")
	}
}

// TestScanFindsGitAndEnv: stand up a fake server that exposes /.git/HEAD
// and /.env, plus a 200-fallback for everything else (mimicking an SPA),
// and confirm the scanner reports exactly the two confirmed findings.
func TestScanFindsGitAndEnv(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ref: refs/heads/main\n")
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DB_PASSWORD=hunter2\nSECRET_KEY=zzz\n")
	})
	// catch-all: SPA-style 200 with HTML body
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!DOCTYPE html><html><body>SPA fallback</body></html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Scan(context.Background(), Config{
		BaseURLs: []string{srv.URL},
	})

	// We expect at least the 2 critical/high hits, with no false positives
	// for things like /backup.zip (HTML fallback fails the confirmer).
	if res.Stats.Findings < 2 {
		t.Fatalf("expected ≥2 findings, got %d (probes=%d)", res.Stats.Findings, res.Stats.ProbesSent)
	}
	paths := map[string]string{}
	for _, f := range res.Findings {
		paths[f.Path] = f.Severity
	}
	if paths["/.git/HEAD"] != "high" {
		t.Errorf(".git/HEAD severity = %q, want high", paths["/.git/HEAD"])
	}
	if paths["/.env"] != "critical" {
		t.Errorf(".env severity = %q, want critical", paths["/.env"])
	}
	// No backup.zip should slip through (body is HTML).
	for _, f := range res.Findings {
		if strings.Contains(f.Path, "backup.zip") {
			t.Errorf("false positive on %s — body was SPA HTML", f.Path)
		}
	}
}

// TestScanRespectsMaxBodyBytes verifies the snippet is bounded.
func TestScanRespectsMaxBodyBytes(t *testing.T) {
	long := strings.Repeat("KEY="+strings.Repeat("v", 100)+"\n", 50) // ~5KB
	mux := http.NewServeMux()
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, long)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Scan(context.Background(), Config{
		BaseURLs:     []string{srv.URL},
		MaxBodyBytes: 256,
	})
	if res.Stats.Findings == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range res.Findings {
		if f.BodyLen > 256 {
			t.Errorf("BodyLen=%d, want ≤256", f.BodyLen)
		}
	}
}

// TestScanCustomPaths confirms the cfg.Paths override path.
func TestScanCustomPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/secret/api", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"hello":"world"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Scan(context.Background(), Config{
		BaseURLs: []string{srv.URL},
		Paths:    []string{"/secret/api", "/nope"},
	})
	if res.Stats.PathsPerURL != 2 {
		t.Errorf("expected 2 paths in stats, got %d", res.Stats.PathsPerURL)
	}
	found := false
	for _, f := range res.Findings {
		if f.Path == "/secret/api" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("custom path /secret/api not found; findings=%v", res.Findings)
	}
}
