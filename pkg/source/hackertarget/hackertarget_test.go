package hackertarget

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeServer wires the three relevant API paths to canned responses.
func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/hostsearch/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "www.%s,1.2.3.4\napi.%s,1.2.3.5\nmail.%s,1.2.3.6\n", q, q, q)
	})
	mux.HandleFunc("/reverseiplookup/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "site-a.example\nsite-b.example\n")
	})
	mux.HandleFunc("/findshareddns/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "neighbor1.example\nneighbor2.example\n")
	})
	mux.HandleFunc("/ratelimited/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "API count exceeded - usage exceeds 100 calls per day")
	})
	return httptest.NewServer(mux)
}

func TestHostSearch(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()
	s := NewHackerTarget()
	s.SetBaseURL(srv.URL)

	assets, err := s.Search(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 subdomain assets, got %d", len(assets))
	}
	if !strings.HasPrefix(assets[0].Host, "www.") {
		t.Errorf("unexpected host: %q", assets[0].Host)
	}
	// hostsearch must populate the IP field from the CSV second column.
	if assets[0].IP != "1.2.3.4" {
		t.Errorf("IP not parsed: %q", assets[0].IP)
	}
}

func TestReverseAndShared(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()
	s := NewHackerTarget()
	s.SetBaseURL(srv.URL)

	assets, err := s.Search(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	// 2 reverseDNS + 2 sharedHosts = 4
	if len(assets) != 4 {
		t.Fatalf("expected 4 assets for IP target, got %d", len(assets))
	}
	for _, a := range assets {
		if a.IP != "8.8.8.8" {
			t.Errorf("IP not propagated: %q", a.IP)
		}
	}
}

func TestRateLimitDetection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/hostsearch/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "API count exceeded - usage exceeds 100 calls per day")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := NewHackerTarget()
	s.SetBaseURL(srv.URL)
	// rate limit body must be detected as an error → no assets returned, no panic
	assets, err := s.Search(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Search swallows internal errs and returns nil: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected 0 assets on rate limit, got %d", len(assets))
	}
}

func TestAcceptsAndKey(t *testing.T) {
	s := NewHackerTarget()
	if s.NeedsKey() {
		t.Error("NeedsKey() should be false")
	}
	a := s.Accepts()
	if len(a) != 2 {
		t.Errorf("Accepts() = %v, want 2 entries", a)
	}
}

func TestEmptyTargetRejected(t *testing.T) {
	s := NewHackerTarget()
	_, err := s.Search(context.Background(), "  ")
	if err == nil {
		t.Error("expected error on empty target")
	}
}

func TestIsIP(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":     true,
		"::1":         true,
		"example.com": false,
		"not-an-ip":   false,
		"":            false,
	}
	for in, want := range cases {
		if got := isIP(in); got != want {
			t.Errorf("isIP(%q) = %v, want %v", in, got, want)
		}
	}
}
