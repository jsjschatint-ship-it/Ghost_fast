package portscan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestParseRange validates the textual port-spec parser.
func TestParseRange(t *testing.T) {
	cases := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"80", []int{80}, false},
		{"80,443", []int{80, 443}, false},
		{"8000-8003", []int{8000, 8001, 8002, 8003}, false},
		{"80, 80, 80,443 ; 8000-8001", []int{80, 443, 8000, 8001}, false},
		{"abc", nil, true},
		{"0-100", nil, true},
		{"100-50", nil, true},
		{"99999", nil, true},
	}
	for _, tc := range cases {
		got, err := ParseRange(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseRange(%q) expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRange(%q) err: %v", tc.in, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("ParseRange(%q) len=%d want %d (%v)", tc.in, len(got), len(tc.want), got)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("ParseRange(%q)[%d]=%d want %d", tc.in, i, got[i], tc.want[i])
				break
			}
		}
	}
}

// TestEmbeddedPortLists ensures both port-list embeds load with expected counts.
func TestEmbeddedPortLists(t *testing.T) {
	if got := parsePortFile(defaultTop100); len(got) < 90 || len(got) > 110 {
		t.Errorf("top100 size unexpected: %d", len(got))
	}
	if got := parsePortFile(defaultTop1000); len(got) < 990 || len(got) > 1010 {
		t.Errorf("top1000 size unexpected: %d", len(got))
	}
}

// TestSplitHostExtraPort covers IPv4, IPv6, host:port, URL and bare host.
func TestSplitHostExtraPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"example.com", "example.com", 0},
		{"example.com:8080", "example.com", 8080},
		{"https://example.com:8443/path", "example.com", 8443},
		{"http://example.com/foo", "example.com", 0},
		{"127.0.0.1", "127.0.0.1", 0},
		{"127.0.0.1:22", "127.0.0.1", 22},
		{"[::1]:443", "::1", 443},
	}
	for _, tc := range cases {
		h, p := splitHostExtraPort(tc.in)
		if h != tc.host || p != tc.port {
			t.Errorf("splitHostExtraPort(%q) = (%q,%d); want (%q,%d)", tc.in, h, p, tc.host, tc.port)
		}
	}
}

// TestScanLoopback launches a real TCP listener on a random port and verifies
// the scanner finds it. Skipped if the OS cannot bind to localhost (rare).
func TestScanLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer ln.Close()
	// Echo back a fixed banner immediately so the banner-grab path is exercised.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("TESTBANNER\r\n"))
		_ = conn.Close()
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	s := New(Config{
		Ports:              []int{port, port + 1}, // open + likely-closed
		Concurrency:        4,
		PerHostConcurrency: 4,
		Timeout:            500 * time.Millisecond,
		RetryTimeout:       1 * time.Second,
		RetryPerPort:       0,
		GrabBanner:         true,
		BannerTimeout:      500 * time.Millisecond,
		SkipResolve:        true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := s.Run(ctx, []string{"127.0.0.1"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("expected at least one open port, got none")
	}
	found := false
	for _, r := range results {
		if r.Port == port {
			found = true
			if !strings.Contains(r.Banner, "TESTBANNER") {
				t.Errorf("expected banner to contain TESTBANNER, got %q", r.Banner)
			}
			if r.IP != "127.0.0.1" {
				t.Errorf("expected IP=127.0.0.1, got %q", r.IP)
			}
			if r.Attempts != 1 {
				t.Errorf("expected attempts=1, got %d", r.Attempts)
			}
		}
	}
	if !found {
		t.Errorf("did not detect listener on port %d. results: %+v", port, results)
	}
	// Sanity: total port count matches  Config.Ports.
	for _, r := range results {
		if r.Port != port {
			t.Errorf("unexpected open port %d (only %d should be listening)", r.Port, port)
		}
	}
	_ = strconv.Itoa(port) // keep strconv import used regardless
}
