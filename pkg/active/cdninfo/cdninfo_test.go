package cdninfo

import (
	"testing"
)

// TestClassifyHeaders_Cloudflare verifies multi-signal detection: both
// `cf-ray` and `server: cloudflare` should fire (same vendor, distinct keys).
func TestClassifyHeaders_Cloudflare(t *testing.T) {
	h := map[string]string{
		"cf-ray":          "1234567890abcdef-LAX",
		"server":          "cloudflare",
		"cf-cache-status": "HIT",
	}
	hits := classifyHeaders(h)
	if len(hits) < 2 {
		t.Fatalf("expected ≥2 hits, got %v", hits)
	}
	for _, h := range hits {
		if h.Vendor != "cloudflare" {
			t.Errorf("unexpected vendor %q", h.Vendor)
		}
		if h.Source != "header" {
			t.Errorf("unexpected source %q", h.Source)
		}
	}
}

// TestClassifyHeaders_Aliyun ensures we catch 国内 CDN by `via` header.
func TestClassifyHeaders_Aliyun(t *testing.T) {
	h := map[string]string{
		"via":     "cache27.l2et2[140,200-0,M], cache49.l2et2[141,0], alicdn",
		"eagleid": "abc-def",
	}
	hits := classifyHeaders(h)
	gotAliyun := 0
	for _, h := range hits {
		if h.Vendor == "aliyun_cdn" {
			gotAliyun++
		}
	}
	if gotAliyun < 1 {
		t.Errorf("aliyun_cdn not detected, hits=%v", hits)
	}
}

// TestClassifyCNAME covers the CNAME-substring path.
func TestClassifyCNAME(t *testing.T) {
	cases := map[string]string{
		"foo.cloudfront.net": "aws_cloudfront",
		"x.akamaiedge.net":   "akamai",
		"x.wsdvs.com":        "wangsu",
		"abc.kunlunca.com":   "aliyun_cdn",
		"x.b-cdn.net":        "bunnycdn",
	}
	for cname, want := range cases {
		hits := classifyCNAME([]string{cname})
		if len(hits) == 0 {
			t.Errorf("no hit for %q", cname)
			continue
		}
		found := false
		for _, h := range hits {
			if h.Vendor == want {
				found = true
			}
		}
		if !found {
			t.Errorf("CNAME %q → expected %q, got %v", cname, want, hits)
		}
	}
}

// TestRegistrableRoot covers the eTLD+1 heuristic.
func TestRegistrableRoot(t *testing.T) {
	cases := map[string]string{
		"www.example.com":            "example.com",
		"a.b.c.example.com":          "example.com",
		"www.example.co.uk":          "example.co.uk",
		"foo.bar.www.example.com.cn": "example.com.cn",
		"example.com":                "example.com",
	}
	for in, want := range cases {
		if got := registrableRoot(in); got != want {
			t.Errorf("registrableRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGetCanonical case-insensitive header lookup.
func TestGetCanonical(t *testing.T) {
	h := map[string]string{"Cf-Ray": "abc", "Server": "nginx"}
	if v, ok := getCanonical(h, "cf-ray"); !ok || v != "abc" {
		t.Errorf("getCanonical case-insensitive failed: %q ok=%v", v, ok)
	}
	if _, ok := getCanonical(h, "x-nope"); ok {
		t.Error("expected miss")
	}
}

// TestNoVendorsForPlainNginx — must not yield false-positive Cloudflare on
// a plain nginx response. (The detector is very sensitive; this is the
// regression guardrail.)
func TestNoVendorsForPlainNginx(t *testing.T) {
	h := map[string]string{"Server": "nginx/1.18.0"}
	if hits := classifyHeaders(h); len(hits) != 0 {
		t.Errorf("plain nginx should have 0 vendor hits, got %v", hits)
	}
}

func TestPassiveHackerTargetCandidates(t *testing.T) {
	body := "www.example.com,203.0.113.10\nmail.example.com,203.0.113.11\nbad-line\n"
	got := hackerTargetCandidates(body, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(got))
	}
	if got[0].Source != "hackertarget_hostsearch" || got[0].Label != "www.example.com" || got[0].IPs[0] != "203.0.113.10" {
		t.Fatalf("unexpected first candidate: %+v", got[0])
	}
}

func TestPassiveThreatMinerCandidates(t *testing.T) {
	body := `{"results":[{"domain":"old.example.com","ip":"203.0.113.20"},{"host":"api.example.com","ip_address":"203.0.113.21"}]}`
	got := threatMinerCandidates("example.com", body, 10)
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(got))
	}
	if got[1].Label != "api.example.com" || got[1].IPs[0] != "203.0.113.21" {
		t.Fatalf("unexpected second candidate: %+v", got[1])
	}
}

func TestDedupOriginCandidatesMergesIPs(t *testing.T) {
	in := []*OriginCandidate{
		{Source: "history", Label: "Old.Example.Com.", IPs: []string{"203.0.113.1"}},
		{Source: "history", Label: "old.example.com", IPs: []string{"203.0.113.1", "203.0.113.2"}},
	}
	got := dedupOriginCandidates(in)
	if len(got) != 1 {
		t.Fatalf("expected one merged candidate, got %d", len(got))
	}
	if len(got[0].IPs) != 2 {
		t.Fatalf("expected merged IPs, got %+v", got[0].IPs)
	}
}
