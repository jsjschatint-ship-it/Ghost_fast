package dnsadv

import (
	"context"
	"strings"
	"testing"
)

// TestSignaturesShape sanity-checks that every signature in the curated table
// has a non-empty service name + at least one CNAME match string + at least
// one HTTP fingerprint string.
func TestSignaturesShape(t *testing.T) {
	if len(takeoverSigs) < 20 {
		t.Fatalf("expected >=20 takeover signatures, got %d", len(takeoverSigs))
	}
	for i, sig := range takeoverSigs {
		if sig.Service == "" {
			t.Errorf("sig[%d] has empty Service", i)
		}
		if len(sig.CNAMEMatch) == 0 {
			t.Errorf("sig[%d/%s] has no CNAMEMatch entries", i, sig.Service)
		}
		if len(sig.HTTPMatch) == 0 {
			t.Errorf("sig[%d/%s] has no HTTPMatch entries", i, sig.Service)
		}
		for _, m := range sig.CNAMEMatch {
			if strings.TrimSpace(m) == "" {
				t.Errorf("sig[%d/%s] has empty CNAMEMatch", i, sig.Service)
			}
		}
	}
}

// TestDedupLower covers the helper used both for input cleanup and result
// stability.
func TestDedupLower(t *testing.T) {
	in := []string{"FOO.com", " bar.com ", "foo.com", "", "BAR.COM"}
	out := dedupLower(in)
	if len(out) != 2 || out[0] != "foo.com" || out[1] != "bar.com" {
		t.Errorf("unexpected: %v", out)
	}
}

// TestConfigNormalize verifies default values.
func TestConfigNormalize(t *testing.T) {
	c := Config{}
	c.Normalize()
	if c.Mode != "both" {
		t.Errorf("expected Mode=both, got %q", c.Mode)
	}
	if c.AXFRTimeout <= 0 {
		t.Errorf("AXFRTimeout default not applied")
	}
	if c.TakeoverConcurrency <= 0 {
		t.Errorf("TakeoverConcurrency default not applied")
	}
	if len(c.Resolvers) == 0 {
		t.Errorf("Resolvers default not applied")
	}
}

// TestScannerModeMissingDomain covers the takeover-only path: when mode is
// "takeover" and no subdomains are supplied, Scan should produce an empty
// result without panicking.
func TestScannerModeMissingDomain(t *testing.T) {
	s := New(Config{Mode: "takeover"})
	r := s.Scan(context.Background(), "", nil)
	if r == nil {
		t.Fatal("nil result")
	}
	if len(r.AXFR) != 0 || len(r.Takeovers) != 0 {
		t.Errorf("expected empty result, got AXFR=%d takeovers=%d", len(r.AXFR), len(r.Takeovers))
	}
}
