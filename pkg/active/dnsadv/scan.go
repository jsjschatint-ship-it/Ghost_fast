package dnsadv

import (
	"context"
	"strings"
	"time"
)

// Scanner orchestrates AXFR + takeover probes. Construct once via New, reuse
// across multiple Scan() calls (it holds no per-run state).
type Scanner struct {
	cfg Config
}

// New constructs a Scanner with the supplied config. The config is normalised
// in place; callers can inspect the effective values via Config().
func New(cfg Config) *Scanner {
	cfg.Normalize()
	return &Scanner{cfg: cfg}
}

// Config returns the effective (normalised) configuration.
func (s *Scanner) Config() Config { return s.cfg }

// Scan runs the configured probes against `domain` (with `subdomains` used for
// takeover checks). Empty subdomains in takeover-only mode is a no-op.
//
// AXFR is attempted against `domain` only (not against each subdomain — zone
// transfers are zone-level and authoritative servers don't respond to AXFR
// for non-zone names).
func (s *Scanner) Scan(ctx context.Context, domain string, subdomains []string) *Result {
	domain = strings.TrimSpace(strings.ToLower(domain))
	t0 := time.Now()
	res := &Result{Domain: domain}

	mode := strings.ToLower(strings.TrimSpace(s.cfg.Mode))
	if mode == "" {
		mode = "both"
	}
	doAXFR := domain != "" && (mode == "axfr" || mode == "both")
	doTakeover := len(subdomains) > 0 && (mode == "takeover" || mode == "both")

	if doAXFR {
		res.AXFR = tryAXFR(ctx, domain, s.cfg.Resolvers, s.cfg.AXFRTimeout)
	}
	if doTakeover {
		res.Takeovers = checkTakeovers(ctx, subdomains, &s.cfg)
	}
	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}
