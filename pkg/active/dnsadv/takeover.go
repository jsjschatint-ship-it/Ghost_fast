package dnsadv

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// checkTakeovers concurrently inspects each subdomain for dangling CNAMEs that
// match a known takeover signature. Returned slice contains one entry per
// non-empty match (vulnerable OR informational) sorted by Subdomain.
func checkTakeovers(ctx context.Context, subdomains []string, cfg *Config) []*TakeoverResult {
	cfg.Normalize()
	subdomains = dedupLower(subdomains)
	if len(subdomains) == 0 {
		return nil
	}

	client := &http.Client{
		Timeout: cfg.TakeoverHTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: cfg.TakeoverHTTPTimeout,
			DialContext: (&net.Dialer{
				Timeout: cfg.TakeoverHTTPTimeout,
			}).DialContext,
		},
		// Cap redirects to avoid follow-loops into cloud provider error pages.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	results := make([]*TakeoverResult, 0)
	var mu sync.Mutex
	gate := make(chan struct{}, cfg.TakeoverConcurrency)
	var wg sync.WaitGroup
	for _, sub := range subdomains {
		select {
		case <-ctx.Done():
			break
		default:
		}
		sub := sub
		wg.Add(1)
		gate <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-gate }()
			r := inspectOne(ctx, sub, client, cfg.IncludeUnvulnerable)
			if r != nil {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Subdomain < results[j].Subdomain })
	return results
}

// inspectOne returns a TakeoverResult if the subdomain has a CNAME matching
// one of takeoverSigs AND the HTTP probe body contains the corresponding
// fingerprint. Non-matches return nil (we don't pollute the result set with
// every clean subdomain — callers can deduce coverage from the input list).
//
// When includeUnvulnerable is true, signatures with Vulnerable=false also
// surface for visibility (dangling CNAME at GCS, etc.).
func inspectOne(ctx context.Context, subdomain string, client *http.Client, includeUnvulnerable bool) *TakeoverResult {
	cname, err := lookupCNAMEChain(ctx, subdomain)
	if err != nil || cname == "" {
		return nil
	}
	cnameLow := strings.ToLower(cname)

	// First filter by CNAME suffix — much faster than fetching HTTP every time.
	var matched *takeoverSig
	for i := range takeoverSigs {
		for _, m := range takeoverSigs[i].CNAMEMatch {
			if strings.Contains(cnameLow, strings.ToLower(m)) {
				matched = &takeoverSigs[i]
				break
			}
		}
		if matched != nil {
			break
		}
	}
	if matched == nil {
		return nil
	}
	if !matched.Vulnerable && !includeUnvulnerable {
		return nil
	}

	// HTTP probe — try https first, fall back to http on TLS error. Some
	// dangling SaaS endpoints respond on either or both schemes.
	status, body, httpErr := probeOnce(ctx, client, "https://"+subdomain)
	if httpErr != nil || status == 0 {
		status, body, httpErr = probeOnce(ctx, client, "http://"+subdomain)
	}

	result := &TakeoverResult{
		Subdomain:  subdomain,
		CNAME:      strings.TrimSuffix(cname, "."),
		Service:    matched.Service,
		Vulnerable: matched.Vulnerable,
		HTTPStatus: status,
		Doc:        matched.Doc,
	}
	if httpErr != nil {
		result.Err = httpErr.Error()
	}
	for _, needle := range matched.HTTPMatch {
		if strings.Contains(body, needle) {
			result.Evidence = needle
			return result
		}
	}
	// CNAME matched but HTTP fingerprint didn't — still surface the dangling
	// CNAME as an informational signal (caller may want to investigate).
	result.Vulnerable = false
	result.Evidence = "" // no body confirmation
	if !includeUnvulnerable {
		// Default behaviour: do not return CNAME-only hits to avoid noise.
		return nil
	}
	return result
}

// probeOnce performs one HTTP GET and returns status + body string + error.
// Body is capped to 16 KB; that's plenty for the SaaS error fingerprints.
func probeOnce(ctx context.Context, client *http.Client, url string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "ghost-dnsadv/1.0 (+takeover detector)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return resp.StatusCode, string(body), err
	}
	return resp.StatusCode, string(body), nil
}

// lookupCNAMEChain returns the final hop of the CNAME chain for `name`, or ""
// when there is no CNAME or the lookup fails. Go's net.LookupCNAME already
// follows the chain via the system resolver, so we don't need to walk it
// manually.
func lookupCNAMEChain(ctx context.Context, name string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cname, err := net.DefaultResolver.LookupCNAME(cctx, name)
	if err != nil {
		return "", err
	}
	cname = strings.TrimSuffix(cname, ".")
	// LookupCNAME returns the queried name verbatim when the host has no CNAME.
	if strings.EqualFold(cname, name) {
		return "", nil
	}
	return cname, nil
}

// dedupLower returns a lowercased, trimmed, order-preserving deduplicated copy.
func dedupLower(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
