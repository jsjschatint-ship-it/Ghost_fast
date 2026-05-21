// Package subdomain provides active subdomain brute-force discovery.
//
// Given a root domain (e.g. "example.com") it concurrently issues DNS A
// queries for `<word>.<root>` across a curated wordlist, detects and filters
// wildcard DNS sinkholes, rotates across multiple public resolvers, and
// returns the deduplicated set of live subdomains with their resolved IPs.
//
// Design choices:
//   - stdlib net.Resolver only; no new third-party dependencies.
//   - Per-resolver isolation: each query routes to one resolver chosen
//     round-robin, so a single slow resolver cannot block the whole run.
//   - Wildcard detection probes 5 random labels before bruteforcing; any
//     answer whose A-set is a subset of the wildcard A-set is dropped.
package subdomain

import (
	"time"

	"github.com/wgpsec/ENScan/pkg/models"
)

// defaultResolvers are public DNS servers used when Config.Resolvers is empty.
// Mixed CN + international for better diversity and coverage.
var defaultResolvers = []string{
	"8.8.8.8:53",        // Google
	"1.1.1.1:53",        // Cloudflare
	"9.9.9.9:53",        // Quad9
	"223.5.5.5:53",      // AliDNS
	"119.29.29.29:53",   // DNSPod
	"208.67.222.222:53", // OpenDNS
}

// Config tunes the brute forcer. Zero value gets sane defaults via Normalize.
type Config struct {
	// Wordlist is the explicit list of label prefixes to try. If empty, the
	// embedded default top-5k SecLists wordlist is used.
	Wordlist []string `json:"wordlist" yaml:"wordlist"`
	// WordlistPath, if set, overrides the embedded default; the file is read
	// at Run time (one label per line, # comments stripped).
	WordlistPath string `json:"wordlist_path" yaml:"wordlist_path"`
	// Resolvers is the list of "host:port" DNS server addresses. Defaults to
	// defaultResolvers (Google, Cloudflare, Quad9, AliDNS, DNSPod, OpenDNS).
	Resolvers []string `json:"resolvers" yaml:"resolvers"`
	// Concurrency is the maximum number of in-flight DNS queries.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// Timeout is per-query timeout.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// SkipWildcard disables wildcard detection. Use with caution.
	SkipWildcard bool `json:"skip_wildcard" yaml:"skip_wildcard"`
	// WildcardProbes controls how many random labels are queried to detect
	// wildcard DNS. Defaults to 5.
	WildcardProbes int `json:"wildcard_probes" yaml:"wildcard_probes"`
	// RetryPerQuery is the number of retries on transient DNS failures.
	RetryPerQuery int `json:"retry_per_query" yaml:"retry_per_query"`
	// IncludeRoot, when true, also queries the root domain itself.
	IncludeRoot bool `json:"include_root" yaml:"include_root"`
}

// Normalize fills in defaults for unset fields.
func (c *Config) Normalize() {
	if c.Concurrency <= 0 {
		c.Concurrency = 100
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if len(c.Resolvers) == 0 {
		c.Resolvers = append([]string(nil), defaultResolvers...)
	}
	if c.WildcardProbes <= 0 {
		c.WildcardProbes = 5
	}
	if c.RetryPerQuery < 0 {
		c.RetryPerQuery = 0
	}
}

// Result describes a single discovered subdomain.
type Result struct {
	// Name is the FQDN that resolved.
	Name string `json:"name"`
	// IPs are the resolved A/AAAA addresses (deduped, sorted).
	IPs []string `json:"ips,omitempty"`
	// CNAME is the canonical name if the response contained one.
	CNAME string `json:"cname,omitempty"`
	// Resolver records which DNS server returned the answer.
	Resolver string `json:"resolver,omitempty"`
	// Wildcard is true when the answer matched the detected wildcard set.
	// Such results are normally filtered before being returned, but the field
	// is preserved so callers can opt in to inspect them.
	Wildcard bool `json:"wildcard,omitempty"`
}

// ToAsset converts the result to a *models.Asset for session storage.
func (r *Result) ToAsset() *models.Asset {
	a := models.NewAsset()
	a.Domain = r.Name
	a.Host = r.Name
	if len(r.IPs) > 0 {
		a.IP = r.IPs[0]
	}
	a.Source = "subdomain_brute"
	a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
	if r.CNAME != "" || len(r.IPs) > 1 {
		raw := map[string]string{}
		if r.CNAME != "" {
			raw["cname"] = r.CNAME
		}
		if len(r.IPs) > 1 {
			raw["ips"] = joinComma(r.IPs)
		}
		if r.Resolver != "" {
			raw["resolver"] = r.Resolver
		}
		a.Raw = raw
	}
	return a
}

// joinComma joins strings with comma without importing strings (keeps types.go
// tiny and dependency-free).
func joinComma(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	n := len(parts) - 1
	for _, p := range parts {
		n += len(p)
	}
	buf := make([]byte, 0, n)
	for i, p := range parts {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, p...)
	}
	return string(buf)
}
