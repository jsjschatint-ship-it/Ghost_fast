// Package dnsadv provides advanced DNS reconnaissance:
//   - AXFR zone transfers (try every authoritative NS, return full zone)
//   - Subdomain takeover detection (dangling CNAME → suspended SaaS)
//
// Both features can run independently or as part of a single Scan() call.
// The package depends on github.com/miekg/dns for raw AXFR queries; standard
// A/AAAA/CNAME lookups still use net.Resolver to avoid duplicate DNS code.
package dnsadv

import (
	"time"

	"github.com/wgpsec/ENScan/pkg/models"
)

// Config tunes a Scan run. Zero values trigger sane defaults via Normalize.
type Config struct {
	// Mode selects which probes to run:
	//   "axfr"     — only attempt zone transfers
	//   "takeover" — only check supplied subdomains for takeover
	//   "both"     — do both (default)
	Mode string `json:"mode" yaml:"mode"`
	// AXFRTimeout caps each AXFR TCP query.
	AXFRTimeout time.Duration `json:"axfr_timeout" yaml:"axfr_timeout"`
	// Resolvers is the list of "host:port" DNS server addresses used for NS
	// lookups before the AXFR attempt. Defaults to a public set.
	Resolvers []string `json:"resolvers" yaml:"resolvers"`
	// TakeoverConcurrency caps simultaneous takeover checks.
	TakeoverConcurrency int `json:"takeover_concurrency" yaml:"takeover_concurrency"`
	// TakeoverHTTPTimeout caps each HTTP GET during takeover fingerprinting.
	TakeoverHTTPTimeout time.Duration `json:"takeover_http_timeout" yaml:"takeover_http_timeout"`
	// IncludeUnvulnerable, when true, returns hits for services that match a
	// signature but are flagged "not vulnerable" upstream (informational).
	IncludeUnvulnerable bool `json:"include_unvulnerable" yaml:"include_unvulnerable"`
}

// Normalize fills in defaults.
func (c *Config) Normalize() {
	if c.Mode == "" {
		c.Mode = "both"
	}
	if c.AXFRTimeout <= 0 {
		c.AXFRTimeout = 8 * time.Second
	}
	if c.TakeoverConcurrency <= 0 {
		c.TakeoverConcurrency = 30
	}
	if c.TakeoverHTTPTimeout <= 0 {
		c.TakeoverHTTPTimeout = 6 * time.Second
	}
	if len(c.Resolvers) == 0 {
		c.Resolvers = []string{
			"8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53",
		}
	}
}

// AXFRResult records one AXFR attempt (success or denial) against one NS.
type AXFRResult struct {
	// Domain is the zone we tried to transfer.
	Domain string `json:"domain"`
	// NameServer is the NS we queried (e.g. "ns1.example.com.").
	NameServer string `json:"name_server"`
	// NSAddr is the resolved IP:port we actually dialled.
	NSAddr string `json:"ns_addr,omitempty"`
	// Success is true when the server returned a zone transfer.
	Success bool `json:"success"`
	// RecordCount is the number of resource records received.
	RecordCount int `json:"record_count,omitempty"`
	// Records is a slice of zone records in textual form (RFC 1035).
	// Truncated to 1000 entries to keep responses bounded.
	Records []string `json:"records,omitempty"`
	// Truncated is true when more records were dropped to enforce the cap.
	Truncated bool `json:"truncated,omitempty"`
	// Err records why the transfer failed (REFUSED, NOTAUTH, timeout, …).
	Err string `json:"err,omitempty"`
	// DurationMS records wire latency for the AXFR attempt.
	DurationMS int64 `json:"duration_ms,omitempty"`
}

// TakeoverResult records one subdomain takeover check.
type TakeoverResult struct {
	// Subdomain is the FQDN being checked.
	Subdomain string `json:"subdomain"`
	// CNAME is the resolved CNAME chain target (last hop). Empty if no CNAME.
	CNAME string `json:"cname,omitempty"`
	// Service is the matched SaaS name (e.g. "GitHub Pages", "AWS/S3").
	Service string `json:"service,omitempty"`
	// Vulnerable is true when the signature reports the service is exploitable.
	Vulnerable bool `json:"vulnerable"`
	// Evidence is the substring from the HTTP response that confirmed the match.
	Evidence string `json:"evidence,omitempty"`
	// HTTPStatus is the response status code from the takeover probe.
	HTTPStatus int `json:"http_status,omitempty"`
	// Doc is a short note / reference URL for the service.
	Doc string `json:"doc,omitempty"`
	// Err records any error encountered (resolver failure, HTTP error).
	Err string `json:"err,omitempty"`
}

// Result bundles AXFR + takeover outcomes for one Scan call.
type Result struct {
	Domain    string            `json:"domain"`
	AXFR      []*AXFRResult     `json:"axfr,omitempty"`
	Takeovers []*TakeoverResult `json:"takeovers,omitempty"`
	// DurationMS is total scan wall time.
	DurationMS int64 `json:"duration_ms"`
}

// ToAsset converts an exploitable takeover to a *models.Asset; non-vulnerable
// matches return nil. AXFR results are not asset-shaped (they are zone-level).
func (r *TakeoverResult) ToAsset() *models.Asset {
	if !r.Vulnerable {
		return nil
	}
	a := models.NewAsset()
	a.Domain = r.Subdomain
	a.Host = r.Subdomain
	a.Source = "subdomain_takeover"
	a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
	a.Tags = append(a.Tags, "takeover", r.Service)
	a.Raw = map[string]string{
		"service":  r.Service,
		"cname":    r.CNAME,
		"evidence": r.Evidence,
	}
	return a
}
