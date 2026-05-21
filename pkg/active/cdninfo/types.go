// Package cdninfo identifies the CDN / WAF in front of a website and
// surfaces candidates for the **origin (back-end) IP** without firing any
// exploit payloads.
//
// Detection signals (all passive / informational):
//   - Response headers (`Server`, `Via`, `X-Cache`, `cf-ray`, `x-amz-cf-id`,
//     `x-akamai-*`, `x-fastly-*`, `x-served-by`, …)
//   - CNAME / ASN of the front-facing IPs (cloudflare.net, akamaiedge.net,
//     wsdvs.com, alibabaaegis.com, qcloudcdn.cn …)
//   - SSL Subject CN (e.g. `*.r.cloudflarestream.com`)
//
// Origin-IP discovery (no scanning, no probes outside DNS):
//   - MX records — mail typically points at the origin, not the CDN
//   - SPF includes — same logic
//   - `mail.<root>`, `direct.<root>`, `origin.<root>`, `backend.<root>`,
//     `ftp.<root>`, `cpanel.<root>` — common "bypass-CDN" siblings
//   - Historical DNS — left to the caller (we expose the names to query)
//
// We DO NOT brute-force or scan; we only resolve a curated label set.
package cdninfo

import "time"

// Config tunes a Detect() call.
type Config struct {
	// Hosts is the list of hostnames to fingerprint.
	Hosts []string `json:"hosts" yaml:"hosts"`
	// Resolvers is the list of DNS servers (host:port). Empty → defaults.
	Resolvers []string `json:"resolvers" yaml:"resolvers"`
	// HTTPTimeout caps each header-probe request.
	HTTPTimeout time.Duration `json:"http_timeout" yaml:"http_timeout"`
	// DNSTimeout caps each DNS query.
	DNSTimeout time.Duration `json:"dns_timeout" yaml:"dns_timeout"`
	// Concurrency caps parallel hosts.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// SkipOriginHunt disables the bypass-label / MX / SPF lookups (faster
	// but less useful).
	SkipOriginHunt    bool     `json:"skip_origin_hunt" yaml:"skip_origin_hunt"`
	DoPassiveDNS      bool     `json:"do_passive_dns" yaml:"do_passive_dns"`
	PassiveSources    []string `json:"passive_sources" yaml:"passive_sources"`
	MaxPassiveRecords int      `json:"max_passive_records" yaml:"max_passive_records"`
	SecurityTrailsKey string   `json:"securitytrails_key,omitempty" yaml:"securitytrails_key,omitempty"`
	VirusTotalKey     string   `json:"virustotal_key,omitempty" yaml:"virustotal_key,omitempty"`
	// UserAgent for the header probe.
	UserAgent string `json:"user_agent" yaml:"user_agent"`
}

// Normalize fills in defaults.
func (c *Config) Normalize() {
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 10 * time.Second
	}
	if c.DNSTimeout <= 0 {
		c.DNSTimeout = 4 * time.Second
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	if c.MaxPassiveRecords <= 0 {
		c.MaxPassiveRecords = 100
	}
	if c.UserAgent == "" {
		c.UserAgent = "Mozilla/5.0 (compatible; ghost-cdninfo/1.0)"
	}
}

// VendorHit is one positive vendor identification.
type VendorHit struct {
	Vendor   string `json:"vendor"`   // cloudflare, akamai, fastly, aws_cloudfront, aliyun, tencent_cloud, …
	Kind     string `json:"kind"`     // cdn|waf|cloud_lb
	Source   string `json:"source"`   // header, cname, body, cert
	Evidence string `json:"evidence"` // the actual matched value
}

// OriginCandidate is a hostname/IP that *might* be the origin behind the CDN.
type OriginCandidate struct {
	Source string   `json:"source"` // mx, spf, bypass_label, historical
	Label  string   `json:"label"`  // the FQDN we resolved
	IPs    []string `json:"ips"`
	Note   string   `json:"note,omitempty"`
}

// HostReport is the per-host result.
type HostReport struct {
	Host             string             `json:"host"`
	FrontIPs         []string           `json:"front_ips,omitempty"`
	CNAMEChain       []string           `json:"cname_chain,omitempty"`
	HasCDN           bool               `json:"has_cdn"`
	Vendors          []*VendorHit       `json:"vendors,omitempty"`
	OriginCandidates []*OriginCandidate `json:"origin_candidates,omitempty"`
	ResponseHeaders  map[string]string  `json:"response_headers,omitempty"`
	HTTPStatus       int                `json:"http_status,omitempty"`
	Err              string             `json:"err,omitempty"`
	DurationMS       int64              `json:"duration_ms,omitempty"`
}

// Result is the merged Detect() output.
type Result struct {
	Hosts      []*HostReport `json:"hosts"`
	Stats      Stats         `json:"stats"`
	DurationMS int64         `json:"duration_ms"`
}

// Stats summarises the run.
type Stats struct {
	HostsScanned     int            `json:"hosts_scanned"`
	HostsWithCDN     int            `json:"hosts_with_cdn"`
	VendorCounts     map[string]int `json:"vendor_counts,omitempty"`
	OriginCandidates int            `json:"origin_candidates"`
}
