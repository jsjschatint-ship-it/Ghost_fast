// Package asn expands an IP, hostname, ASN, or org name into the full BGP
// prefix list announced by that ASN — the canonical "find every IP in this
// company's AS" pivot.
//
// Sources (all over plain HTTPS, no key required):
//
//	bgpview.io   — JSON API: /ip/<ip>, /asn/<num>/prefixes, /search?query_term=<org>
//	team-cymru   — IP-to-ASN whois via TCP/43 (`whois -h whois.cymru.com " -v <ip>"`)
//
// bgpview is the primary source; team-cymru is a fallback that works even
// when bgpview is rate-limited or down.
package asn

import "time"

// Config tunes a Lookup() call.
type Config struct {
	// Inputs is the heterogeneous list of identifiers: IPs, hostnames, ASN
	// strings ("AS13335" / "13335"), or org-name search terms.
	Inputs []string `json:"inputs" yaml:"inputs"`
	// ResolveHostnames toggles the hostname → IP resolution step. Default true.
	ResolveHostnames bool `json:"resolve_hostnames" yaml:"resolve_hostnames"`
	// SkipIPv6 drops IPv6 prefixes from the output (they often double the
	// row count without changing the high-value v4 list). Default false
	// (i.e. IPv6 included). Inverted-sense so the zero value matches the
	// documented "include everything" default.
	SkipIPv6 bool `json:"skip_ipv6" yaml:"skip_ipv6"`
	// MaxASNs caps the unique ASNs we expand per Lookup() call.
	MaxASNs int `json:"max_asns" yaml:"max_asns"`
	// MaxPrefixesPerASN caps prefix list per ASN.
	MaxPrefixesPerASN int `json:"max_prefixes_per_asn" yaml:"max_prefixes_per_asn"`
	// HTTPTimeout caps each upstream API request.
	HTTPTimeout time.Duration `json:"http_timeout" yaml:"http_timeout"`
	// Concurrency caps simultaneous upstream calls.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// BGPViewBase overrides the bgpview.io API root (tests).
	BGPViewBase string `json:"bgpview_base" yaml:"bgpview_base"`
	// UserAgent is the HTTP UA.
	UserAgent string `json:"user_agent" yaml:"user_agent"`
}

// Normalize fills in defaults.
func (c *Config) Normalize() {
	if c.MaxASNs <= 0 {
		c.MaxASNs = 50
	}
	if c.MaxPrefixesPerASN <= 0 {
		c.MaxPrefixesPerASN = 2000
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 15 * time.Second
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.BGPViewBase == "" {
		c.BGPViewBase = "https://api.bgpview.io"
	}
	if c.UserAgent == "" {
		c.UserAgent = "Mozilla/5.0 (compatible; ghost-asn/1.0)"
	}
}

// ASNInfo summarises one ASN.
type ASNInfo struct {
	ASN         int    `json:"asn"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Country     string `json:"country,omitempty"`
}

// Prefix is one announced BGP prefix.
type Prefix struct {
	CIDR        string `json:"cidr"`
	Family      int    `json:"family"` // 4 or 6
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Country     string `json:"country,omitempty"`
}

// IPMapping records how one input IP resolved to ASN+prefix.
type IPMapping struct {
	Input  string `json:"input"`
	IP     string `json:"ip"`
	ASN    int    `json:"asn"`
	Prefix string `json:"prefix,omitempty"`
	Source string `json:"source"` // bgpview, cymru
	Err    string `json:"err,omitempty"`
}

// Result is the merged Lookup() output.
type Result struct {
	IPMappings []*IPMapping `json:"ip_mappings,omitempty"`
	ASNs       []*ASNInfo   `json:"asns,omitempty"`
	Prefixes   []*Prefix    `json:"prefixes,omitempty"`
	Stats      Stats        `json:"stats"`
	DurationMS int64        `json:"duration_ms"`
}

// Stats summarises the run.
type Stats struct {
	Inputs       int `json:"inputs"`
	ASNs         int `json:"asns"`
	IPv4Prefixes int `json:"ipv4_prefixes"`
	IPv6Prefixes int `json:"ipv6_prefixes"`
}
