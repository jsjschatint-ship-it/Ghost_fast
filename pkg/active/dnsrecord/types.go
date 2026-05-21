// Package dnsrecord pulls every commonly-useful DNS RR for a domain in one
// pass — A/AAAA/MX/TXT/SOA/SRV/NS/CAA/CNAME — plus a few synthesized
// look-ups (DMARC at `_dmarc.<domain>`, DKIM selectors, common SRV labels).
// Output also surfaces TXT-record verification tokens (GitHub/AWS/Atlassian/
// 钉钉/Google Workspace…) which betray which 3rd-party SaaS the org uses.
//
// This is the "complete" sibling of pkg/active/dnsadv (which only does
// AXFR + takeover). Use this for steady-state recon, dnsadv for sec-checks.
package dnsrecord

import "time"

// Config tunes a single Lookup() run.
type Config struct {
	// Resolvers is the list of `ip:port` (or `ip`) servers to query in
	// rotation. Empty → use the OS default resolver.
	Resolvers []string `json:"resolvers" yaml:"resolvers"`
	// Timeout caps each individual DNS query.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// Concurrency caps simultaneous queries across record types.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// DKIMSelectors lists selectors to probe at <sel>._domainkey.<domain>.
	// Empty → use the built-in common-selector list (defaultDKIMSelectors).
	DKIMSelectors []string `json:"dkim_selectors" yaml:"dkim_selectors"`
	// SRVLabels lists SRV labels to probe at <label>.<domain>. Empty →
	// built-in default list of commonly-deployed services.
	SRVLabels []string `json:"srv_labels" yaml:"srv_labels"`
	// SkipSRV disables SRV probing entirely (it's noisy).
	SkipSRV bool `json:"skip_srv" yaml:"skip_srv"`
	// SkipDKIM disables DKIM probing.
	SkipDKIM bool `json:"skip_dkim" yaml:"skip_dkim"`
}

// Normalize fills in defaults.
func (c *Config) Normalize() {
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 12
	}
}

// RR is one record returned for a domain.
type RR struct {
	Type  string `json:"type"`  // A / AAAA / MX / TXT / SOA / SRV / NS / CAA / CNAME / DKIM / DMARC
	Name  string `json:"name"`  // queried name (e.g. _dmarc.example.com)
	Value string `json:"value"` // string form of the record content
	// Optional priority/weight for MX/SRV; flag byte for CAA.
	Priority uint16 `json:"priority,omitempty"`
	Weight   uint16 `json:"weight,omitempty"`
	Port     uint16 `json:"port,omitempty"`
}

// TokenMatch is a TXT-record verification token we recognised.
type TokenMatch struct {
	Provider string `json:"provider"`        // github, google_workspace, aws_ses, atlassian, dingtalk, …
	Type     string `json:"type"`            // verification, ownership, spf_include, etc.
	Raw      string `json:"raw"`             // original TXT value
	Value    string `json:"value,omitempty"` // parsed token if present
}

// Email captures the email-related inferences (MX provider, SPF, DMARC).
type Email struct {
	MXProviders []string `json:"mx_providers,omitempty"` // resolved & classified MX hosts
	SPF         string   `json:"spf,omitempty"`
	SPFIncludes []string `json:"spf_includes,omitempty"`
	DMARC       string   `json:"dmarc,omitempty"`
	DMARCPolicy string   `json:"dmarc_policy,omitempty"` // none|quarantine|reject
}

// Result is the merged output for one Lookup() call.
type Result struct {
	Domain     string        `json:"domain"`
	Records    []*RR         `json:"records"`
	Tokens     []*TokenMatch `json:"tokens,omitempty"`
	Email      Email         `json:"email"`
	Stats      Stats         `json:"stats"`
	DurationMS int64         `json:"duration_ms"`
}

// Stats summarises the lookup.
type Stats struct {
	Total       int            `json:"total"`
	ByType      map[string]int `json:"by_type,omitempty"`
	TokensCount int            `json:"tokens"`
}
