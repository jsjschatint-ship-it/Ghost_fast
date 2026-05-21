// Package whoisrdap performs registration-data lookups for domains and IPs
// via the modern RDAP (JSON) protocol plus legacy WHOIS (TCP/43 plaintext).
//
// Two-tier strategy:
//  1. RDAP first — structured JSON, easy to parse, handles internationalised
//     domains correctly.
//  2. WHOIS fallback — for TLDs that don't have RDAP (or that filter most
//     fields out of RDAP), pull the plaintext record from the appropriate
//     whois server and surface raw lines.
//
// Both results are merged into one Record per input so callers can use
// whichever fields they got.
package whoisrdap

import "time"

// Config tunes a Lookup() call.
type Config struct {
	// Inputs is the list of domains or IPs to query.
	Inputs []string `json:"inputs" yaml:"inputs"`
	// DoRDAP toggles the RDAP stage. Default true.
	DoRDAP bool `json:"do_rdap" yaml:"do_rdap"`
	// DoWHOIS toggles the WHOIS stage. Default true.
	DoWHOIS bool `json:"do_whois" yaml:"do_whois"`
	// HTTPTimeout caps each RDAP request.
	HTTPTimeout time.Duration `json:"http_timeout" yaml:"http_timeout"`
	// WHOISTimeout caps each WHOIS TCP query.
	WHOISTimeout time.Duration `json:"whois_timeout" yaml:"whois_timeout"`
	// Concurrency caps simultaneous lookups.
	Concurrency       int    `json:"concurrency" yaml:"concurrency"`
	DoReverseWHOIS    bool   `json:"do_reverse_whois" yaml:"do_reverse_whois"`
	ReverseWhoisKey   string `json:"reverse_whois_key,omitempty" yaml:"reverse_whois_key,omitempty"`
	MaxSiblingDomains int    `json:"max_sibling_domains" yaml:"max_sibling_domains"`
	// UserAgent is the HTTP UA for RDAP fetches.
	UserAgent string `json:"user_agent" yaml:"user_agent"`
}

// Normalize fills in defaults.
func (c *Config) Normalize() {
	if !c.DoRDAP && !c.DoWHOIS {
		c.DoRDAP = true
		c.DoWHOIS = true
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 12 * time.Second
	}
	if c.WHOISTimeout <= 0 {
		c.WHOISTimeout = 8 * time.Second
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.MaxSiblingDomains <= 0 {
		c.MaxSiblingDomains = 100
	}
	if c.UserAgent == "" {
		c.UserAgent = "Mozilla/5.0 (compatible; ghost-whoisrdap/1.0)"
	}
}

// Contact represents one registrant / admin / tech contact.
type Contact struct {
	Role         string `json:"role,omitempty"` // registrant|admin|tech|abuse
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Country      string `json:"country,omitempty"`
}

type SiblingDomain struct {
	Domain string `json:"domain"`
	Source string `json:"source"`
	Pivot  string `json:"pivot"`
}

// Record is the merged RDAP + WHOIS result for one input.
type Record struct {
	Input          string           `json:"input"`
	Kind           string           `json:"kind"` // domain|ip
	Handle         string           `json:"handle,omitempty"`
	Domain         string           `json:"domain,omitempty"`
	Registrar      string           `json:"registrar,omitempty"`
	RegistrarURL   string           `json:"registrar_url,omitempty"`
	WHOISServer    string           `json:"whois_server,omitempty"`
	Status         []string         `json:"status,omitempty"`
	Nameservers    []string         `json:"nameservers,omitempty"`
	CreatedAt      string           `json:"created_at,omitempty"`
	UpdatedAt      string           `json:"updated_at,omitempty"`
	ExpiresAt      string           `json:"expires_at,omitempty"`
	Contacts       []*Contact       `json:"contacts,omitempty"`
	IPNetwork      string           `json:"ip_network,omitempty"` // for IP queries
	IPCountry      string           `json:"ip_country,omitempty"`
	IPOrg          string           `json:"ip_org,omitempty"`
	SiblingDomains []*SiblingDomain `json:"sibling_domains,omitempty"`
	// Raw stores the source data:
	//   "rdap_json"  → full RDAP JSON body
	//   "whois_text" → raw WHOIS plaintext
	Raw map[string]string `json:"raw,omitempty"`
	// Sources lists which stages succeeded.
	Sources    []string `json:"sources,omitempty"`
	Err        string   `json:"err,omitempty"`
	DurationMS int64    `json:"duration_ms,omitempty"`
}

// Result is the merged Lookup() output.
type Result struct {
	Records    []*Record `json:"records"`
	Stats      Stats     `json:"stats"`
	DurationMS int64     `json:"duration_ms"`
}

// Stats summarises the run.
type Stats struct {
	Inputs         int `json:"inputs"`
	RDAPOK         int `json:"rdap_ok"`
	WHOISOK        int `json:"whois_ok"`
	Failed         int `json:"failed"`
	UniqueEmails   int `json:"unique_emails"`
	SiblingDomains int `json:"sibling_domains"`
}
