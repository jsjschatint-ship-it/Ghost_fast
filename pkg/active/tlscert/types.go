// Package tlscert correlates assets via TLS certificate intelligence + favicon
// hashes — both are first-class "find this org's siblings" pivots used by
// Shodan / FOFA / Censys.
//
// Three sub-features:
//  1. Live TLS handshake → extract cert chain, SANs, SHA-256 fingerprint.
//  2. crt.sh query → historical certs for a domain (all issued CT log entries),
//     yielding an expanded SAN universe of "sibling" subdomains.
//  3. Favicon hash → mmh3-32 of base64-encoded /favicon.ico bytes, matching
//     Shodan's `http.favicon.hash:<int>` syntax for pivoting.
package tlscert

import "time"

// Config tunes a Run().
type Config struct {
	// Targets is host:port (port defaults to 443 if missing) or just host.
	Targets []string `json:"targets" yaml:"targets"`
	// Domains to query against crt.sh for historical certs (separate from
	// Targets so the user can opt out of crt.sh — that endpoint is slow).
	CTLogDomains []string `json:"ctlog_domains" yaml:"ctlog_domains"`
	// FaviconURLs are the URLs whose /favicon.ico we should hash. If empty,
	// we synthesise `https://<target>/favicon.ico` for each target.
	FaviconURLs []string `json:"favicon_urls" yaml:"favicon_urls"`

	// DoLiveTLS toggles the live TLS handshake stage. Default true.
	DoLiveTLS bool `json:"do_live_tls" yaml:"do_live_tls"`
	// DoCrtSh toggles the crt.sh CT-log query. Default false (rate-limited).
	DoCrtSh bool `json:"do_crtsh" yaml:"do_crtsh"`
	// DoFavicon toggles the favicon-hash stage. Default true.
	DoFavicon bool `json:"do_favicon" yaml:"do_favicon"`

	// Concurrency caps parallel TLS handshakes + favicon fetches.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// TLSTimeout caps each handshake.
	TLSTimeout time.Duration `json:"tls_timeout" yaml:"tls_timeout"`
	// HTTPTimeout caps each crt.sh / favicon HTTP fetch.
	HTTPTimeout time.Duration `json:"http_timeout" yaml:"http_timeout"`
	// CrtShMaxRows caps the rows we keep from crt.sh per domain (cert dumps
	// can balloon into tens of thousands).
	CrtShMaxRows int `json:"crtsh_max_rows" yaml:"crtsh_max_rows"`
	// UserAgent for HTTP fetches.
	UserAgent string `json:"user_agent" yaml:"user_agent"`
}

// Normalize fills in defaults.
func (c *Config) Normalize() {
	if c.Concurrency <= 0 {
		c.Concurrency = 16
	}
	if c.TLSTimeout <= 0 {
		c.TLSTimeout = 8 * time.Second
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 15 * time.Second
	}
	if c.CrtShMaxRows <= 0 {
		c.CrtShMaxRows = 5000
	}
	if c.UserAgent == "" {
		c.UserAgent = "ghost-tlscert/1.0 (+OSINT)"
	}
}

// CertInfo is what we extract from one live TLS endpoint.
type CertInfo struct {
	Target      string    `json:"target"`
	Host        string    `json:"host"`
	Port        string    `json:"port"`
	SubjectCN   string    `json:"subject_cn,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	SANs        []string  `json:"sans,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	SerialHex   string    `json:"serial_hex,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	IsSelfSign  bool      `json:"is_self_signed,omitempty"`
	IsExpired   bool      `json:"is_expired,omitempty"`
	IsWildcard  bool      `json:"is_wildcard,omitempty"`
	NegotiatedV string    `json:"negotiated_tls,omitempty"`
	Err         string    `json:"err,omitempty"`
	DurationMS  int64     `json:"duration_ms,omitempty"`
}

// CTRow is one row from crt.sh's JSON output, normalised.
type CTRow struct {
	IssuerCAID int      `json:"issuer_ca_id,omitempty"`
	IssuerName string   `json:"issuer_name,omitempty"`
	CommonName string   `json:"common_name,omitempty"`
	NameValues []string `json:"name_values,omitempty"` // expanded SAN list
	SerialHex  string   `json:"serial_hex,omitempty"`
	NotBefore  string   `json:"not_before,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
	EntryTime  string   `json:"entry_timestamp,omitempty"`
}

// CTQuery is the aggregated crt.sh result for one queried domain.
type CTQuery struct {
	Domain      string   `json:"domain"`
	Rows        []*CTRow `json:"rows,omitempty"`
	UniqueNames []string `json:"unique_names,omitempty"` // dedup of all SAN + CN
	Truncated   bool     `json:"truncated,omitempty"`
	Err         string   `json:"err,omitempty"`
	DurationMS  int64    `json:"duration_ms,omitempty"`
	HTTPStatus  int      `json:"http_status,omitempty"`
}

// FaviconHash is the result for one favicon URL.
type FaviconHash struct {
	URL        string `json:"url"`
	HTTPStatus int    `json:"http_status,omitempty"`
	BodyLen    int    `json:"body_len,omitempty"`
	MD5        string `json:"md5,omitempty"`
	MMH3       int32  `json:"mmh3"` // Shodan-compatible (signed int32)
	Err        string `json:"err,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

// Result is the full output of Run().
type Result struct {
	Certs      []*CertInfo    `json:"certs,omitempty"`
	CTQueries  []*CTQuery     `json:"ct_queries,omitempty"`
	Favicons   []*FaviconHash `json:"favicons,omitempty"`
	DurationMS int64          `json:"duration_ms"`
	Stats      Stats          `json:"stats"`
}

// Stats summarises the run.
type Stats struct {
	CertsOK        int `json:"certs_ok"`
	CertsErr       int `json:"certs_err"`
	CTRows         int `json:"ct_rows"`
	CTUniqueNames  int `json:"ct_unique_names"`
	FaviconsHashed int `json:"favicons_hashed"`
}
