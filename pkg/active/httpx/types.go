// Package httpx provides active HTTP/HTTPS liveness probing and fingerprinting.
//
// It accepts a list of inputs (URLs, hostnames, or host:port pairs) and concurrently
// probes each over HTTP and/or HTTPS, collecting:
//
//   - HTTP status / final URL / redirect chain
//   - Response size, server header, content-type
//   - HTML <title>
//   - TLS certificate subject/issuer/SANs (when HTTPS)
//   - Resolved IP addresses + CNAME chain
//   - Favicon (mmh3) hash
//   - Tech fingerprint guesses (CMS / server / framework / CDN)
//
// All results are returned as both a structured Result and a *models.Asset so they
// can be merged into existing session storage.
package httpx

import (
	"time"

	"github.com/wgpsec/ENScan/pkg/models"
)

// Config tunes the prober. Zero value gets sane defaults via Normalize.
type Config struct {
	// Concurrency is the maximum number of in-flight probes.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// Timeout is per-request timeout (includes redirects).
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// MaxRedirects caps redirect follow depth. 0 means do not follow.
	MaxRedirects int `json:"max_redirects" yaml:"max_redirects"`
	// FollowRedirects toggles redirect following.
	FollowRedirects bool `json:"follow_redirects" yaml:"follow_redirects"`
	// UserAgent overrides the default UA string.
	UserAgent string `json:"user_agent" yaml:"user_agent"`
	// ExtraHeaders are added to every request.
	ExtraHeaders map[string]string `json:"extra_headers" yaml:"extra_headers"`
	// SchemesAuto, when true, probes both http and https for bare hosts.
	SchemesAuto bool `json:"schemes_auto" yaml:"schemes_auto"`
	// Ports is consulted when the input lacks an explicit port and SchemesAuto is on.
	// Default: 80 (http) + 443 (https).
	Ports []int `json:"ports" yaml:"ports"`
	// FetchFavicon controls whether /favicon.ico is downloaded and mmh3-hashed.
	FetchFavicon bool `json:"fetch_favicon" yaml:"fetch_favicon"`
	// ResolveDNS toggles IP + CNAME resolution.
	ResolveDNS bool `json:"resolve_dns" yaml:"resolve_dns"`
	// MaxBodyBytes caps body bytes read for title + fingerprint parsing.
	MaxBodyBytes int64 `json:"max_body_bytes" yaml:"max_body_bytes"`
	// Proxy is an HTTP/SOCKS5 proxy URL applied to every probe.
	Proxy string `json:"proxy" yaml:"proxy"`
	// SkipTLSVerify disables certificate verification (still records cert info).
	SkipTLSVerify bool `json:"skip_tls_verify" yaml:"skip_tls_verify"`
}

// Normalize fills in defaults for unset fields.
func (c *Config) Normalize() {
	if c.Concurrency <= 0 {
		c.Concurrency = 50
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxRedirects <= 0 {
		c.MaxRedirects = 5
	}
	if c.UserAgent == "" {
		c.UserAgent = "Ghost/1.0 (httpx)"
	}
	if len(c.Ports) == 0 {
		c.Ports = []int{80, 443}
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 256 * 1024
	}
}

// Result is the structured outcome of a single probe.
type Result struct {
	// Input is the original target string supplied by the caller.
	Input string `json:"input"`
	// URL is the URL actually requested (after scheme/port inference).
	URL string `json:"url"`
	// FinalURL is the URL after redirects.
	FinalURL string `json:"final_url,omitempty"`
	// Status is the HTTP status code (0 on transport error).
	Status int `json:"status"`
	// ContentLength is the body length actually read (capped by MaxBodyBytes).
	ContentLength int64 `json:"content_length"`
	// Title is the parsed HTML <title>.
	Title string `json:"title,omitempty"`
	// Server is the Server response header.
	Server string `json:"server,omitempty"`
	// ContentType is the Content-Type response header.
	ContentType string `json:"content_type,omitempty"`
	// Scheme is "http" or "https" of the final URL.
	Scheme string `json:"scheme,omitempty"`
	// Host is the host (no port) of the final URL.
	Host string `json:"host,omitempty"`
	// Port is the explicit or scheme-default port.
	Port int `json:"port,omitempty"`
	// IPs are resolved A/AAAA addresses (deduped).
	IPs []string `json:"ips,omitempty"`
	// CNAME is the first non-self CNAME, if any.
	CNAME string `json:"cname,omitempty"`
	// FaviconHash is the mmh3 signed-int32 hash of base64-encoded favicon bytes.
	FaviconHash string `json:"favicon_hash,omitempty"`
	// Cert holds TLS certificate metadata when HTTPS succeeded.
	Cert *CertInfo `json:"cert,omitempty"`
	// Tech is the deduped list of fingerprints matched.
	Tech []string `json:"tech,omitempty"`
	// Chain captures redirect hops as a list of URLs.
	Chain []string `json:"chain,omitempty"`
	// Duration is the wall time spent on the probe.
	Duration time.Duration `json:"duration"`
	// Err contains the transport / parse error message, if any.
	Err string `json:"err,omitempty"`
}

// CertInfo summarises a server TLS certificate.
type CertInfo struct {
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	SANs      []string  `json:"sans,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	SelfSign  bool      `json:"self_sign,omitempty"`
}

// ToAsset converts the result to a *models.Asset suitable for session storage.
func (r *Result) ToAsset() *models.Asset {
	a := models.NewAsset()
	a.URL = r.FinalURL
	if a.URL == "" {
		a.URL = r.URL
	}
	a.Host = r.Host
	a.Port = r.Port
	a.Protocol = r.Scheme
	a.Title = r.Title
	a.Server = r.Server
	a.Products = append([]string(nil), r.Tech...)
	if len(r.IPs) > 0 {
		a.IP = r.IPs[0]
	}
	a.FaviconHash = r.FaviconHash
	if r.Cert != nil {
		a.CertSubject = r.Cert.Subject
		a.CertIssuer = r.Cert.Issuer
		a.CertDomains = append([]string(nil), r.Cert.SANs...)
	}
	a.Source = "httpx"
	a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
	if r.Raw() != nil {
		a.Raw = r.Raw()
	}
	return a
}

// Raw returns a minimal raw map for downstream storage.
func (r *Result) Raw() map[string]string {
	if r == nil {
		return nil
	}
	m := map[string]string{}
	if r.Status > 0 {
		m["status"] = itoa(r.Status)
	}
	if r.ContentLength > 0 {
		m["content_length"] = itoa(int(r.ContentLength))
	}
	if r.ContentType != "" {
		m["content_type"] = r.ContentType
	}
	if r.CNAME != "" {
		m["cname"] = r.CNAME
	}
	if r.Duration > 0 {
		m["rtt_ms"] = itoa(int(r.Duration.Milliseconds()))
	}
	if r.Err != "" {
		m["err"] = r.Err
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// itoa is a tiny stdlib-free integer-to-string for the Raw map.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
