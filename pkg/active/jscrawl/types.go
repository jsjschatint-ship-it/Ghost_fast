// Package jscrawl performs recursive crawling of HTML pages + JS files to
// surface API endpoints and exposed secrets/keys.
//
// Pipeline:
//  1. Seed URL(s) → fetch HTML → collect <script src> + same-origin <a href>.
//  2. For each JS file: fetch, scan body for endpoint patterns + secret
//     fingerprints, and detect chained JS imports (`import "/static/x.js"`,
//     webpack chunks, `.js.map` refs).
//  3. Repeat up to MaxDepth, with per-host fetch budget + global concurrency.
//
// Output is one Page per fetched URL plus aggregated lists of unique
// endpoints/secrets keyed by source URL for quick reverse-engineering.
package jscrawl

import (
	"strings"
	"time"
)

// Config tunes a Crawl run.
type Config struct {
	// Seeds is the list of starting URLs (full http/https URL).
	Seeds []string `json:"seeds" yaml:"seeds"`
	// MaxDepth limits how many hops away from each seed we follow.
	// 0 = only the seed itself; 1 = seed + its direct .js refs; …
	// Default 2 covers most SPA bundles.
	MaxDepth int `json:"max_depth" yaml:"max_depth"`
	// MaxPages caps the total number of fetches (HTML + JS combined) to
	// protect against accidental crawl-the-internet runs.
	MaxPages int `json:"max_pages" yaml:"max_pages"`
	// MaxBodyBytes caps the response body we read & scan. JS bundles can be
	// huge (10+ MB minified) — we still scan them, but cap to avoid OOM.
	MaxBodyBytes int64 `json:"max_body_bytes" yaml:"max_body_bytes"`
	// Concurrency caps simultaneous fetches across all hosts.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// Timeout caps each HTTP fetch.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// SameHostOnly, when true, refuses to follow refs that leave the seed's
	// host. Default true — most bug-bounty crawls want this.
	SameHostOnly bool `json:"same_host_only" yaml:"same_host_only"`
	// FollowRedirects controls whether the HTTP client follows 3xx.
	FollowRedirects bool `json:"follow_redirects" yaml:"follow_redirects"`
	// UserAgent overrides the default UA string.
	UserAgent string `json:"user_agent" yaml:"user_agent"`
	// AllowExternalJS, when true, also fetches+scans .js files served from a
	// different host than the seed (e.g. CDNs). Off by default to avoid
	// leaking session cookies via Referer to unrelated CDNs.
	AllowExternalJS bool `json:"allow_external_js" yaml:"allow_external_js"`

	// ---- katana-compat extensions ----

	// Headers are extra HTTP headers sent on every request (Authorization,
	// X-API-Key, X-CSRF-Token, ...). UserAgent still wins for User-Agent.
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	// Cookie is the raw Cookie header string sent on every request.
	Cookie string `json:"cookie,omitempty" yaml:"cookie,omitempty"`
	// Proxy is the upstream HTTP/SOCKS5 proxy URL.
	//   http://127.0.0.1:8080      (Burp)
	//   socks5://127.0.0.1:1080
	Proxy string `json:"proxy,omitempty" yaml:"proxy,omitempty"`
	// KnownFiles, when true, also fetches well-known discovery files for each
	// seed host: /robots.txt, /sitemap.xml, /sitemap_index.xml,
	// /.well-known/security.txt, /humans.txt -- and feeds any Sitemap / sub-
	// sitemap / Disallow paths back into the crawl queue.
	KnownFiles bool `json:"known_files,omitempty" yaml:"known_files,omitempty"`
	// FetchSourceMaps, when true, for each fetched .js URL also attempts to
	// fetch `<js>.map`, parses it, and scans every embedded sourcesContent[]
	// block for secrets (often the cleanest way to recover .env values that
	// were bundled at build time).
	FetchSourceMaps bool `json:"fetch_source_maps,omitempty" yaml:"fetch_source_maps,omitempty"`
	// ExtractForms enables <form> harvesting (action / method / inputs) to
	// surface authentication endpoints + parameter names.
	ExtractForms bool `json:"extract_forms,omitempty" yaml:"extract_forms,omitempty"`
	// ExcludePatterns are regex strings; any URL matching ANY pattern is
	// skipped. Useful to avoid /logout, /signout, /admin/destroy, etc.
	ExcludePatterns []string `json:"exclude_patterns,omitempty" yaml:"exclude_patterns,omitempty"`
	// IncludeHosts is an extra host allowlist (in addition to seed hosts)
	// considered in-scope when SameHostOnly is true. Empty = no extras.
	IncludeHosts []string `json:"include_hosts,omitempty" yaml:"include_hosts,omitempty"`
	// MaxRetries retries on 5xx / connect-timeout / network error.
	// 0 = no retries, 1 = one extra attempt (default).
	MaxRetries int `json:"max_retries,omitempty" yaml:"max_retries,omitempty"`
	// RatePerSecond caps the per-host fetch rate. 0 = unlimited.
	RatePerSecond int `json:"rate_per_second,omitempty" yaml:"rate_per_second,omitempty"`

	// ---- katana-compat scope/filter extensions (round 2) ----

	// MatchRegex is an URL allowlist: when non-empty, only URLs matching at
	// least one of these regexes are followed. Applied AFTER ExcludePatterns
	// so an excluded URL can never sneak through via match.
	MatchRegex []string `json:"match_regex,omitempty" yaml:"match_regex,omitempty"`
	// ExtensionMatch limits crawling to URLs whose path ends in one of these
	// extensions (no dot, lowercase: e.g. ["js","json","html"]). HTML seeds
	// are always allowed regardless of this list -- otherwise the crawl
	// couldn't bootstrap.
	ExtensionMatch []string `json:"extension_match,omitempty" yaml:"extension_match,omitempty"`
	// ExtensionFilter is a path-extension blocklist (e.g. ["png","gif",
	// "css","woff","woff2","ico","svg","map"] -- NOTE: dropping .map here
	// disables FetchSourceMaps). Applied to all references EXCEPT seeds.
	ExtensionFilter []string `json:"extension_filter,omitempty" yaml:"extension_filter,omitempty"`
	// FieldScope controls how SameHostOnly compares URLs to seed hosts:
	//   "fqdn" (default) -- exact host match (api.example.com != www.example.com)
	//   "rdn"            -- root-domain match using publicsuffix (api.example.com
	//                       == www.example.com == example.com)
	//   "" / "dn"        -- treated as "fqdn" for backward compat
	FieldScope string `json:"field_scope,omitempty" yaml:"field_scope,omitempty"`
	// IgnoreQueryParams collapses URLs that differ only in query-string into
	// a single fetch (the first one wins). Useful when a site uses ?_t=
	// cache-busting hashes or session ids that produce thousands of
	// pseudo-distinct URLs of the same path.
	IgnoreQueryParams bool `json:"ignore_query_params,omitempty" yaml:"ignore_query_params,omitempty"`
	// CrawlDurationSec, when > 0, caps the WHOLE crawl wall time (across
	// all seeds and recursion). Independent from per-request Timeout. Once
	// elapsed the crawler stops accepting new fetches and returns whatever
	// it has so far.
	CrawlDurationSec int `json:"crawl_duration_sec,omitempty" yaml:"crawl_duration_sec,omitempty"`

	// ---- external-engine integration ----

	// UseExternalKatana, when true, asks Crawl() to delegate the crawl to a
	// locally-installed `katana` binary (github.com/projectdiscovery/katana)
	// instead of using the in-process implementation. Falls back to the
	// internal crawler with a logged warning if the binary isn't present.
	// Pairs with HeadlessKatana to enable Chrome rendering of SPAs.
	UseExternalKatana bool `json:"use_external_katana,omitempty" yaml:"use_external_katana,omitempty"`
	// KatanaBin overrides the auto-detected katana path. "" = look up in PATH.
	KatanaBin string `json:"katana_bin,omitempty" yaml:"katana_bin,omitempty"`
	// HeadlessKatana, when true (and UseExternalKatana=true), passes -hl to
	// katana so it spins up Chrome headless. Required to crawl pure-client-
	// rendered SPAs (React/Vue/Angular without SSR). Costs ~200MB RAM per
	// concurrent tab and a few seconds of cold-start latency.
	HeadlessKatana bool `json:"headless_katana,omitempty" yaml:"headless_katana,omitempty"`

	// UseAST, when true, runs an in-process JavaScript AST parser
	// (dop251/goja) on every fetched JS body in addition to the regex
	// scanner. Catches endpoints hidden inside template literals, route
	// objects, and string concatenations that regex misses. Costs ~5-10x
	// CPU per JS body parsed; default off.
	UseAST bool `json:"use_ast,omitempty" yaml:"use_ast,omitempty"`
}

// Normalize fills in defaults.
func (c *Config) Normalize() {
	if c.MaxDepth <= 0 {
		c.MaxDepth = 2
	}
	if c.MaxPages <= 0 {
		c.MaxPages = 200
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 5 * 1024 * 1024 // 5 MB per file
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	if c.Timeout <= 0 {
		c.Timeout = 12 * time.Second
	}
	if c.UserAgent == "" {
		c.UserAgent = "Mozilla/5.0 (compatible; ghost-jscrawl/1.0)"
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}
	if c.RatePerSecond < 0 {
		c.RatePerSecond = 0
	}
	if c.CrawlDurationSec < 0 {
		c.CrawlDurationSec = 0
	}
	// Lowercase user-supplied extensions so the lookup is case-insensitive.
	c.ExtensionMatch = lowerStrings(c.ExtensionMatch)
	c.ExtensionFilter = lowerStrings(c.ExtensionFilter)
	c.FieldScope = strings.ToLower(strings.TrimSpace(c.FieldScope))
	// SameHostOnly default is true; can't distinguish "explicit false" from
	// zero value via a bool here — callers should pass an explicit value.
}

// lowerStrings returns a new slice with each entry trimmed + lowercased and
// any empty / dot-prefixed values stripped (".png" -> "png"). nil slices stay
// nil so the "feature off" code path remains a simple len() == 0 check.
func lowerStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		s = strings.TrimPrefix(s, ".")
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Match is one finding from scanning a JS/HTML body.
type Match struct {
	// Type is the category: "endpoint" | "secret".
	Type string `json:"type"`
	// Rule is the rule name that fired (e.g. "aws_access_key_id").
	Rule string `json:"rule"`
	// Value is the matched string. Secret values are partially redacted to
	// the middle 60 % of bytes; endpoints are returned in full.
	Value string `json:"value"`
	// Severity is "info" | "low" | "medium" | "high" | "critical".
	Severity string `json:"severity,omitempty"`
}

// Page is everything we learned about one URL.
type Page struct {
	// URL is the absolute URL we fetched.
	URL string `json:"url"`
	// Source is "seed" | "html" | "js" indicating how we got here.
	Source string `json:"source"`
	// Depth is how many hops away from a seed.
	Depth int `json:"depth"`
	// Status is the HTTP status code (0 means we never got a response).
	Status int `json:"status"`
	// ContentType is the response Content-Type.
	ContentType string `json:"content_type,omitempty"`
	// BodyLen is the number of bytes we actually scanned (≤ MaxBodyBytes).
	BodyLen int `json:"body_len,omitempty"`
	// Matches is the unique findings extracted from this body.
	Matches []*Match `json:"matches,omitempty"`
	// References lists URLs discovered inside this page (already absolute).
	References []string `json:"references,omitempty"`
	// Err captures any fetch/parse error.
	Err string `json:"err,omitempty"`
	// DurationMS is wall time for fetch+scan.
	DurationMS int64 `json:"duration_ms,omitempty"`
}

// Result is the full crawl output.
type Result struct {
	Seeds []string `json:"seeds"`
	Pages []*Page  `json:"pages"`
	// Endpoints aggregates unique endpoint values across all pages, sorted.
	Endpoints []string `json:"endpoints,omitempty"`
	// Secrets aggregates unique secret matches across all pages, sorted by
	// rule name then value.
	Secrets []*Match `json:"secrets,omitempty"`
	// Forms is the list of <form> findings discovered while crawling HTML.
	// Only populated when Config.ExtractForms is true.
	Forms []*Form `json:"forms,omitempty"`
	// Parameters is the union of all unique query+form parameter names found
	// across all visited pages. Useful as a fuzzing seed list.
	Parameters []string `json:"parameters,omitempty"`
	// WebSockets is the unique sorted set of ws:// / wss:// URLs surfaced in
	// any HTML/JS body or .map file.
	WebSockets []string `json:"websockets,omitempty"`
	// SourceMaps lists every .js.map we successfully fetched + parsed. Only
	// populated when Config.FetchSourceMaps is true.
	SourceMaps []*SourceMapInfo `json:"source_maps,omitempty"`
	// KnownFiles is the per-host roll-up of robots.txt / sitemap.xml /
	// security.txt discoveries. Only populated when Config.KnownFiles is true.
	KnownFiles []*KnownFile `json:"known_files,omitempty"`
	// Stats summarises the crawl.
	Stats Stats `json:"stats"`
	// DurationMS is the total wall time.
	DurationMS int64 `json:"duration_ms"`
}

// Stats summarises the crawl.
type Stats struct {
	PagesFetched      int `json:"pages_fetched"`
	JSFiles           int `json:"js_files"`
	EndpointsFound    int `json:"endpoints_found"`
	SecretsFound      int `json:"secrets_found"`
	Errors            int `json:"errors"`
	FormsFound        int `json:"forms_found,omitempty"`
	ParamsFound       int `json:"params_found,omitempty"`
	WebSocketsFound   int `json:"websockets_found,omitempty"`
	SourceMapsFetched int `json:"source_maps_fetched,omitempty"`
	KnownFilesFetched int `json:"known_files_fetched,omitempty"`
	Retries           int `json:"retries,omitempty"`
}

// Form is a discovered HTML <form> element.
type Form struct {
	// URL is the page where the form was found.
	URL string `json:"url"`
	// Action is the resolved absolute URL of the form action (defaults to URL
	// if the action attribute was empty).
	Action string `json:"action"`
	// Method is the form method, uppercased (GET / POST / PUT ...).
	Method string `json:"method"`
	// EncType is the enctype attribute when set; mostly multipart/form-data
	// for upload forms.
	EncType string `json:"enctype,omitempty"`
	// Inputs lists each input/textarea/select element that has a name.
	Inputs []*FormInput `json:"inputs,omitempty"`
}

// FormInput is one named field inside a <form>.
type FormInput struct {
	Name  string `json:"name"`
	Type  string `json:"type,omitempty"`  // text / password / hidden / submit / file / ...
	Value string `json:"value,omitempty"` // default value if any
}

// SourceMapInfo is what we learned from one .js.map file.
type SourceMapInfo struct {
	// URL is the .map URL we fetched (e.g. https://x/static/app.bundle.js.map).
	URL string `json:"url"`
	// Version is the source-map spec version (almost always 3).
	Version int `json:"version,omitempty"`
	// File is the original .js this map refers to (the `file` field).
	File string `json:"file,omitempty"`
	// Sources lists the original source paths (e.g. "webpack:///./src/App.tsx").
	Sources []string `json:"sources,omitempty"`
	// HasContent indicates whether the map carries inline sourcesContent[].
	// When true, the original source is fully recoverable.
	HasContent bool `json:"has_content,omitempty"`
	// BytesRecovered is the total length of sourcesContent[] (recovered code).
	BytesRecovered int `json:"bytes_recovered,omitempty"`
	// SecretsInContent is how many secret findings came from sourcesContent
	// (these are also folded into Result.Secrets at the top level).
	SecretsInContent int `json:"secrets_in_content,omitempty"`
}

// KnownFile records one well-known discovery file (robots/sitemap/security/etc.).
type KnownFile struct {
	URL    string `json:"url"`             // e.g. https://x/robots.txt
	Status int    `json:"status"`          // HTTP status
	Kind   string `json:"kind"`            // robots | sitemap | security | humans
	Bytes  int    `json:"bytes,omitempty"` // body length
	// ExtractedURLs are URLs harvested from this file that we re-enqueue.
	ExtractedURLs []string `json:"extracted_urls,omitempty"`
}
