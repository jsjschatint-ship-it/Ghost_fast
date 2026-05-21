// Package sensifile probes a list of URLs for the existence of high-value
// information-disclosure paths — `/.git/HEAD`, `/.env`, `/robots.txt`,
// `/sitemap.xml`, `/swagger.json`, `/actuator/env`, `/.DS_Store`, etc.
//
// Detection model (intentionally non-exploitative):
//  1. HEAD the candidate path; if HEAD is rejected (405), fall back to GET.
//  2. Treat HTTP 200/206 + correct-shape body as "present".
//  3. Skim the first KB of the body to confirm: e.g. /.git/HEAD must start
//     with "ref: refs/" and /.env must contain at least one `KEY=VALUE`.
//
// No directory listing, no auth, no follow-up fetches.
package sensifile

import "time"

// Config tunes a Scan() run.
type Config struct {
	// BaseURLs is the list of root URLs to probe (e.g. "https://example.com").
	BaseURLs []string `json:"base_urls" yaml:"base_urls"`
	// Paths overrides the built-in path list when non-empty.
	Paths []string `json:"paths" yaml:"paths"`
	// IncludeMediumOnly drops "info" severity findings (the everyday robots.txt
	// / sitemap.xml that almost every site has).
	IncludeMediumOnly bool `json:"include_medium_only" yaml:"include_medium_only"`
	// Concurrency caps simultaneous HTTP requests across all URLs.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// Timeout caps each HTTP request.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// MaxBodyBytes caps body bytes captured per finding (default 1024).
	MaxBodyBytes int64 `json:"max_body_bytes" yaml:"max_body_bytes"`
	// FollowRedirects toggles 3xx following.
	FollowRedirects bool `json:"follow_redirects" yaml:"follow_redirects"`
	// UserAgent overrides the default UA.
	UserAgent string `json:"user_agent" yaml:"user_agent"`
}

// Normalize fills in defaults.
func (c *Config) Normalize() {
	if c.Concurrency <= 0 {
		c.Concurrency = 20
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 1024
	}
	if c.UserAgent == "" {
		c.UserAgent = "Mozilla/5.0 (compatible; ghost-sensifile/1.0)"
	}
}

// Finding is one positively-confirmed sensitive-path hit.
type Finding struct {
	BaseURL     string `json:"base_url"`
	Path        string `json:"path"`
	URL         string `json:"url"`
	Category    string `json:"category"` // git, env, config, swagger, …
	Severity    string `json:"severity"` // info|low|medium|high|critical
	Description string `json:"description"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	BodyLen     int    `json:"body_len,omitempty"`
	BodySnippet string `json:"body_snippet,omitempty"`
	DurationMS  int64  `json:"duration_ms"`
}

// Probe is one attempted check (whether or not it found anything). Useful
// for QA / debugging; the top-level `findings` slice is the deduplicated
// "hit" list.
type Probe struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Confirmed   bool   `json:"confirmed,omitempty"`
	Err         string `json:"err,omitempty"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
}

// Result is the merged Scan() output.
type Result struct {
	Findings   []*Finding `json:"findings"`
	Probes     []*Probe   `json:"probes,omitempty"`
	Stats      Stats      `json:"stats"`
	DurationMS int64      `json:"duration_ms"`
}

// Stats summarises the run.
type Stats struct {
	URLs        int            `json:"urls"`
	PathsPerURL int            `json:"paths_per_url"`
	ProbesSent  int            `json:"probes_sent"`
	Findings    int            `json:"findings"`
	BySeverity  map[string]int `json:"by_severity,omitempty"`
}
