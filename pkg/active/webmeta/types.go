package webmeta

import "time"

type Config struct {
	Targets         []string      `json:"targets" yaml:"targets"`
	Concurrency     int           `json:"concurrency" yaml:"concurrency"`
	Timeout         time.Duration `json:"timeout" yaml:"timeout"`
	MaxBodyBytes    int64         `json:"max_body_bytes" yaml:"max_body_bytes"`
	MaxSitemapURLs  int           `json:"max_sitemap_urls" yaml:"max_sitemap_urls"`
	MaxSitemaps     int           `json:"max_sitemaps" yaml:"max_sitemaps"`
	FetchRobots     bool          `json:"fetch_robots" yaml:"fetch_robots"`
	FetchSitemap    bool          `json:"fetch_sitemap" yaml:"fetch_sitemap"`
	FollowRedirects bool          `json:"follow_redirects" yaml:"follow_redirects"`
	TryHTTPFallback bool          `json:"try_http_fallback" yaml:"try_http_fallback"`
	SkipTLSVerify   bool          `json:"skip_tls_verify" yaml:"skip_tls_verify"`
	UserAgent       string        `json:"user_agent" yaml:"user_agent"`
}

func (c *Config) Normalize() {
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 512 * 1024
	}
	if c.MaxSitemapURLs <= 0 {
		c.MaxSitemapURLs = 200
	}
	if c.MaxSitemaps <= 0 {
		c.MaxSitemaps = 5
	}
	if c.UserAgent == "" {
		c.UserAgent = "Mozilla/5.0 (compatible; ghost-webmeta/1.0)"
	}
}

type Result struct {
	Targets    []string  `json:"targets"`
	Reports    []*Report `json:"reports"`
	Stats      Stats     `json:"stats"`
	DurationMS int64     `json:"duration_ms"`
}

type Stats struct {
	Targets       int `json:"targets"`
	OK            int `json:"ok"`
	Errors        int `json:"errors"`
	Emails        int `json:"emails"`
	Phones        int `json:"phones"`
	ICPNumbers    int `json:"icp_numbers"`
	RobotsPaths   int `json:"robots_paths"`
	SitemapURLs   int `json:"sitemap_urls"`
	MetaTags      int `json:"meta_tags"`
	ExternalLinks int `json:"external_links"`
}

type Report struct {
	Input         string            `json:"input"`
	URL           string            `json:"url"`
	FinalURL      string            `json:"final_url,omitempty"`
	Status        int               `json:"status"`
	ContentType   string            `json:"content_type,omitempty"`
	Server        string            `json:"server,omitempty"`
	Title         string            `json:"title,omitempty"`
	Meta          map[string]string `json:"meta,omitempty"`
	OpenGraph     map[string]string `json:"open_graph,omitempty"`
	Canonical     string            `json:"canonical,omitempty"`
	Icons         []string          `json:"icons,omitempty"`
	Emails        []string          `json:"emails,omitempty"`
	Phones        []string          `json:"phones,omitempty"`
	ICPNumbers    []string          `json:"icp_numbers,omitempty"`
	ExternalLinks []string          `json:"external_links,omitempty"`
	Robots        *RobotsInfo       `json:"robots,omitempty"`
	Sitemaps      []*SitemapInfo    `json:"sitemaps,omitempty"`
	Err           string            `json:"err,omitempty"`
	DurationMS    int64             `json:"duration_ms"`
}

type RobotsInfo struct {
	URL       string   `json:"url"`
	Status    int      `json:"status"`
	Allows    []string `json:"allows,omitempty"`
	Disallows []string `json:"disallows,omitempty"`
	Sitemaps  []string `json:"sitemaps,omitempty"`
	Err       string   `json:"err,omitempty"`
}

type SitemapInfo struct {
	URL    string   `json:"url"`
	Status int      `json:"status"`
	URLs   []string `json:"urls,omitempty"`
	Err    string   `json:"err,omitempty"`
}
