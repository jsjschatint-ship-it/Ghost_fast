package jscrawl

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
)

// knownFilePaths lists every well-known discovery path we probe per unique
// seed host. Order matters only for output stability; everything is fetched
// independently.
var knownFilePaths = []struct {
	Path string
	Kind string
}{
	{"/robots.txt", "robots"},
	{"/sitemap.xml", "sitemap"},
	{"/sitemap_index.xml", "sitemap"},
	{"/.well-known/security.txt", "security"},
	{"/humans.txt", "humans"},
}

// fetchKnownFiles probes every knownFilePaths entry for each unique
// scheme://host derived from seeds. Returns:
//   - kfs: one KnownFile record per probe (incl. 404s) for visibility.
//   - extras: URLs harvested out of robots.txt + sitemap.xml that the
//     caller should feed back into the crawl queue.
//
// We deliberately don't run secret-scanning on these bodies here -- callers
// already do that on every Page they fetch; mixing both code paths would
// double-count. Robots/sitemap are URL sources, not content sources.
func fetchKnownFiles(ctx context.Context, client *http.Client, seeds []string, cfg *Config, rl *rateLimiter) ([]*KnownFile, []string) {
	bases := uniqueSchemeHosts(seeds)
	if len(bases) == 0 {
		return nil, nil
	}
	var kfs []*KnownFile
	seenURL := map[string]struct{}{}
	addExtra := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seenURL[u]; ok {
			return
		}
		seenURL[u] = struct{}{}
	}
	var extras []string
	for _, base := range bases {
		for _, kf := range knownFilePaths {
			target := base + kf.Path
			body, status, _, err := do(ctx, client, target, cfg, rl)
			rec := &KnownFile{
				URL:    target,
				Status: status,
				Kind:   kf.Kind,
				Bytes:  len(body),
			}
			kfs = append(kfs, rec)
			if err != nil || status != 200 || len(body) == 0 {
				continue
			}
			switch kf.Kind {
			case "robots":
				for _, u := range parseRobots(target, string(body)) {
					if _, ok := seenURL[u]; !ok {
						addExtra(u)
						extras = append(extras, u)
						rec.ExtractedURLs = append(rec.ExtractedURLs, u)
					}
				}
			case "sitemap":
				for _, u := range parseSitemap(target, body) {
					if _, ok := seenURL[u]; !ok {
						addExtra(u)
						extras = append(extras, u)
						rec.ExtractedURLs = append(rec.ExtractedURLs, u)
					}
				}
			}
		}
	}
	return kfs, extras
}

// uniqueSchemeHosts collapses a list of full URLs down to unique
// scheme://host roots, preserving the first scheme we see per host.
func uniqueSchemeHosts(seeds []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range seeds {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			continue
		}
		scheme := u.Scheme
		if scheme == "" {
			scheme = "https"
		}
		root := scheme + "://" + u.Host
		if seen[root] {
			continue
		}
		seen[root] = true
		out = append(out, root)
	}
	return out
}

// parseRobots extracts URLs from a robots.txt body:
//   - "Sitemap: <url>"  -> harvested verbatim (absolute).
//   - "Disallow: /path" -> resolved against base, added as a candidate URL.
//   - "Allow: /path"    -> same.
//
// Patterns containing wildcards (* or $) are skipped to avoid feeding the
// crawler glob templates -- those are robots.txt language, not real URLs.
func parseRobots(baseURL, body string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	var out []string
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if val == "" || val == "/" {
			continue
		}
		switch key {
		case "sitemap":
			if u, err := base.Parse(val); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
				u.Fragment = ""
				out = append(out, u.String())
			}
		case "disallow", "allow":
			if strings.ContainsAny(val, "*$") {
				continue
			}
			if u, err := base.Parse(val); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
				u.Fragment = ""
				out = append(out, u.String())
			}
		}
	}
	return out
}

// sitemapURLSet maps the <urlset><url><loc>...</loc></url></urlset> schema.
type sitemapURLSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

// sitemapIndex maps the <sitemapindex><sitemap><loc>...</loc></sitemap>...
// schema -- sub-sitemaps that themselves need to be fetched.
type sitemapIndex struct {
	XMLName  xml.Name `xml:"sitemapindex"`
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

// parseSitemap parses both <urlset> and <sitemapindex> documents and returns
// every <loc> it finds. Index <loc>s are also returned -- callers can either
// follow them (re-enqueue as more sitemap fetches) or treat them as URLs
// (the crawler will fetch + parse + extract from them anyway).
func parseSitemap(baseURL string, body []byte) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if u, err := base.Parse(raw); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			u.Fragment = ""
			out = append(out, u.String())
		}
	}
	var urlset sitemapURLSet
	if err := xml.Unmarshal(body, &urlset); err == nil && len(urlset.URLs) > 0 {
		for _, u := range urlset.URLs {
			add(u.Loc)
		}
	}
	var idx sitemapIndex
	if err := xml.Unmarshal(body, &idx); err == nil && len(idx.Sitemaps) > 0 {
		for _, sm := range idx.Sitemaps {
			add(sm.Loc)
		}
	}
	return out
}
