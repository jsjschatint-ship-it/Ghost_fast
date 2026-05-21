package webmeta

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	phoneRe = regexp.MustCompile(`(?i)(?:\+?86[-\s]?)?1[3-9]\d{9}|0\d{2,3}[-\s]?\d{7,8}`)
	icpRe   = regexp.MustCompile(`[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-Z]?ICP备?\d{5,}(?:-\d+)?号?`)
	locRe   = regexp.MustCompile(`(?is)<loc>\s*([^<]+?)\s*</loc>`)
)

func Collect(ctx context.Context, cfg Config) *Result {
	cfg.Normalize()
	t0 := time.Now()
	targets := uniqueNonEmpty(cfg.Targets)
	res := &Result{Targets: targets}
	if len(targets) == 0 {
		return res
	}
	client := buildClient(&cfg)
	reports := make([]*Report, len(targets))
	gate := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for i, target := range targets {
		i, target := i, target
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case gate <- struct{}{}:
				defer func() { <-gate }()
			case <-ctx.Done():
				reports[i] = &Report{Input: target, Err: ctx.Err().Error()}
				return
			}
			reports[i] = collectOne(ctx, client, target, &cfg)
		}()
	}
	wg.Wait()
	for _, r := range reports {
		if r != nil {
			res.Reports = append(res.Reports, r)
		}
	}
	res.Stats = aggregateStats(res.Reports)
	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}

func collectOne(ctx context.Context, client *http.Client, target string, cfg *Config) *Report {
	t0 := time.Now()
	candidates := candidateURLs(target, cfg.TryHTTPFallback)
	if len(candidates) == 0 {
		return &Report{Input: target, Err: "invalid target", DurationMS: time.Since(t0).Milliseconds()}
	}
	var report *Report
	for i, u := range candidates {
		r := fetchPage(ctx, client, target, u, cfg)
		report = r
		if r.Err == "" || i == len(candidates)-1 {
			break
		}
	}
	if report == nil {
		report = &Report{Input: target, Err: "no candidate url", DurationMS: time.Since(t0).Milliseconds()}
	}
	base := report.FinalURL
	if base == "" {
		base = report.URL
	}
	if base != "" && report.Err == "" {
		if cfg.FetchRobots {
			report.Robots = fetchRobots(ctx, client, base, cfg)
		}
		if cfg.FetchSitemap {
			report.Sitemaps = fetchSitemaps(ctx, client, base, cfg, report.Robots)
		}
	}
	report.DurationMS = time.Since(t0).Milliseconds()
	return report
}

func fetchPage(ctx context.Context, client *http.Client, input, targetURL string, cfg *Config) *Report {
	t0 := time.Now()
	r := &Report{Input: input, URL: targetURL}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		r.Err = err.Error()
		r.DurationMS = time.Since(t0).Milliseconds()
		return r
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		r.Err = err.Error()
		r.DurationMS = time.Since(t0).Milliseconds()
		return r
	}
	defer resp.Body.Close()
	r.Status = resp.StatusCode
	r.FinalURL = resp.Request.URL.String()
	r.ContentType = resp.Header.Get("Content-Type")
	r.Server = resp.Header.Get("Server")
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxBodyBytes))
	if err != nil {
		r.Err = "read body: " + err.Error()
	}
	bodyStr := string(body)
	if strings.Contains(strings.ToLower(r.ContentType), "html") || strings.Contains(strings.ToLower(bodyStr[:minInt(len(bodyStr), 256)]), "<html") {
		applyHTMLMeta(r, bodyStr)
	}
	r.Emails = extractSorted(emailRe, bodyStr, 100)
	r.Phones = extractSorted(phoneRe, bodyStr, 100)
	r.ICPNumbers = extractSorted(icpRe, bodyStr, 50)
	r.DurationMS = time.Since(t0).Milliseconds()
	return r
}

func applyHTMLMeta(r *Report, body string) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return
	}
	r.Title = normalizeText(doc.Find("title").First().Text())
	meta := map[string]string{}
	og := map[string]string{}
	doc.Find("meta").Each(func(_ int, s *goquery.Selection) {
		key := ""
		if v, ok := s.Attr("name"); ok {
			key = strings.ToLower(strings.TrimSpace(v))
		} else if v, ok := s.Attr("http-equiv"); ok {
			key = strings.ToLower(strings.TrimSpace(v))
		} else if v, ok := s.Attr("property"); ok {
			key = strings.ToLower(strings.TrimSpace(v))
		}
		if key == "" {
			return
		}
		content, _ := s.Attr("content")
		content = normalizeText(content)
		if content == "" {
			return
		}
		if strings.HasPrefix(key, "og:") {
			og[key] = content
		} else {
			meta[key] = content
		}
	})
	if len(meta) > 0 {
		r.Meta = meta
	}
	if len(og) > 0 {
		r.OpenGraph = og
	}
	doc.Find("link[rel]").Each(func(_ int, s *goquery.Selection) {
		rel, _ := s.Attr("rel")
		href, ok := s.Attr("href")
		if !ok {
			return
		}
		rel = strings.ToLower(rel)
		if strings.Contains(rel, "canonical") && r.Canonical == "" {
			r.Canonical = resolveURL(r.FinalURL, href)
		}
		if strings.Contains(rel, "icon") {
			r.Icons = appendUnique(r.Icons, resolveURL(r.FinalURL, href), 20)
		}
	})
	base, err := url.Parse(r.FinalURL)
	if err != nil {
		return
	}
	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, ok := s.Attr("href")
		if !ok {
			return
		}
		abs := resolveURL(r.FinalURL, href)
		u, err := url.Parse(abs)
		if err != nil || u.Host == "" || u.Scheme == "" {
			return
		}
		if !sameHost(base.Host, u.Host) {
			r.ExternalLinks = appendUnique(r.ExternalLinks, abs, 100)
		}
	})
}

func fetchRobots(ctx context.Context, client *http.Client, baseURL string, cfg *Config) *RobotsInfo {
	robotsURL := rootURL(baseURL, "/robots.txt")
	info := &RobotsInfo{URL: robotsURL}
	status, body, err := fetchText(ctx, client, robotsURL, cfg)
	info.Status = status
	if err != nil {
		info.Err = err.Error()
		return info
	}
	allows, disallows, sitemaps := parseRobots(body, robotsURL)
	info.Allows = allows
	info.Disallows = disallows
	info.Sitemaps = sitemaps
	return info
}

func fetchSitemaps(ctx context.Context, client *http.Client, baseURL string, cfg *Config, robots *RobotsInfo) []*SitemapInfo {
	queue := append([]string(nil), robotsSitemaps(robots)...)
	if len(queue) == 0 {
		queue = append(queue, rootURL(baseURL, "/sitemap.xml"))
	}
	seen := map[string]struct{}{}
	var out []*SitemapInfo
	totalURLs := 0
	for len(queue) > 0 && len(out) < cfg.MaxSitemaps && totalURLs < cfg.MaxSitemapURLs {
		u := queue[0]
		queue = queue[1:]
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		status, body, err := fetchText(ctx, client, u, cfg)
		info := &SitemapInfo{URL: u, Status: status}
		if err != nil {
			info.Err = err.Error()
			out = append(out, info)
			continue
		}
		urls, nested := parseSitemap(body)
		for _, next := range nested {
			if len(out)+len(queue) >= cfg.MaxSitemaps {
				break
			}
			queue = append(queue, next)
		}
		for _, pageURL := range urls {
			if totalURLs >= cfg.MaxSitemapURLs {
				break
			}
			info.URLs = appendUnique(info.URLs, pageURL, cfg.MaxSitemapURLs)
			totalURLs++
		}
		out = append(out, info)
	}
	return out
}

func fetchText(ctx context.Context, client *http.Client, targetURL string, cfg *Config) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "text/plain,application/xml,text/xml,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxBodyBytes))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

func parseRobots(body, robotsURL string) ([]string, []string, []string) {
	base := robotsURL
	var allows, disallows, sitemaps []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}
		switch key {
		case "allow":
			allows = appendUnique(allows, resolveURL(base, val), 300)
		case "disallow":
			disallows = appendUnique(disallows, resolveURL(base, val), 300)
		case "sitemap":
			sitemaps = appendUnique(sitemaps, resolveURL(base, val), 50)
		}
	}
	return allows, disallows, sitemaps
}

func parseSitemap(body string) ([]string, []string) {
	type locNode struct {
		Loc string `xml:"loc"`
	}
	type sitemapDoc struct {
		URLs     []locNode `xml:"url"`
		Sitemaps []locNode `xml:"sitemap"`
	}
	var doc sitemapDoc
	if err := xml.Unmarshal([]byte(body), &doc); err == nil && (len(doc.URLs) > 0 || len(doc.Sitemaps) > 0) {
		urls := make([]string, 0, len(doc.URLs))
		for _, n := range doc.URLs {
			if v := strings.TrimSpace(n.Loc); v != "" {
				urls = appendUnique(urls, v, 100000)
			}
		}
		nested := make([]string, 0, len(doc.Sitemaps))
		for _, n := range doc.Sitemaps {
			if v := strings.TrimSpace(n.Loc); v != "" {
				nested = appendUnique(nested, v, 100000)
			}
		}
		return urls, nested
	}
	matches := locRe.FindAllStringSubmatch(body, -1)
	urls := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			urls = appendUnique(urls, strings.TrimSpace(m[1]), 100000)
		}
	}
	return urls, nil
}

func buildClient(cfg *Config) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   cfg.Concurrency,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
	}
	c := &http.Client{Timeout: cfg.Timeout, Transport: tr}
	if !cfg.FollowRedirects {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	} else {
		c.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	return c
}

func aggregateStats(reports []*Report) Stats {
	st := Stats{Targets: len(reports)}
	for _, r := range reports {
		if r == nil {
			continue
		}
		if r.Err != "" || r.Status == 0 {
			st.Errors++
		} else {
			st.OK++
		}
		st.Emails += len(r.Emails)
		st.Phones += len(r.Phones)
		st.ICPNumbers += len(r.ICPNumbers)
		st.MetaTags += len(r.Meta) + len(r.OpenGraph)
		st.ExternalLinks += len(r.ExternalLinks)
		if r.Robots != nil {
			st.RobotsPaths += len(r.Robots.Allows) + len(r.Robots.Disallows)
		}
		for _, sm := range r.Sitemaps {
			st.SitemapURLs += len(sm.URLs)
		}
	}
	return st
}

func candidateURLs(raw string, fallback bool) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return nil
	}
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	}
	if strings.HasPrefix(strings.ToLower(raw), "http://") || strings.HasPrefix(strings.ToLower(raw), "https://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return []string{raw}
		}
		return nil
	}
	out := []string{"https://" + raw}
	if fallback {
		out = append(out, "http://"+raw)
	}
	return out
}

func rootURL(baseURL, path string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func resolveURL(baseURL, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(strings.ToLower(raw), "javascript:") || strings.HasPrefix(strings.ToLower(raw), "data:") {
		return ""
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return raw
	}
	ref, err := base.Parse(raw)
	if err != nil {
		return raw
	}
	ref.Fragment = ""
	return ref.String()
}

func sameHost(a, b string) bool {
	ah := strings.ToLower(strings.Split(a, ":")[0])
	bh := strings.ToLower(strings.Split(b, ":")[0])
	return ah == bh
}

func robotsSitemaps(r *RobotsInfo) []string {
	if r == nil {
		return nil
	}
	return append([]string(nil), r.Sitemaps...)
}

func extractSorted(re *regexp.Regexp, body string, limit int) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range re.FindAllString(body, -1) {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		k := strings.ToLower(m)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, m)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	sort.Strings(out)
	return out
}

func uniqueNonEmpty(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range in {
		for _, s := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' }) {
			s = strings.TrimSpace(s)
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			k := strings.ToLower(s)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func appendUnique(out []string, v string, limit int) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return out
	}
	if limit > 0 && len(out) >= limit {
		return out
	}
	for _, existing := range out {
		if strings.EqualFold(existing, v) {
			return out
		}
	}
	return append(out, v)
}

func normalizeText(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
