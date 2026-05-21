package jscrawl

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/publicsuffix"
)

// Crawl runs one full crawl from the supplied seeds. Cancel via ctx.
//
// Pipeline (in order):
//  1. (optional) Fetch known files (robots.txt / sitemap.xml / security.txt /
//     humans.txt) for each unique seed host. Sitemap + robots Allow/Disallow
//     URLs are folded back into the crawl queue as additional "seeds".
//  2. For each seed, recursively fetch HTML + JS up to MaxDepth, capped by
//     MaxPages globally. Same-host filter respects SameHostOnly + IncludeHosts.
//  3. (optional) For each fetched .js, also try <js>.map and recover any
//     embedded sourcesContent[]; scan them for secrets.
//  4. (optional) Extract <form> elements (action / method / inputs).
//  5. Aggregate everything into a Result.
func Crawl(ctx context.Context, cfg Config) *Result {
	cfg.Normalize()
	t0 := time.Now()
	res := &Result{Seeds: cfg.Seeds}
	if len(cfg.Seeds) == 0 {
		return res
	}
	c := newCrawler(&cfg)
	c.run(ctx, res)
	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}

// crawler bundles the mutable state of a single Crawl invocation. Methods on
// crawler are go-safe; concurrent fetchers serialise on c.mu when appending
// to result slices and consulting the dedup map.
type crawler struct {
	cfg        *Config
	client     *http.Client
	rateLimit  *rateLimiter
	excludes   []*regexp.Regexp
	matches    []*regexp.Regexp // MatchRegex compiled (allowlist)
	extMatch   map[string]bool  // ExtensionMatch as set
	extFilter  map[string]bool  // ExtensionFilter as set
	seedHosts  map[string]bool  // hosts of cfg.Seeds (in-scope by default)
	seedRoots  map[string]bool  // root domains of cfg.Seeds when FieldScope=rdn
	allowHosts map[string]bool  // IncludeHosts (extra in-scope hosts)
	scopeIsRDN bool             // true when FieldScope == "rdn"

	mu         sync.Mutex
	fetched    map[string]bool
	pages      []*Page
	forms      []*Form
	paramSet   map[string]struct{}
	wsSet      map[string]struct{}
	sourceMaps []*SourceMapInfo
	smMatches  []*Match // secret/endpoint matches recovered from .map
	knownFiles []*KnownFile

	retries atomic.Int64
	count   atomic.Int32
	stop    atomic.Bool
	wg      sync.WaitGroup
	gate    chan struct{}
}

func newCrawler(cfg *Config) *crawler {
	c := &crawler{
		cfg:        cfg,
		client:     buildClient(cfg),
		rateLimit:  newRateLimiter(cfg.RatePerSecond),
		seedHosts:  map[string]bool{},
		seedRoots:  map[string]bool{},
		allowHosts: map[string]bool{},
		extMatch:   toBoolSet(cfg.ExtensionMatch),
		extFilter:  toBoolSet(cfg.ExtensionFilter),
		scopeIsRDN: cfg.FieldScope == "rdn",
		fetched:    make(map[string]bool, cfg.MaxPages),
		paramSet:   make(map[string]struct{}),
		wsSet:      make(map[string]struct{}),
		gate:       make(chan struct{}, cfg.Concurrency),
	}
	for _, s := range cfg.Seeds {
		if u, err := url.Parse(s); err == nil {
			host := strings.ToLower(u.Host)
			c.seedHosts[host] = true
			if rdn := rootDomain(host); rdn != "" {
				c.seedRoots[rdn] = true
			}
		}
	}
	for _, h := range cfg.IncludeHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			c.allowHosts[h] = true
			if rdn := rootDomain(h); rdn != "" {
				c.seedRoots[rdn] = true
			}
		}
	}
	for _, p := range cfg.ExcludePatterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if re, err := regexp.Compile(p); err == nil {
			c.excludes = append(c.excludes, re)
		}
		// Bad regex is silently ignored — the alternative is failing the
		// whole crawl, which would be brittle UX-wise.
	}
	for _, p := range cfg.MatchRegex {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if re, err := regexp.Compile(p); err == nil {
			c.matches = append(c.matches, re)
		}
	}
	return c
}

// toBoolSet builds a presence-set out of an already-normalised string slice
// (Normalize() is responsible for trim+lowercase+dot-strip).
func toBoolSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[s] = true
	}
	return m
}

// rootDomain returns the effective TLD+1 of host (e.g. "api.example.co.uk"
// -> "example.co.uk"). Falls back to the bare host when the ICANN suffix
// list doesn't contain a match (private TLDs, IPs, raw hostnames).
func rootDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	// Strip port if present.
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	// IPs (v4 / v6 in brackets) are returned as-is so they still match.
	if net.ParseIP(host) != nil || (strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]")) {
		return host
	}
	rdn, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || rdn == "" {
		return host
	}
	return rdn
}

func (c *crawler) run(ctx context.Context, res *Result) {
	// Apply CrawlDurationSec by wrapping ctx in an additional timeout. Doing
	// this here (rather than at the public Crawl() call site) keeps the
	// public API stable while still letting Config own the policy.
	if c.cfg.CrawlDurationSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.cfg.CrawlDurationSec)*time.Second)
		defer cancel()
	}
	go func() {
		<-ctx.Done()
		c.stop.Store(true)
	}()

	// External-engine fast path: if the user opted into shelling out to the
	// upstream katana binary AND it's actually installed, defer the entire
	// crawl to it. runExternalKatana populates res in-place and returns
	// true; on false (binary missing / run failed) we fall through to the
	// internal pipeline below.
	if c.cfg.UseExternalKatana && c.runExternalKatana(ctx, res) {
		return
	}

	// Step 1: known files (robots/sitemap/security/humans) -> extra seeds.
	if c.cfg.KnownFiles {
		kfs, extras := fetchKnownFiles(ctx, c.client, c.cfg.Seeds, c.cfg, c.rateLimit)
		c.knownFiles = kfs
		// Extras are treated as depth-1 seeds: they're discovered via robots,
		// not direct seeds, so they shouldn't get a full MaxDepth budget on
		// their own. depth=0 means they're still allowed to recurse normally.
		for _, u := range extras {
			c.enqueue(ctx, u, "known", 0)
		}
	}

	// Step 2: real seeds.
	for _, s := range c.cfg.Seeds {
		c.enqueue(ctx, s, "seed", 0)
	}
	c.wg.Wait()

	// Sort pages for deterministic output.
	sort.Slice(c.pages, func(i, j int) bool { return c.pages[i].URL < c.pages[j].URL })

	res.Pages = c.pages
	res.Forms = c.forms
	res.SourceMaps = c.sourceMaps
	res.KnownFiles = c.knownFiles

	// Aggregate parameter / websocket sets to sorted slices.
	res.Parameters = sortedKeys(c.paramSet)
	res.WebSockets = sortedKeys(c.wsSet)

	// Aggregate per-page matches + source-map matches into the top-level
	// endpoint/secret lists.
	res.Endpoints, res.Secrets, res.Stats = aggregate(c.pages, c.smMatches)
	res.Stats.FormsFound = len(c.forms)
	res.Stats.ParamsFound = len(res.Parameters)
	res.Stats.WebSocketsFound = len(res.WebSockets)
	res.Stats.SourceMapsFetched = len(c.sourceMaps)
	res.Stats.KnownFilesFetched = len(c.knownFiles)
	res.Stats.Retries = int(c.retries.Load())
}

// enqueue schedules one URL for fetch. Idempotent (dedup via c.fetched);
// respects MaxPages cap and ctx cancellation; fast-paths when c.stop is set.
//
// Filter chain (in order, first failing rule wins):
//  1. ExcludePatterns (regex blocklist)
//  2. ExtensionFilter (lowercase set)
//  3. ExtensionMatch  (lowercase set, only when non-empty)
//  4. MatchRegex      (regex allowlist, only when non-empty)
//
// Every check is a no-op when its config is empty, so the cost on the fast
// path (no filters set) is just two map lookups.
func (c *crawler) enqueue(ctx context.Context, target, source string, depth int) {
	if c.stop.Load() {
		return
	}
	if !c.passesEnqueueFilters(target, source) {
		return
	}
	dedupKey := c.dedupKey(target)
	c.mu.Lock()
	if c.fetched[dedupKey] {
		c.mu.Unlock()
		return
	}
	if c.count.Load() >= int32(c.cfg.MaxPages) {
		c.mu.Unlock()
		return
	}
	c.fetched[dedupKey] = true
	c.count.Add(1)
	c.mu.Unlock()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.gate <- struct{}{}
		defer func() { <-c.gate }()
		if c.stop.Load() {
			return
		}
		p := c.fetchAndScan(ctx, target, source, depth)
		c.mu.Lock()
		c.pages = append(c.pages, p)
		c.mu.Unlock()
		// Aggregate query params from EVERY URL we fetched (regardless of
		// content-type) — even a CSS reference may carry ?v=hash.
		for _, k := range collectParams(target) {
			c.recordParam(k)
		}
		if depth >= c.cfg.MaxDepth {
			return
		}
		next := nextSource(p)
		for _, ref := range p.References {
			if !c.shouldFollow(ref) {
				continue
			}
			c.enqueue(ctx, ref, next, depth+1)
		}
	}()
}

// fetchAndScan: single-page work unit. Performs the fetch (with retries +
// rate limit), runs body scanners, extracts references, and (when enabled)
// extracts forms / source maps / WebSocket URLs.
func (c *crawler) fetchAndScan(ctx context.Context, target, source string, depth int) *Page {
	t0 := time.Now()
	p := &Page{URL: target, Source: source, Depth: depth}

	body, status, ct, err := c.do(ctx, target)
	p.Status = status
	p.ContentType = ct
	if err != nil {
		p.Err = err.Error()
		p.DurationMS = time.Since(t0).Milliseconds()
		return p
	}
	p.BodyLen = len(body)

	bodyStr := string(body)
	p.Matches = scanBody(bodyStr)
	p.References = extractReferences(target, bodyStr, ct)

	// Aggregate WebSocket URLs out of any body.
	for _, m := range wsURLPattern.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) >= 2 {
			c.recordWS(m[1])
		}
	}

	ctLower := strings.ToLower(ct)
	isHTML := strings.Contains(ctLower, "html")
	isJS := strings.Contains(ctLower, "javascript") || strings.HasSuffix(strings.ToLower(target), ".js")

	// Extract HTML forms; aggregate their input names into Parameters.
	if c.cfg.ExtractForms && isHTML {
		forms := extractForms(target, bodyStr)
		if len(forms) > 0 {
			c.mu.Lock()
			c.forms = append(c.forms, forms...)
			c.mu.Unlock()
			for _, f := range forms {
				for _, in := range f.Inputs {
					c.recordParam(in.Name)
				}
			}
		}
	}

	// AST endpoint extraction on JS bodies (opt-in, slower but more thorough).
	// Findings are merged into p.Matches alongside the regex pass; the
	// aggregator dedupes by Rule|Value so overlapping hits don't double up.
	if c.cfg.UseAST && isJS {
		astHits := extractEndpointsAST(bodyStr)
		if len(astHits) > 0 {
			p.Matches = append(p.Matches, astHits...)
		}
	}

	// Try fetching a sibling .map for any .js URL.
	if c.cfg.FetchSourceMaps && isJS {
		if info, ms := tryFetchSourceMap(ctx, c.client, target, c.cfg, c.rateLimit); info != nil {
			c.mu.Lock()
			c.sourceMaps = append(c.sourceMaps, info)
			c.smMatches = append(c.smMatches, ms...)
			c.mu.Unlock()
		}
	}

	p.DurationMS = time.Since(t0).Milliseconds()
	return p
}

// do is the central HTTP fetch helper used by every code path that needs
// raw bytes (the main crawler, knownfiles.go, sourcemap.go). It handles:
//   - rate limiting (per-host token bucket)
//   - custom UA / Headers / Cookie
//   - body cap (MaxBodyBytes)
//   - automatic retries on transient errors / 5xx
//
// Returns the body (truncated to MaxBodyBytes), the final HTTP status (0 if
// we never got a response), the response Content-Type, and any error.
func (c *crawler) do(ctx context.Context, target string) ([]byte, int, string, error) {
	return do(ctx, c.client, target, c.cfg, c.rateLimit)
}

// matchesExclude returns true if any compiled exclude pattern fires.
func (c *crawler) matchesExclude(target string) bool {
	for _, re := range c.excludes {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

// passesEnqueueFilters bundles all the URL-level admission checks. "seed"-
// sourced URLs always pass extension-based filters so the crawl can
// bootstrap (we don't want users dropping HTML seeds when they only want
// .js results -- HTML is the source of those references).
func (c *crawler) passesEnqueueFilters(target, source string) bool {
	if c.matchesExclude(target) {
		return false
	}
	ext := urlExtension(target)
	if source != "seed" && len(c.extFilter) > 0 && c.extFilter[ext] {
		return false
	}
	if source != "seed" && len(c.extMatch) > 0 && ext != "" && !c.extMatch[ext] {
		return false
	}
	// MatchRegex (allowlist) is also seed-exempt: seeds must always pass so
	// the crawl can bootstrap. Otherwise a user who wants only `/api/`
	// results couldn't ever start from `/`.
	if source != "seed" && len(c.matches) > 0 {
		hit := false
		for _, re := range c.matches {
			if re.MatchString(target) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// dedupKey is what we feed into c.fetched to decide if a URL is already
// scheduled. Default is the URL itself; with IgnoreQueryParams it strips
// the query+fragment so /foo?a=1 and /foo?a=2 collapse into one fetch.
func (c *crawler) dedupKey(target string) string {
	if !c.cfg.IgnoreQueryParams {
		return target
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// urlExtension returns the lowercased file extension (without dot) of a
// URL's path, or "" when there isn't one. Used by ExtensionMatch /
// ExtensionFilter -- both work in the same lowercase / no-dot space.
func urlExtension(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return ""
	}
	p := u.Path
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))
	return ext
}

func (c *crawler) recordParam(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	c.mu.Lock()
	c.paramSet[name] = struct{}{}
	c.mu.Unlock()
}

func (c *crawler) recordWS(u string) {
	u = strings.TrimSpace(u)
	if u == "" {
		return
	}
	c.mu.Lock()
	c.wsSet[u] = struct{}{}
	c.mu.Unlock()
}

// shouldFollow applies SameHostOnly + AllowExternalJS + IncludeHosts +
// FieldScope. Note this is the FOLLOW gate (parent -> child reference);
// admission filters (ExcludePatterns / Match / Ext*) are handled in
// passesEnqueueFilters and run later inside enqueue itself.
func (c *crawler) shouldFollow(ref string) bool {
	if c.matchesExclude(ref) {
		return false
	}
	u, err := url.Parse(ref)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Host)
	if c.seedHosts[host] || c.allowHosts[host] {
		return true
	}
	// FieldScope=rdn: allow any host whose effective TLD+1 matches a seed
	// host's TLD+1. "api.example.com" + "www.example.com" both pass with
	// seed = "example.com".
	if c.scopeIsRDN {
		if rdn := rootDomain(host); rdn != "" && c.seedRoots[rdn] {
			return true
		}
	}
	// Cross-host: allow .js URLs only if AllowExternalJS, skip otherwise.
	if c.cfg.SameHostOnly {
		if c.cfg.AllowExternalJS && strings.HasSuffix(strings.ToLower(u.Path), ".js") {
			return true
		}
		return false
	}
	return true
}

// nextSource translates a parent page's source/CT into the child's source tag.
func nextSource(parent *Page) string {
	if parent == nil {
		return "html"
	}
	ct := strings.ToLower(parent.ContentType)
	if strings.Contains(ct, "javascript") || strings.HasSuffix(strings.ToLower(parent.URL), ".js") {
		return "js"
	}
	return "html"
}

// ----- Free helpers used by knownfiles.go / sourcemap.go too -----

// do is the package-level low-level HTTP fetch helper. We keep both a method
// (crawler.do) and a free function so files like knownfiles.go can call it
// without being forced to construct a crawler.
//
// rl is optional (nil = unlimited). Counted retries don't trigger extra
// rate-limit waits (the wait happens once before the first request) — the
// retry path keeps the original "slot" so we don't double-pay.
//
// Returns the body (truncated to cfg.MaxBodyBytes), HTTP status (0 on
// connect failure), Content-Type, and any error after retries are exhausted.
func do(ctx context.Context, client *http.Client, target string, cfg *Config, rl *rateLimiter) ([]byte, int, string, error) {
	var (
		lastBody []byte
		lastCT   string
		lastErr  error
		status   int
	)
	if err := rl.wait(ctx, target); err != nil {
		return nil, 0, "", err
	}
	attempts := cfg.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 0; attempt < attempts; attempt++ {
		if ctx.Err() != nil {
			return lastBody, status, lastCT, ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, 0, "", err
		}
		req.Header.Set("User-Agent", cfg.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/javascript,text/javascript,*/*;q=0.8")
		for k, v := range cfg.Headers {
			if k == "" {
				continue
			}
			req.Header.Set(k, v)
		}
		if cfg.Cookie != "" {
			req.Header.Set("Cookie", cfg.Cookie)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if isRetryable(err) && attempt < attempts-1 {
				continue
			}
			return lastBody, status, lastCT, err
		}
		status = resp.StatusCode
		lastCT = resp.Header.Get("Content-Type")

		body, rerr := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxBodyBytes))
		_ = resp.Body.Close()
		lastBody = body
		if rerr != nil {
			lastErr = rerr
			if attempt < attempts-1 {
				continue
			}
			return lastBody, status, lastCT, rerr
		}
		// 5xx is retryable up to MaxRetries.
		if status >= 500 && status <= 599 && attempt < attempts-1 {
			continue
		}
		return body, status, lastCT, nil
	}
	return lastBody, status, lastCT, lastErr
}

// isRetryable returns true for net errors worth retrying (timeout, refused,
// reset). DNS NXDOMAIN and TLS errors are NOT retried — they won't fix on
// retry and just waste the budget.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := err.Error()
	for _, marker := range []string{
		"connection reset",
		"connection refused",
		"i/o timeout",
		"server closed",
		"unexpected EOF",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// buildClient wires a *http.Client tuned for crawling: TLS-skip, capped
// redirects, configurable timeout, optional Proxy, optional cookie jar.
func buildClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
	}
	if cfg.Proxy != "" {
		if pu, err := url.Parse(cfg.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
		// Bad proxy URL is silently dropped — the alternative is failing the
		// whole crawl. The user will notice via missing results.
	}
	c := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
	}
	// A cookie jar lets us preserve session cookies across redirects + .map
	// fetches even if the user only set the initial Cookie via Config.Cookie
	// header.
	if jar, err := cookiejar.New(nil); err == nil {
		c.Jar = jar
	}
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

// extractReferences finds same-page links + JS imports relative to baseURL.
// HTML pages contribute <script src> + <link rel=preload> + <a href> + <img>
// + <iframe>; JS bodies contribute every "[^"]+\.js" string. All values are
// resolved to absolute URLs.
func extractReferences(baseURL, body, contentType string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	out := make([]string, 0, 16)
	seen := make(map[string]struct{})
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") {
			return
		}
		ref, err := base.Parse(raw)
		if err != nil {
			return
		}
		// Drop fragments — they're never new resources.
		ref.Fragment = ""
		s := ref.String()
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "html") {
		if doc, err := goquery.NewDocumentFromReader(strings.NewReader(body)); err == nil {
			doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
				if v, ok := s.Attr("src"); ok {
					add(v)
				}
			})
			doc.Find("link[href]").Each(func(_ int, s *goquery.Selection) {
				if rel, _ := s.Attr("rel"); rel == "modulepreload" || rel == "preload" || rel == "stylesheet" {
					if v, ok := s.Attr("href"); ok {
						add(v)
					}
				}
			})
			doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
				if v, ok := s.Attr("href"); ok {
					add(v)
				}
			})
			doc.Find("iframe[src]").Each(func(_ int, s *goquery.Selection) {
				if v, ok := s.Attr("src"); ok {
					add(v)
				}
			})
			// <form action="..."> -- the form harvester uses these too, but
			// it's nice to also follow them as URLs (often /login pages).
			doc.Find("form[action]").Each(func(_ int, s *goquery.Selection) {
				if v, ok := s.Attr("action"); ok {
					add(v)
				}
			})
		}
	}

	// Always also scan the raw body for ".js" string literals — works for
	// inline <script> bodies, JS bundles, and any text/plain response.
	for _, m := range jsURLPattern.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 {
			add(m[1])
		}
	}
	return out
}

// scanBody runs every rule against text and returns deduplicated matches.
func scanBody(text string) []*Match {
	if len(text) == 0 {
		return nil
	}
	out := make([]*Match, 0, 8)
	seen := make(map[string]struct{})
	for _, ru := range rules {
		matches := ru.Re.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			val := m[0]
			if ru.Group > 0 && ru.Group < len(m) {
				val = m[ru.Group]
			}
			val = strings.TrimSpace(val)
			if len(val) < ru.MinLen {
				continue
			}
			key := ru.Name + "|" + val
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, &Match{
				Type:     ru.Type,
				Rule:     ru.Name,
				Value:    maybeRedact(ru.Type, val),
				Severity: ru.Severity,
			})
		}
	}
	return out
}

// maybeRedact obfuscates the middle of secret values so the output is safe to
// share in tickets/screenshots, while preserving enough prefix/suffix to
// confirm the find.
func maybeRedact(kind, v string) string {
	if kind != "secret" || len(v) < 12 {
		return v
	}
	keep := 4
	return v[:keep] + strings.Repeat("*", len(v)-2*keep) + v[len(v)-keep:]
}

// aggregate folds per-page matches + source-map matches into deduplicated,
// sorted top-level lists.
func aggregate(pages []*Page, extraMatches []*Match) ([]string, []*Match, Stats) {
	var stats Stats
	endpointSet := map[string]struct{}{}
	secretMap := map[string]*Match{}

	consume := func(ms []*Match) {
		for _, m := range ms {
			if m == nil {
				continue
			}
			switch m.Type {
			case "endpoint":
				endpointSet[m.Value] = struct{}{}
			case "secret":
				key := m.Rule + "|" + m.Value
				if _, ok := secretMap[key]; !ok {
					secretMap[key] = m
				}
			}
		}
	}

	for _, p := range pages {
		stats.PagesFetched++
		if p.Err != "" {
			stats.Errors++
		}
		ct := strings.ToLower(p.ContentType)
		if strings.Contains(ct, "javascript") || strings.HasSuffix(strings.ToLower(p.URL), ".js") {
			stats.JSFiles++
		}
		consume(p.Matches)
	}
	consume(extraMatches)

	endpoints := make([]string, 0, len(endpointSet))
	for k := range endpointSet {
		endpoints = append(endpoints, k)
	}
	sort.Strings(endpoints)
	stats.EndpointsFound = len(endpoints)

	secrets := make([]*Match, 0, len(secretMap))
	for _, m := range secretMap {
		secrets = append(secrets, m)
	}
	sort.Slice(secrets, func(i, j int) bool {
		if secrets[i].Rule != secrets[j].Rule {
			return secrets[i].Rule < secrets[j].Rule
		}
		return secrets[i].Value < secrets[j].Value
	})
	stats.SecretsFound = len(secrets)
	return endpoints, secrets, stats
}

// sortedKeys returns a sorted slice of the keys of any string-set map.
func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
