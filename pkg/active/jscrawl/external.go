package jscrawl

import (
	"context"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/wgpsec/ENScan/pkg/active/katana"
)

// runExternalKatana drives a one-shot katana CLI run and folds its results
// into the crawler's collection slices. Returns true when external execution
// fully replaced the internal crawl; false signals the caller to fall back
// to the in-process pipeline (binary missing, run failed, etc.).
//
// Why fall back instead of failing hard: many users will tick "use external
// katana" once and forget; if we fail the whole crawl they'd just see "0
// results" with no clue why. Falling back keeps the run useful and the
// status indicator on the dashboard tells them katana wasn't found.
//
// Trade-offs vs internal mode:
//   - We do NOT run our secret scanner on bodies (we don't have them).
//   - We DO still run sourcemap fetching on .js URLs katana surfaces (cheap
//     extra fetch, high signal).
//   - WebSockets aren't auto-extracted (would need response bodies too).
//   - Forms come straight from katana's -fx output.
func (c *crawler) runExternalKatana(ctx context.Context, res *Result) bool {
	info := katana.Detect(c.cfg.KatanaBin)
	if !info.OK {
		if info.Error != "" {
			log.Printf("[jscrawl] external katana requested but broken: %s", info.Error)
		} else {
			log.Printf("[jscrawl] external katana requested but not found in PATH; falling back to internal")
		}
		return false
	}
	log.Printf("[jscrawl] using external katana at %s (v%s)", info.Path, info.Version)

	kcfg := katana.Config{
		Bin:               info.Path,
		Seeds:             c.cfg.Seeds,
		MaxDepth:          c.cfg.MaxDepth,
		Concurrency:       c.cfg.Concurrency,
		Timeout:           c.cfg.Timeout,
		CrawlDuration:     time.Duration(c.cfg.CrawlDurationSec) * time.Second,
		UserAgent:         c.cfg.UserAgent,
		Cookie:            c.cfg.Cookie,
		Headers:           c.cfg.Headers,
		Proxy:             c.cfg.Proxy,
		RatePerSecond:     c.cfg.RatePerSecond,
		MaxRetries:        c.cfg.MaxRetries,
		JSCrawl:           true,
		KnownFiles:        c.cfg.KnownFiles,
		ExtractForms:      c.cfg.ExtractForms,
		Headless:          c.cfg.HeadlessKatana,
		NoSandbox:         true, // safe default; required inside Docker
		FieldScope:        c.cfg.FieldScope,
		ExcludePatterns:   c.cfg.ExcludePatterns,
		MatchRegex:        c.cfg.MatchRegex,
		ExtensionMatch:    c.cfg.ExtensionMatch,
		ExtensionFilter:   c.cfg.ExtensionFilter,
		IgnoreQueryParams: c.cfg.IgnoreQueryParams,
	}

	outputs, err := katana.Run(ctx, kcfg)
	if err != nil {
		log.Printf("[jscrawl] external katana failed: %v; falling back to internal", err)
		return false
	}

	// Walk katana outputs, dedup URLs, build our Page+Form set.
	seenURL := map[string]bool{}
	for _, o := range outputs {
		u := strings.TrimSpace(o.Request.Endpoint)
		if u == "" || seenURL[u] {
			continue
		}
		seenURL[u] = true

		p := &Page{
			URL:         u,
			Source:      "katana", // mark provenance distinctly from "seed"/"html"/"js"
			Depth:       0,        // katana doesn't expose depth in JSONL by default
			Status:      o.Response.StatusCode,
			ContentType: o.Response.ContentType,
		}
		c.pages = append(c.pages, p)

		// Aggregate query params from every URL.
		for _, k := range collectParams(u) {
			c.recordParam(k)
		}

		// Convert any forms katana attached to this URL.
		for _, f := range o.Forms {
			inputs := make([]*FormInput, 0, len(f.Inputs))
			for name, val := range f.Inputs {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				inputs = append(inputs, &FormInput{Name: name, Value: val})
				c.recordParam(name)
			}
			absAction := f.Action
			// Resolve relative actions against the page URL.
			if absAction != "" && !strings.HasPrefix(absAction, "http://") && !strings.HasPrefix(absAction, "https://") {
				if base, perr := url.Parse(u); perr == nil {
					if rel, rerr := base.Parse(absAction); rerr == nil {
						absAction = rel.String()
					}
				}
			}
			if absAction == "" {
				absAction = u
			}
			method := strings.ToUpper(strings.TrimSpace(f.Method))
			if method == "" {
				method = "GET"
			}
			c.forms = append(c.forms, &Form{
				URL:     u,
				Action:  absAction,
				Method:  method,
				EncType: strings.ToLower(strings.TrimSpace(f.EncType)),
				Inputs:  inputs,
			})
		}
	}

	// Even in external mode we still try fetching .js.map files for any JS
	// URL we surfaced -- this is a separate fetch that our internal crawler
	// would have done too, so it's not duplicate traffic.
	if c.cfg.FetchSourceMaps {
		for u := range seenURL {
			if !strings.HasSuffix(strings.ToLower(stripQuery(u)), ".js") {
				continue
			}
			if info, ms := tryFetchSourceMap(ctx, c.client, u, c.cfg, c.rateLimit); info != nil {
				c.sourceMaps = append(c.sourceMaps, info)
				c.smMatches = append(c.smMatches, ms...)
			}
		}
	}

	// Sort pages for deterministic output.
	sort.Slice(c.pages, func(i, j int) bool { return c.pages[i].URL < c.pages[j].URL })

	res.Pages = c.pages
	res.Forms = c.forms
	res.SourceMaps = c.sourceMaps
	res.Parameters = sortedKeys(c.paramSet)
	res.WebSockets = sortedKeys(c.wsSet) // empty unless internal also ran

	// Build endpoints list from URLs we visited; secrets only come from
	// sourcesContent recovery (we have no bodies otherwise).
	endpoints := make([]string, 0, len(seenURL))
	for u := range seenURL {
		endpoints = append(endpoints, u)
	}
	sort.Strings(endpoints)
	res.Endpoints = endpoints

	// Run aggregate over our (mostly empty) pages slice for stat counts;
	// then fold in source-map matches as the secret source.
	_, secrets, _ := aggregate(nil, c.smMatches)
	res.Secrets = secrets
	res.Stats = Stats{
		PagesFetched:      len(c.pages),
		EndpointsFound:    len(endpoints),
		SecretsFound:      len(secrets),
		FormsFound:        len(c.forms),
		ParamsFound:       len(res.Parameters),
		WebSocketsFound:   len(res.WebSockets),
		SourceMapsFetched: len(c.sourceMaps),
	}
	// JS file count for stats line.
	for _, p := range c.pages {
		if strings.Contains(strings.ToLower(p.ContentType), "javascript") ||
			strings.HasSuffix(strings.ToLower(stripQuery(p.URL)), ".js") {
			res.Stats.JSFiles++
		}
	}
	return true
}

// stripQuery returns the URL with any ?query and #fragment chopped off.
// Used for extension-suffix checks so /app.js?v=hash still ends in .js.
func stripQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}
