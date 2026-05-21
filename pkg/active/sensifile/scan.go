package sensifile

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Scan probes all (baseURL × path) combinations and returns the merged Result.
func Scan(ctx context.Context, cfg Config) *Result {
	cfg.Normalize()
	t0 := time.Now()
	res := &Result{Stats: Stats{BySeverity: map[string]int{}}}
	if len(cfg.BaseURLs) == 0 {
		return res
	}

	// Build the effective rule list. If cfg.Paths is non-empty, treat each
	// entry as a custom "info"-severity probe (no body confirmation).
	rules := defaultRules
	if len(cfg.Paths) > 0 {
		rules = make([]rule, 0, len(cfg.Paths))
		for _, p := range cfg.Paths {
			rules = append(rules, rule{Path: p, Category: "custom", Severity: "info", Description: "Custom path"})
		}
	}

	// Filter by severity if requested.
	if cfg.IncludeMediumOnly {
		filtered := rules[:0]
		for _, r := range rules {
			if r.Severity != "info" && r.Severity != "low" {
				filtered = append(filtered, r)
			} else if r.Severity == "low" {
				// keep low — only drop pure info noise.
				filtered = append(filtered, r)
			}
		}
		rules = filtered
	}

	client := buildClient(&cfg)
	res.Stats.URLs = len(cfg.BaseURLs)
	res.Stats.PathsPerURL = len(rules)

	var (
		mu       sync.Mutex
		findings []*Finding
		probes   []*Probe
		wg       sync.WaitGroup
		gate     = make(chan struct{}, cfg.Concurrency)
	)

	for _, base := range cfg.BaseURLs {
		base := strings.TrimRight(base, "/")
		if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			base = "https://" + base
		}
		for _, ru := range rules {
			ru := ru
			select {
			case <-ctx.Done():
				break
			default:
			}
			wg.Add(1)
			gate <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-gate }()
				probe, hit := probeOne(ctx, client, base, ru, &cfg)
				mu.Lock()
				probes = append(probes, probe)
				if hit != nil {
					findings = append(findings, hit)
				}
				mu.Unlock()
			}()
		}
	}
	wg.Wait()

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].BaseURL != findings[j].BaseURL {
			return findings[i].BaseURL < findings[j].BaseURL
		}
		if findings[i].Severity != findings[j].Severity {
			return sevRank(findings[i].Severity) > sevRank(findings[j].Severity)
		}
		return findings[i].Path < findings[j].Path
	})
	res.Findings = findings
	res.Probes = probes
	res.Stats.ProbesSent = len(probes)
	res.Stats.Findings = len(findings)
	for _, f := range findings {
		res.Stats.BySeverity[f.Severity]++
	}
	res.DurationMS = time.Since(t0).Milliseconds()
	return res
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	}
	return 1
}

// probeOne runs HEAD→GET for one path against one base URL.
func probeOne(ctx context.Context, client *http.Client, base string, ru rule, cfg *Config) (*Probe, *Finding) {
	t0 := time.Now()
	url := base + ru.Path
	probe := &Probe{URL: url}

	// 1) HEAD first — cheap, skips body transfer if not present.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		probe.Err = err.Error()
		probe.DurationMS = time.Since(t0).Milliseconds()
		return probe, nil
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		probe.Err = err.Error()
		probe.DurationMS = time.Since(t0).Milliseconds()
		return probe, nil
	}
	resp.Body.Close()
	probe.Status = resp.StatusCode
	probe.ContentType = resp.Header.Get("Content-Type")

	// 2) If HEAD says "definitely not there", bail.
	if resp.StatusCode == 404 || resp.StatusCode == 410 {
		probe.DurationMS = time.Since(t0).Milliseconds()
		return probe, nil
	}
	// 3) If HEAD is OK without a body or the rule wants confirmation, fetch GET.
	wantConfirm := ru.Confirm != nil
	wantBody := wantConfirm || (resp.StatusCode == 200 && cfg.MaxBodyBytes > 0)
	var bodySnippet string
	var bodyLen int
	if wantBody || resp.StatusCode == 405 /* HEAD not allowed */ {
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		req2.Header.Set("User-Agent", cfg.UserAgent)
		req2.Header.Set("Range", "bytes=0-2047") // hint, ignored by many servers
		gresp, gerr := client.Do(req2)
		if gerr == nil {
			defer gresp.Body.Close()
			probe.Status = gresp.StatusCode
			probe.ContentType = gresp.Header.Get("Content-Type")
			b, _ := io.ReadAll(io.LimitReader(gresp.Body, cfg.MaxBodyBytes))
			bodyLen = len(b)
			bodySnippet = string(b)
		}
	}

	// 4) Decide confirmation.
	if probe.Status != 200 && probe.Status != 206 {
		probe.DurationMS = time.Since(t0).Milliseconds()
		return probe, nil
	}
	if ru.Confirm != nil && !ru.Confirm(bodySnippet) {
		probe.DurationMS = time.Since(t0).Milliseconds()
		return probe, nil
	}
	// Default SPA-fallback rejection: if no explicit confirmer and the body
	// looks like HTML while the path's file extension doesn't suggest HTML,
	// treat it as the SPA catch-all returning index.html.
	if ru.Confirm == nil && looksLikeHTMLFallback(ru.Path, probe.ContentType, bodySnippet) {
		probe.DurationMS = time.Since(t0).Milliseconds()
		return probe, nil
	}

	probe.Confirmed = true
	probe.DurationMS = time.Since(t0).Milliseconds()
	hit := &Finding{
		BaseURL:     base,
		Path:        ru.Path,
		URL:         url,
		Category:    ru.Category,
		Severity:    ru.Severity,
		Description: ru.Description,
		Status:      probe.Status,
		ContentType: probe.ContentType,
		BodyLen:     bodyLen,
		BodySnippet: truncate(bodySnippet, 512),
		DurationMS:  probe.DurationMS,
	}
	return probe, hit
}

// looksLikeHTMLFallback returns true when (a) the response is HTML and
// (b) the path's extension implies it should NOT be HTML — the classic
// SPA-catch-all symptom. Paths without extensions (e.g. `/admin/`) are
// allowed through because admin landing pages legitimately return HTML.
func looksLikeHTMLFallback(path, ct, body string) bool {
	ctLow := strings.ToLower(ct)
	bodyLow := strings.ToLower(strings.TrimLeft(body, " \t\r\n"))
	htmlish := strings.HasPrefix(ctLow, "text/html") ||
		strings.HasPrefix(bodyLow, "<!doctype html") ||
		strings.HasPrefix(bodyLow, "<html")
	if !htmlish {
		return false
	}
	// Find the last "." in the basename.
	base := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		base = path[i+1:]
	}
	dot := strings.LastIndexByte(base, '.')
	if dot < 0 {
		// No extension → admin landing / Spring actuator root / etc. Keep.
		return false
	}
	ext := strings.ToLower(base[dot+1:])
	switch ext {
	case "html", "htm", "xhtml":
		return false
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func buildClient(cfg *Config) *http.Client {
	c := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       30 * time.Second,
			ResponseHeaderTimeout: cfg.Timeout,
		},
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
