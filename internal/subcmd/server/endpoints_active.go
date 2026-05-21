// Active probing HTTP endpoints: subbrute / httpx / portscan.
//
// All three are exposed under /api/active/*. Each handler is synchronous —
// it blocks until the scan finishes, then returns the full result list as
// JSON. For long scans the dashboard shows a spinner. We deliberately avoid
// SSE here to keep the surface area small; if a long-running mode is needed
// later it can be added without changing the existing contract.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wgpsec/ENScan/pkg/active/asn"
	"github.com/wgpsec/ENScan/pkg/active/cdninfo"
	"github.com/wgpsec/ENScan/pkg/active/dnsadv"
	"github.com/wgpsec/ENScan/pkg/active/dnsrecord"
	"github.com/wgpsec/ENScan/pkg/active/httpx"
	"github.com/wgpsec/ENScan/pkg/active/jscrawl"
	"github.com/wgpsec/ENScan/pkg/active/katana"
	"github.com/wgpsec/ENScan/pkg/active/portscan"
	"github.com/wgpsec/ENScan/pkg/active/sensifile"
	"github.com/wgpsec/ENScan/pkg/active/subdomain"
	"github.com/wgpsec/ENScan/pkg/active/tlscert"
	"github.com/wgpsec/ENScan/pkg/active/webmeta"
	"github.com/wgpsec/ENScan/pkg/active/whoisrdap"
)

// ---- safety caps shared by all three handlers ----
const (
	activeMaxTargets     = 500
	activeMaxConcurrency = 1000
	activeMaxRuntimeSec  = 600 // 10 min hard cap per request
	activeDefaultRuntime = 120 * time.Second
)

// activeReqCtx wraps the http request context with the per-request hard cap.
// Caller MUST call cancel() to release resources.
func activeReqCtx(r *http.Request, requestedTimeoutSec int) (context.Context, context.CancelFunc) {
	if requestedTimeoutSec <= 0 || requestedTimeoutSec > activeMaxRuntimeSec {
		return context.WithTimeout(r.Context(), activeDefaultRuntime)
	}
	return context.WithTimeout(r.Context(), time.Duration(requestedTimeoutSec)*time.Second)
}

// ---- /api/active/subbrute ----

type subbruteReq struct {
	Domain         string   `json:"domain"`
	Domains        []string `json:"domains"`
	WordlistPath   string   `json:"wordlist_path"` // "builtin:top5000" | "builtin:top20000" | absolute path
	Resolvers      []string `json:"resolvers"`
	Concurrency    int      `json:"concurrency"`
	TimeoutSec     int      `json:"timeout_sec"`
	SkipWildcard   bool     `json:"skip_wildcard"`
	WildcardProbes int      `json:"wildcard_probes"`
	IncludeRoot    bool     `json:"include_root"`
	HardTimeoutSec int      `json:"hard_timeout_sec"` // request-level cap
}

func (s *server) handleActiveSubbrute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req subbruteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	domains := mergeDomains(req.Domain, req.Domains)
	if len(domains) == 0 {
		writeError(w, 400, "domain / domains required")
		return
	}
	if len(domains) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many domains (%d > %d)", len(domains), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}

	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := subdomain.Config{
		WordlistPath:   req.WordlistPath,
		Resolvers:      req.Resolvers,
		Concurrency:    req.Concurrency,
		Timeout:        time.Duration(maxInt(req.TimeoutSec, 1)) * time.Second,
		SkipWildcard:   req.SkipWildcard,
		WildcardProbes: req.WildcardProbes,
		IncludeRoot:    req.IncludeRoot,
	}
	brute := subdomain.New(cfg)

	t0 := time.Now()
	all := make([]*subdomain.Result, 0, 64)
	for _, d := range domains {
		if ctx.Err() != nil {
			break
		}
		res, err := brute.Run(ctx, d, nil)
		if err != nil {
			// Continue best-effort across domains; report per-domain error in
			// the summary if needed.
			continue
		}
		all = append(all, res...)
	}

	writeJSON(w, 200, map[string]any{
		"results":     all,
		"count":       len(all),
		"duration_ms": time.Since(t0).Milliseconds(),
		"domains":     domains,
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/httpx ----

type httpxReq struct {
	Targets         []string `json:"targets"`
	TargetsCSV      string   `json:"targets_csv"` // alternative single-string CSV input
	Concurrency     int      `json:"concurrency"`
	TimeoutSec      int      `json:"timeout_sec"`
	FetchFavicon    bool     `json:"fetch_favicon"`
	FollowRedirects bool     `json:"follow_redirects"`
	SchemesAuto     bool     `json:"schemes_auto"` // when true, probe both http+https for bare hosts
	HardTimeoutSec  int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveHTTPX(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req httpxReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	targets := mergeTargets(req.Targets, req.TargetsCSV)
	if len(targets) == 0 {
		writeError(w, 400, "targets required")
		return
	}
	if len(targets) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many targets (%d > %d)", len(targets), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}

	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := httpx.Config{
		Concurrency:     req.Concurrency,
		Timeout:         time.Duration(maxInt(req.TimeoutSec, 1)) * time.Second,
		FetchFavicon:    req.FetchFavicon,
		FollowRedirects: req.FollowRedirects,
		SchemesAuto:     req.SchemesAuto,
	}
	prober := httpx.New(cfg)

	t0 := time.Now()
	results := prober.Run(ctx, targets, nil)
	writeJSON(w, 200, map[string]any{
		"results":     results,
		"count":       len(results),
		"duration_ms": time.Since(t0).Milliseconds(),
		"targets":     targets,
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/portscan ----

type portscanReq struct {
	Targets            []string `json:"targets"`
	TargetsCSV         string   `json:"targets_csv"`
	Preset             string   `json:"preset"`     // top100|top1000|all
	PortRange          string   `json:"port_range"` // "80,443,8000-8100"
	Concurrency        int      `json:"concurrency"`
	PerHostConcurrency int      `json:"per_host_concurrency"`
	TimeoutMs          int      `json:"timeout_ms"`
	RetryTimeoutMs     int      `json:"retry_timeout_ms"`
	RetryPerPort       int      `json:"retry_per_port"`
	GrabBanner         bool     `json:"grab_banner"`
	BannerTimeoutMs    int      `json:"banner_timeout_ms"`
	SkipResolve        bool     `json:"skip_resolve"`
	HardTimeoutSec     int      `json:"hard_timeout_sec"`
}

func (s *server) handleActivePortscan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req portscanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	targets := mergeTargets(req.Targets, req.TargetsCSV)
	if len(targets) == 0 {
		writeError(w, 400, "targets required")
		return
	}
	if len(targets) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many targets (%d > %d)", len(targets), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}

	// Validate port-range string up-front for friendlier error messages.
	if req.PortRange != "" {
		if _, err := portscan.ParseRange(req.PortRange); err != nil {
			writeError(w, 400, "invalid port_range: "+err.Error())
			return
		}
	}

	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := portscan.Config{
		PortPreset:         req.Preset,
		PortRange:          req.PortRange,
		Concurrency:        req.Concurrency,
		PerHostConcurrency: req.PerHostConcurrency,
		Timeout:            time.Duration(maxInt(req.TimeoutMs, 100)) * time.Millisecond,
		RetryTimeout:       time.Duration(maxInt(req.RetryTimeoutMs, 100)) * time.Millisecond,
		RetryPerPort:       req.RetryPerPort,
		GrabBanner:         req.GrabBanner,
		BannerTimeout:      time.Duration(maxInt(req.BannerTimeoutMs, 100)) * time.Millisecond,
		SkipResolve:        req.SkipResolve,
	}
	scanner := portscan.New(cfg)

	t0 := time.Now()
	results, err := scanner.Run(ctx, targets, nil)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"results":     results,
		"count":       len(results),
		"duration_ms": time.Since(t0).Milliseconds(),
		"targets":     targets,
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/dnsadv ----

type dnsadvReq struct {
	Domain               string   `json:"domain"`
	Subdomains           []string `json:"subdomains"`
	SubdomainsCSV        string   `json:"subdomains_csv"`
	Mode                 string   `json:"mode"` // both|axfr|takeover
	Resolvers            []string `json:"resolvers"`
	AXFRTimeoutSec       int      `json:"axfr_timeout_sec"`
	TakeoverConcurrency  int      `json:"takeover_concurrency"`
	TakeoverTimeoutSec   int      `json:"takeover_timeout_sec"`
	IncludeInformational bool     `json:"include_informational"`
	HardTimeoutSec       int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveDNSAdv(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req dnsadvReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	subs := mergeTargets(req.Subdomains, req.SubdomainsCSV)
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "both"
	}
	if req.Domain == "" && mode != "takeover" {
		writeError(w, 400, "domain required for axfr/both mode")
		return
	}
	if mode == "takeover" && len(subs) == 0 {
		writeError(w, 400, "subdomains required for takeover mode")
		return
	}
	if len(subs) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many subdomains (%d > %d)", len(subs), activeMaxTargets))
		return
	}
	if req.TakeoverConcurrency > activeMaxConcurrency {
		req.TakeoverConcurrency = activeMaxConcurrency
	}

	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := dnsadv.Config{
		Mode:                mode,
		Resolvers:           req.Resolvers,
		AXFRTimeout:         time.Duration(maxInt(req.AXFRTimeoutSec, 1)) * time.Second,
		TakeoverConcurrency: req.TakeoverConcurrency,
		TakeoverHTTPTimeout: time.Duration(maxInt(req.TakeoverTimeoutSec, 1)) * time.Second,
		IncludeUnvulnerable: req.IncludeInformational,
	}
	scanner := dnsadv.New(cfg)
	t0 := time.Now()
	result := scanner.Scan(ctx, req.Domain, subs)
	writeJSON(w, 200, map[string]any{
		"result":      result,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/jscrawl ----

type jscrawlReq struct {
	Seeds           []string `json:"seeds"`
	SeedsCSV        string   `json:"seeds_csv"`
	MaxDepth        int      `json:"max_depth"`
	MaxPages        int      `json:"max_pages"`
	Concurrency     int      `json:"concurrency"`
	TimeoutSec      int      `json:"timeout_sec"`
	MaxBodyMB       int      `json:"max_body_mb"`
	SameHostOnly    bool     `json:"same_host_only"`
	AllowExternalJS bool     `json:"allow_external_js"`
	FollowRedirects bool     `json:"follow_redirects"`
	UserAgent       string   `json:"user_agent"`
	HardTimeoutSec  int      `json:"hard_timeout_sec"`

	// ---- katana-compat extensions ----
	Headers         map[string]string `json:"headers,omitempty"`
	Cookie          string            `json:"cookie,omitempty"`
	Proxy           string            `json:"proxy,omitempty"`
	KnownFiles      bool              `json:"known_files,omitempty"`
	FetchSourceMaps bool              `json:"fetch_source_maps,omitempty"`
	ExtractForms    bool              `json:"extract_forms,omitempty"`
	ExcludePatterns []string          `json:"exclude_patterns,omitempty"`
	IncludeHosts    []string          `json:"include_hosts,omitempty"`
	MaxRetries      int               `json:"max_retries,omitempty"`
	RatePerSecond   int               `json:"rate_per_second,omitempty"`

	// ---- katana-compat scope/filter (round 2) ----
	MatchRegex        []string `json:"match_regex,omitempty"`
	ExtensionMatch    []string `json:"extension_match,omitempty"`
	ExtensionFilter   []string `json:"extension_filter,omitempty"`
	FieldScope        string   `json:"field_scope,omitempty"`
	IgnoreQueryParams bool     `json:"ignore_query_params,omitempty"`
	CrawlDurationSec  int      `json:"crawl_duration_sec,omitempty"`

	// ---- external katana shell-out ----
	UseExternalKatana bool   `json:"use_external_katana,omitempty"`
	KatanaBin         string `json:"katana_bin,omitempty"`
	HeadlessKatana    bool   `json:"headless_katana,omitempty"`

	// ---- AST endpoint extractor ----
	UseAST bool `json:"use_ast,omitempty"`
}

func (s *server) handleActiveJSCrawl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req jscrawlReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	seeds := mergeTargets(req.Seeds, req.SeedsCSV)
	// Normalize each seed: ensure scheme prefix.
	for i, s := range seeds {
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			seeds[i] = "https://" + s
		}
	}
	if len(seeds) == 0 {
		writeError(w, 400, "seeds required")
		return
	}
	if len(seeds) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many seeds (%d > %d)", len(seeds), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}
	if req.MaxPages <= 0 {
		req.MaxPages = 200
	}
	if req.MaxPages > 2000 {
		req.MaxPages = 2000
	}
	if req.MaxBodyMB <= 0 {
		req.MaxBodyMB = 5
	}

	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := jscrawl.Config{
		Seeds:           seeds,
		MaxDepth:        req.MaxDepth,
		MaxPages:        req.MaxPages,
		Concurrency:     req.Concurrency,
		Timeout:         time.Duration(maxInt(req.TimeoutSec, 1)) * time.Second,
		MaxBodyBytes:    int64(req.MaxBodyMB) * 1024 * 1024,
		SameHostOnly:    req.SameHostOnly,
		AllowExternalJS: req.AllowExternalJS,
		FollowRedirects: req.FollowRedirects,
		UserAgent:       req.UserAgent,

		Headers:         req.Headers,
		Cookie:          req.Cookie,
		Proxy:           req.Proxy,
		KnownFiles:      req.KnownFiles,
		FetchSourceMaps: req.FetchSourceMaps,
		ExtractForms:    req.ExtractForms,
		ExcludePatterns: req.ExcludePatterns,
		IncludeHosts:    req.IncludeHosts,
		MaxRetries:      req.MaxRetries,
		RatePerSecond:   req.RatePerSecond,

		MatchRegex:        req.MatchRegex,
		ExtensionMatch:    req.ExtensionMatch,
		ExtensionFilter:   req.ExtensionFilter,
		FieldScope:        req.FieldScope,
		IgnoreQueryParams: req.IgnoreQueryParams,
		CrawlDurationSec:  req.CrawlDurationSec,

		UseExternalKatana: req.UseExternalKatana,
		KatanaBin:         req.KatanaBin,
		HeadlessKatana:    req.HeadlessKatana,

		UseAST: req.UseAST,
	}
	t0 := time.Now()
	result := jscrawl.Crawl(ctx, cfg)
	writeJSON(w, 200, map[string]any{
		"result":      result,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// handleKatanaStatus reports whether an external katana binary is available.
// The dashboard polls this on tab activation to decide whether to enable the
// "use external katana" toggle and to surface the install hint when missing.
//
// Optional query: ?bin=/abs/path/to/katana to test a non-PATH override.
func (s *server) handleKatanaStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	override := strings.TrimSpace(r.URL.Query().Get("bin"))
	info := katana.Detect(override)
	writeJSON(w, 200, info)
}

// ---- /api/active/tlscert ----

type tlscertReq struct {
	Targets        []string `json:"targets"`
	TargetsCSV     string   `json:"targets_csv"`
	CTLogDomains   []string `json:"ctlog_domains"`
	FaviconURLs    []string `json:"favicon_urls"`
	DoLiveTLS      bool     `json:"do_live_tls"`
	DoCrtSh        bool     `json:"do_crtsh"`
	DoFavicon      bool     `json:"do_favicon"`
	Concurrency    int      `json:"concurrency"`
	TLSTimeoutSec  int      `json:"tls_timeout_sec"`
	HTTPTimeoutSec int      `json:"http_timeout_sec"`
	CrtShMaxRows   int      `json:"crtsh_max_rows"`
	UserAgent      string   `json:"user_agent"`
	HardTimeoutSec int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveTLSCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req tlscertReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	targets := mergeTargets(req.Targets, req.TargetsCSV)
	if len(targets) == 0 && len(req.FaviconURLs) == 0 && len(req.CTLogDomains) == 0 {
		writeError(w, 400, "must provide at least one of: targets, favicon_urls, ctlog_domains")
		return
	}
	if len(targets) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many targets (%d > %d)", len(targets), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}

	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := tlscert.Config{
		Targets:      targets,
		CTLogDomains: req.CTLogDomains,
		FaviconURLs:  req.FaviconURLs,
		DoLiveTLS:    req.DoLiveTLS,
		DoCrtSh:      req.DoCrtSh,
		DoFavicon:    req.DoFavicon,
		Concurrency:  req.Concurrency,
		TLSTimeout:   time.Duration(maxInt(req.TLSTimeoutSec, 1)) * time.Second,
		HTTPTimeout:  time.Duration(maxInt(req.HTTPTimeoutSec, 1)) * time.Second,
		CrtShMaxRows: req.CrtShMaxRows,
		UserAgent:    req.UserAgent,
	}
	t0 := time.Now()
	result := tlscert.Run(ctx, cfg)
	writeJSON(w, 200, map[string]any{
		"result":      result,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/dnsrecord ----

type dnsrecordReq struct {
	Domain         string   `json:"domain"`
	Domains        []string `json:"domains"`
	Resolvers      []string `json:"resolvers"`
	DKIMSelectors  []string `json:"dkim_selectors"`
	SRVLabels      []string `json:"srv_labels"`
	SkipSRV        bool     `json:"skip_srv"`
	SkipDKIM       bool     `json:"skip_dkim"`
	Concurrency    int      `json:"concurrency"`
	TimeoutSec     int      `json:"timeout_sec"`
	HardTimeoutSec int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveDNSRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req dnsrecordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	domains := mergeDomains(req.Domain, req.Domains)
	if len(domains) == 0 {
		writeError(w, 400, "domain / domains required")
		return
	}
	if len(domains) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many domains (%d > %d)", len(domains), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}
	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := dnsrecord.Config{
		Resolvers:     req.Resolvers,
		Timeout:       secondsDuration(req.TimeoutSec),
		Concurrency:   req.Concurrency,
		DKIMSelectors: req.DKIMSelectors,
		SRVLabels:     req.SRVLabels,
		SkipSRV:       req.SkipSRV,
		SkipDKIM:      req.SkipDKIM,
	}
	t0 := time.Now()
	results := make([]*dnsrecord.Result, 0, len(domains))
	for _, d := range domains {
		if ctx.Err() != nil {
			break
		}
		results = append(results, dnsrecord.Lookup(ctx, d, cfg))
	}
	writeJSON(w, 200, map[string]any{
		"results":     results,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/sensifile ----

type sensifileReq struct {
	BaseURLs          []string `json:"base_urls"`
	BaseURLsCSV       string   `json:"base_urls_csv"`
	Paths             []string `json:"paths"`
	IncludeMediumOnly bool     `json:"include_medium_only"`
	Concurrency       int      `json:"concurrency"`
	TimeoutSec        int      `json:"timeout_sec"`
	MaxBodyBytes      int64    `json:"max_body_bytes"`
	FollowRedirects   bool     `json:"follow_redirects"`
	UserAgent         string   `json:"user_agent"`
	HardTimeoutSec    int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveSensifile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req sensifileReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	urls := mergeTargets(req.BaseURLs, req.BaseURLsCSV)
	if len(urls) == 0 {
		writeError(w, 400, "base_urls required")
		return
	}
	if len(urls) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many base_urls (%d > %d)", len(urls), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}
	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := sensifile.Config{
		BaseURLs:          urls,
		Paths:             req.Paths,
		IncludeMediumOnly: req.IncludeMediumOnly,
		Concurrency:       req.Concurrency,
		Timeout:           secondsDuration(req.TimeoutSec),
		MaxBodyBytes:      req.MaxBodyBytes,
		FollowRedirects:   req.FollowRedirects,
		UserAgent:         req.UserAgent,
	}
	t0 := time.Now()
	result := sensifile.Scan(ctx, cfg)
	writeJSON(w, 200, map[string]any{
		"result":      result,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/cdninfo ----

type cdninfoReq struct {
	Hosts             []string `json:"hosts"`
	HostsCSV          string   `json:"hosts_csv"`
	Resolvers         []string `json:"resolvers"`
	HTTPTimeoutSec    int      `json:"http_timeout_sec"`
	DNSTimeoutSec     int      `json:"dns_timeout_sec"`
	Concurrency       int      `json:"concurrency"`
	SkipOriginHunt    bool     `json:"skip_origin_hunt"`
	DoPassiveDNS      bool     `json:"do_passive_dns"`
	PassiveSources    []string `json:"passive_sources"`
	MaxPassiveRecords int      `json:"max_passive_records"`
	UserAgent         string   `json:"user_agent"`
	HardTimeoutSec    int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveCDNInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req cdninfoReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	hosts := mergeTargets(req.Hosts, req.HostsCSV)
	if len(hosts) == 0 {
		writeError(w, 400, "hosts required")
		return
	}
	if len(hosts) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many hosts (%d > %d)", len(hosts), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}
	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	appCfg := s.configSnapshot()
	cfg := cdninfo.Config{
		Hosts:             hosts,
		Resolvers:         req.Resolvers,
		HTTPTimeout:       secondsDuration(req.HTTPTimeoutSec),
		DNSTimeout:        secondsDuration(req.DNSTimeoutSec),
		Concurrency:       req.Concurrency,
		SkipOriginHunt:    req.SkipOriginHunt,
		DoPassiveDNS:      req.DoPassiveDNS,
		PassiveSources:    req.PassiveSources,
		MaxPassiveRecords: req.MaxPassiveRecords,
		SecurityTrailsKey: sourceConfigKey(appCfg.GetSourceConfig("securitytrails")),
		VirusTotalKey:     sourceConfigKey(appCfg.GetSourceConfig("virustotal")),
		UserAgent:         req.UserAgent,
	}
	t0 := time.Now()
	result := cdninfo.Detect(ctx, cfg)
	writeJSON(w, 200, map[string]any{
		"result":      result,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/asn ----

type asnReq struct {
	Inputs            []string `json:"inputs"`
	InputsCSV         string   `json:"inputs_csv"`
	ResolveHostnames  bool     `json:"resolve_hostnames"`
	SkipIPv6          bool     `json:"skip_ipv6"`
	MaxASNs           int      `json:"max_asns"`
	MaxPrefixesPerASN int      `json:"max_prefixes_per_asn"`
	HTTPTimeoutSec    int      `json:"http_timeout_sec"`
	Concurrency       int      `json:"concurrency"`
	UserAgent         string   `json:"user_agent"`
	HardTimeoutSec    int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveASN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req asnReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	inputs := mergeTargets(req.Inputs, req.InputsCSV)
	if len(inputs) == 0 {
		writeError(w, 400, "inputs required")
		return
	}
	if len(inputs) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many inputs (%d > %d)", len(inputs), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}
	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := asn.Config{
		Inputs:            inputs,
		ResolveHostnames:  req.ResolveHostnames,
		SkipIPv6:          req.SkipIPv6,
		MaxASNs:           req.MaxASNs,
		MaxPrefixesPerASN: req.MaxPrefixesPerASN,
		HTTPTimeout:       secondsDuration(req.HTTPTimeoutSec),
		Concurrency:       req.Concurrency,
		UserAgent:         req.UserAgent,
	}
	t0 := time.Now()
	result := asn.Lookup(ctx, cfg)
	writeJSON(w, 200, map[string]any{
		"result":      result,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/whoisrdap ----

type whoisrdapReq struct {
	Inputs            []string `json:"inputs"`
	InputsCSV         string   `json:"inputs_csv"`
	DoRDAP            bool     `json:"do_rdap"`
	DoWHOIS           bool     `json:"do_whois"`
	DoReverseWHOIS    bool     `json:"do_reverse_whois"`
	MaxSiblingDomains int      `json:"max_sibling_domains"`
	HTTPTimeoutSec    int      `json:"http_timeout_sec"`
	WHOISTimeoutSec   int      `json:"whois_timeout_sec"`
	Concurrency       int      `json:"concurrency"`
	UserAgent         string   `json:"user_agent"`
	HardTimeoutSec    int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveWhoisRDAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req whoisrdapReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	inputs := mergeTargets(req.Inputs, req.InputsCSV)
	if len(inputs) == 0 {
		writeError(w, 400, "inputs required")
		return
	}
	if len(inputs) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many inputs (%d > %d)", len(inputs), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}
	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	appCfg := s.configSnapshot()
	cfg := whoisrdap.Config{
		Inputs:            inputs,
		DoRDAP:            req.DoRDAP,
		DoWHOIS:           req.DoWHOIS,
		DoReverseWHOIS:    req.DoReverseWHOIS,
		ReverseWhoisKey:   sourceConfigKey(appCfg.GetSourceConfig("whois_reverse")),
		MaxSiblingDomains: req.MaxSiblingDomains,
		HTTPTimeout:       secondsDuration(req.HTTPTimeoutSec),
		WHOISTimeout:      secondsDuration(req.WHOISTimeoutSec),
		Concurrency:       req.Concurrency,
		UserAgent:         req.UserAgent,
	}
	t0 := time.Now()
	result := whoisrdap.Lookup(ctx, cfg)
	writeJSON(w, 200, map[string]any{
		"result":      result,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- /api/active/webmeta ----

type webmetaReq struct {
	Targets         []string `json:"targets"`
	TargetsCSV      string   `json:"targets_csv"`
	Concurrency     int      `json:"concurrency"`
	TimeoutSec      int      `json:"timeout_sec"`
	MaxBodyKB       int      `json:"max_body_kb"`
	MaxSitemapURLs  int      `json:"max_sitemap_urls"`
	MaxSitemaps     int      `json:"max_sitemaps"`
	FetchRobots     bool     `json:"fetch_robots"`
	FetchSitemap    bool     `json:"fetch_sitemap"`
	FollowRedirects bool     `json:"follow_redirects"`
	TryHTTPFallback bool     `json:"try_http_fallback"`
	SkipTLSVerify   bool     `json:"skip_tls_verify"`
	UserAgent       string   `json:"user_agent"`
	HardTimeoutSec  int      `json:"hard_timeout_sec"`
}

func (s *server) handleActiveWebMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	var req webmetaReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "bad json: "+err.Error())
		return
	}
	targets := mergeTargets(req.Targets, req.TargetsCSV)
	if len(targets) == 0 {
		writeError(w, 400, "targets required")
		return
	}
	if len(targets) > activeMaxTargets {
		writeError(w, 400, fmt.Sprintf("too many targets (%d > %d)", len(targets), activeMaxTargets))
		return
	}
	if req.Concurrency > activeMaxConcurrency {
		req.Concurrency = activeMaxConcurrency
	}
	ctx, cancel := activeReqCtx(r, req.HardTimeoutSec)
	defer cancel()

	cfg := webmeta.Config{
		Targets:         targets,
		Concurrency:     req.Concurrency,
		Timeout:         secondsDuration(req.TimeoutSec),
		MaxBodyBytes:    int64(req.MaxBodyKB) * 1024,
		MaxSitemapURLs:  req.MaxSitemapURLs,
		MaxSitemaps:     req.MaxSitemaps,
		FetchRobots:     req.FetchRobots,
		FetchSitemap:    req.FetchSitemap,
		FollowRedirects: req.FollowRedirects,
		TryHTTPFallback: req.TryHTTPFallback,
		SkipTLSVerify:   req.SkipTLSVerify,
		UserAgent:       req.UserAgent,
	}
	t0 := time.Now()
	result := webmeta.Collect(ctx, cfg)
	writeJSON(w, 200, map[string]any{
		"result":      result,
		"duration_ms": time.Since(t0).Milliseconds(),
		"truncated":   ctx.Err() == context.DeadlineExceeded,
	})
}

// ---- helpers ----

// mergeDomains combines a single-string domain field with a list, deduping.
func mergeDomains(single string, list []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			return
		}
		k := strings.ToLower(s)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	if single != "" {
		for _, p := range splitCSV(single) {
			add(p)
		}
	}
	for _, raw := range list {
		for _, p := range splitCSV(raw) {
			add(p)
		}
	}
	return out
}

// mergeTargets combines a list and a single CSV string, deduping.
func mergeTargets(list []string, csv string) []string {
	return mergeDomains(csv, list)
}

// splitCSV splits a string on whitespace, comma, semicolon, or newline.
func splitCSV(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

// maxInt returns the larger of a, b. (Avoids importing math from this small file.)
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func secondsDuration(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func sourceConfigKey(cfg map[string]any) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg["key"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
