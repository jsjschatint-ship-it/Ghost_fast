// Package server 提供 Ghost server 子命令：HTTP API + 仪表盘
package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/wgpsec/ENScan/pkg/config"
	"github.com/wgpsec/ENScan/pkg/core"
	"github.com/wgpsec/ENScan/pkg/importers"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/registry"
	"github.com/wgpsec/ENScan/pkg/runner"
	"github.com/wgpsec/ENScan/pkg/source"
)

//go:embed templates/*.html
var templateFS embed.FS

// New 返回 cobra 子命令
func New() *cobra.Command {
	var cfgPath, addr, authToken string
	cmd := &cobra.Command{
		Use:   "server",
		Short: "启动 HTTP API + 仪表盘（GET /, /api/*）",
		RunE: func(_ *cobra.Command, _ []string) error {
			srv, err := newServer(cfgPath)
			if err != nil {
				return err
			}
			// ----- 鉴权 token 解析（CLI flag > env > 关闭） -----
			// --auth-token random  → 自动生成；--auth-token "" → 关闭；都没传 → 看 env
			if authToken == "" {
				authToken = os.Getenv("GHOST_AUTH_TOKEN")
			}
			if authToken == "random" {
				buf := make([]byte, 32)
				_, _ = rand.Read(buf)
				authToken = hex.EncodeToString(buf)
				log.Printf("[server] AUTH 自动生成 token = %s （请抄走并通过 ?token=... 或 Authorization: Bearer ... 访问）", authToken)
			}
			srv.authToken = authToken
			if authToken == "" {
				log.Printf("[server] ⚠ AUTH 未启用：任何人都能调用 /api/* —— 公网部署务必加 --auth-token random 或环境变量 GHOST_AUTH_TOKEN")
			} else {
				log.Printf("[server] AUTH 已启用（token 长度=%d）", len(authToken))
			}
			// 初始化 SQLite 历史会话存储（失败仅警告，不阻止 server 启动）
			if err := core.InitDB(); err != nil {
				log.Printf("[server] WARN init db: %v (history disabled)", err)
				srv.dbReady = false
			} else {
				srv.dbReady = true
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/api/health", srv.handleHealth)
			mux.HandleFunc("/api/sources", srv.handleSources)
			mux.HandleFunc("/api/config", srv.handleConfig)
			mux.HandleFunc("/api/search", srv.handleSearch)
			mux.HandleFunc("/api/run", srv.handleRun)
			mux.HandleFunc("/api/cancel", srv.handleCancel)
			mux.HandleFunc("/api/progress", srv.handleProgress)
			mux.HandleFunc("/api/progress_sse", srv.handleProgressSSE)
			mux.HandleFunc("/api/result", srv.handleResult)
			mux.HandleFunc("/api/stats", srv.handleStats)
			mux.HandleFunc("/api/import", srv.handleImport)
			mux.HandleFunc("/api/import_smart", srv.handleImportSmart) // POST 智能导入：xlsx/txt → 自动分类 → 主被动联动
			// 历史会话（SQLite 持久化）
			mux.HandleFunc("/api/sessions", srv.handleSessions)         // GET list / DELETE by id / PATCH notes
			mux.HandleFunc("/api/sessions/load", srv.handleSessionLoad) // POST 把 db 会话 hydrate 进 runStore
			mux.HandleFunc("/api/sessions/diff", srv.handleSessionDiff) // GET ?a=&b=  对比 2 个会话的资产差
			// 额外端点（见 endpoints_extra.go）
			mux.HandleFunc("/api/export", srv.handleExport)              // GET ?id=&fmt=xlsx|csv|json
			mux.HandleFunc("/api/dedup_preview", srv.handleDedupPreview) // POST ?id=
			mux.HandleFunc("/api/dedup_apply", srv.handleDedupApply)     // POST ?id=&strategy=
			mux.HandleFunc("/api/analyze", srv.handleAnalyze)            // GET ?id=  根域/地理/ASN
			// 主动探测三件套（pkg/active/{subdomain,httpx,portscan}）
			mux.HandleFunc("/api/active/subbrute", srv.handleActiveSubbrute)    // POST 子域名爆破
			mux.HandleFunc("/api/active/httpx", srv.handleActiveHTTPX)          // POST HTTP 主动探测 + 指纹
			mux.HandleFunc("/api/active/portscan", srv.handleActivePortscan)    // POST TCP connect 端口扫
			mux.HandleFunc("/api/active/dnsadv", srv.handleActiveDNSAdv)        // POST AXFR + 子域接管检测
			mux.HandleFunc("/api/active/jscrawl", srv.handleActiveJSCrawl)      // POST JS 递归爬取 + API/secret 暴露
			mux.HandleFunc("/api/active/katana/status", srv.handleKatanaStatus) // GET 检测外置 katana 二进制是否可用
			mux.HandleFunc("/api/active/tlscert", srv.handleActiveTLSCert)      // POST TLS handshake + crt.sh + favicon hash
			mux.HandleFunc("/api/active/dnsrecord", srv.handleActiveDNSRecord)  // POST 全类型 DNS 枚举 + TXT token
			mux.HandleFunc("/api/active/sensifile", srv.handleActiveSensifile)  // POST 敏感文件存在性
			mux.HandleFunc("/api/active/cdninfo", srv.handleActiveCDNInfo)      // POST CDN/WAF 指纹 + 源站 hunt
			mux.HandleFunc("/api/active/asn", srv.handleActiveASN)              // POST ASN/BGP 网段扩展
			mux.HandleFunc("/api/active/whoisrdap", srv.handleActiveWhoisRDAP)  // POST RDAP + WHOIS 实时查
			mux.HandleFunc("/api/active/webmeta", srv.handleActiveWebMeta)      // POST 网页元信息 + robots/sitemap
			mux.HandleFunc("/", srv.handleDashboard)

			log.Printf("[server] listening on %s （配置=%s, 数据源=%d, history=%v, auth=%v）", addr, cfgPath, len(srv.sources), srv.dbReady, srv.authToken != "")
			return http.ListenAndServe(addr, withCORS(srv.withAuth(mux)))
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "config.yaml", "配置文件路径")
	cmd.Flags().StringVar(&addr, "addr", ":8080", "监听地址")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "API 鉴权 token；'random' = 自动生成 32 字节 hex；空 = 关闭鉴权（也可用环境变量 GHOST_AUTH_TOKEN）")
	return cmd
}

// ----------- 内部：runStore / server -----------

type runStore struct {
	mu   sync.RWMutex
	data map[string]*runEntry
	keys []string
	max  int
}

type runEntry struct {
	ID      string   `json:"id"`
	Target  string   `json:"target"`
	Sources []string `json:"sources"`
	// Assets：当前视图（经默认 smart 去重 / 或 dedup_apply 后的结果）。
	// 所有展示/导出/统计都基于这份。
	Assets []*models.Asset `json:"assets"`
	// RawAssets：采集结束后的原始资产堆（未去重的全 union）。
	// 仅保留在内存里，专门服务于 dedup_preview / dedup_apply：
	// 切去重策略时无需重跑采集，直接基于这份重算 Assets。
	// 不入 db、不进 JSON 序列化给前端（前端只看 Assets，避免 payload 翻倍）。
	RawAssets []*models.Asset `json:"-"`
	When      time.Time       `json:"when"`
	// 异步采集状态（仅 /api/run 路径填）
	Status     string               `json:"status"` // "running" | "done" | "error"
	StartedAt  time.Time            `json:"started_at,omitempty"`
	FinishedAt time.Time            `json:"finished_at,omitempty"`
	Total      int                  `json:"total"` // 计划跑的 source 数
	Events     []runner.SourceEvent `json:"-"`     // 详细事件流（progress 端点单独读）
	ErrMsg     string               `json:"err_msg,omitempty"`
	DBID       int                  `json:"db_id,omitempty"` // SQLite sessions.id；0 = 未入库
	// 多目标批量进度（单目标场景：TargetTotal=1, TargetIdx=1, CurrentTarget=Target）
	TargetTotal   int        `json:"target_total"`             // 计划跑的目标数（>=1）
	TargetIdx     int        `json:"target_idx"`               // 当前跑到第几个（1-based；done 后 = TargetTotal）
	CurrentTarget string     `json:"current_target,omitempty"` // 当前正在跑的目标字符串
	mu            sync.Mutex `json:"-"`
	// cancel：handleRun 启动时填入；handleCancel 调用以中断采集协程
	cancel context.CancelFunc `json:"-"`
	// Canceled：true = 该会话被用户主动取消（区别于天然 done / error）
	Canceled bool `json:"canceled,omitempty"`
}

// appendEvent 线程安全追加事件
func (e *runEntry) appendEvent(ev runner.SourceEvent) {
	e.mu.Lock()
	e.Events = append(e.Events, ev)
	e.mu.Unlock()
}

// snapshotEvents 拷一份事件切片（避免读写竞争）
func (e *runEntry) snapshotEvents() []runner.SourceEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]runner.SourceEvent, len(e.Events))
	copy(out, e.Events)
	return out
}

func newRunStore(max int) *runStore {
	return &runStore{data: make(map[string]*runEntry), max: max}
}

func (s *runStore) put(e *runEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[e.ID] = e
	s.keys = append(s.keys, e.ID)
	for len(s.keys) > s.max {
		evict := s.keys[0]
		s.keys = s.keys[1:]
		delete(s.data, evict)
	}
}

func (s *runStore) get(id string) (*runEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.data[id]
	return e, ok
}

type server struct {
	cfgPath   string
	cfg       *config.Config
	cfgMu     sync.RWMutex
	sources   map[string]source.Source
	store     *runStore
	dbReady   bool   // SQLite 是否可用；为 false 时 SaveSession 跳过、history endpoint 返回 503
	authToken string // 鉴权 token；空串=不鉴权（兼容旧部署）
}

func newServer(cfgPath string) (*server, error) {
	cfg, err := config.LoadFromFile(cfgPath)
	if err != nil {
		log.Printf("[warn] 加载配置 %s 失败：%v；继续以默认配置启动", cfgPath, err)
		cfg = &config.Config{}
		cfg.Runner.Timeout = 60
	}
	return &server{
		cfgPath: cfgPath,
		cfg:     cfg,
		sources: registry.AllSources(),
		store:   newRunStore(50),
	}, nil
}

// ----------- 工具函数 -----------

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

const configSecretPlaceholder = "__GHOST_SECRET__"

// editableEngineNames lists every source that needs an API key, so the
// dashboard's "测绘引擎 Key" form can edit all of them.
// Keep alphabetical for stable UI order. Sources NOT listed here (e.g. ones
// that take no key, or that derive their key from fofa/quake like
// supply_pivots / supply_vendor / path_pivot) shouldn't appear in the form.
var editableEngineNames = []string{
	"abuseipdb",
	"binaryedge",
	"breachdirectory",
	"censys",
	"chaos",
	"daydaymap",
	"dnsdumpster",
	"driftnet",
	"fofa",
	"fullhunt",
	"github_code",
	"github_commits",
	"github_secrets",
	"greynoise",
	"hibp",
	"hunt_io",
	"hunter",
	"hunter_io",
	"hunter_verify",
	"intelx",
	"intelx_leaks",
	"leakix",
	"netlas",
	"onyphe",
	"pdns_circl",
	"publicwww",
	"quake",
	"securitytrails",
	"shodan",
	"shodan_enrich",
	"validin",
	"viewdns",
	"virustotal",
	"zerozone",
	"zerozone_extra",
	"zoomeye",
}

var editableCoreEngineNames = map[string]struct{}{
	"fofa":     {},
	"hunter":   {},
	"quake":    {},
	"shodan":   {},
	"zerozone": {},
	"zoomeye":  {},
}

func isEditableCoreEngine(name string) bool {
	_, ok := editableCoreEngineNames[name]
	return ok
}

type editableEngineDoc struct {
	API        string `json:"api,omitempty"`
	URL        string `json:"url,omitempty"`
	Credential string `json:"credential,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

var editableEngineDocs = map[string]editableEngineDoc{
	"abuseipdb":       {API: "AbuseIPDB IP reputation API", URL: "https://www.abuseipdb.com/account/api", Credential: "key", Scope: "source"},
	"binaryedge":      {API: "BinaryEdge API", URL: "https://app.binaryedge.io/account/api", Credential: "key", Scope: "source"},
	"breachdirectory": {API: "BreachDirectory API via RapidAPI", URL: "https://rapidapi.com/rohan-patra/api/breachdirectory", Credential: "RapidAPI key", Scope: "source"},
	"censys":          {API: "Censys Search API", URL: "https://search.censys.io/account/api", Credential: "key", Scope: "source"},
	"chaos":           {API: "ProjectDiscovery Chaos API", URL: "https://chaos.projectdiscovery.io/", Credential: "key", Scope: "source"},
	"daydaymap":       {API: "DayDayMap API", URL: "https://www.daydaymap.com/", Credential: "key", Scope: "source"},
	"dnsdumpster":     {API: "DNSDumpster API", URL: "https://api.dnsdumpster.com/", Credential: "key", Scope: "source"},
	"driftnet":        {API: "Driftnet domain intelligence API", URL: "https://driftnet.io/", Credential: "key", Scope: "source"},
	"fofa":            {API: "FOFA asset search API", URL: "https://fofa.info/api", Credential: "key or keys", Scope: "engine"},
	"fullhunt":        {API: "FullHunt API", URL: "https://fullhunt.io/docs/", Credential: "key", Scope: "source"},
	"github_code":     {API: "GitHub REST/Search API", URL: "https://github.com/settings/tokens", Credential: "token/key", Scope: "source"},
	"github_commits":  {API: "GitHub Commit Search API", URL: "https://github.com/settings/tokens", Credential: "token/key", Scope: "source"},
	"github_secrets":  {API: "GitHub Code Search API", URL: "https://github.com/settings/tokens", Credential: "token/key", Scope: "source"},
	"greynoise":       {API: "GreyNoise IP intelligence API", URL: "https://viz.greynoise.io/account/api-key", Credential: "key", Scope: "source"},
	"hibp":            {API: "Have I Been Pwned API", URL: "https://haveibeenpwned.com/API/Key", Credential: "key", Scope: "source"},
	"hunt_io":         {API: "Hunt.io intelligence API", URL: "https://hunt.io/developer", Credential: "key", Scope: "source"},
	"hunter":          {API: "Qianxin Hunter asset search API", URL: "https://hunter.qianxin.com/", Credential: "key or keys", Scope: "engine"},
	"hunter_io":       {API: "Hunter.io Domain Search API", URL: "https://hunter.io/api-keys", Credential: "key", Scope: "source"},
	"hunter_verify":   {API: "Hunter.io Email Verifier API", URL: "https://hunter.io/api-keys", Credential: "key", Scope: "source"},
	"intelx":          {API: "Intelligence X API", URL: "https://intelx.io/account?tab=developer", Credential: "key", Scope: "source"},
	"intelx_leaks":    {API: "Intelligence X API", URL: "https://intelx.io/account?tab=developer", Credential: "key", Scope: "source"},
	"leakix":          {API: "LeakIX API", URL: "https://leakix.net/", Credential: "key", Scope: "source"},
	"netlas":          {API: "Netlas Search API", URL: "https://app.netlas.io/profile/", Credential: "key", Scope: "source"},
	"onyphe":          {API: "ONYPHE API", URL: "https://www.onyphe.io/api/", Credential: "key", Scope: "source"},
	"pdns_circl":      {API: "CIRCL Passive DNS API", URL: "https://www.circl.lu/services/passive-dns/", Credential: "user:pass or Basic token", Scope: "source"},
	"publicwww":       {API: "PublicWWW API", URL: "https://publicwww.com/api/", Credential: "key", Scope: "source"},
	"quake":           {API: "360 Quake asset search API", URL: "https://quake.360.net/", Credential: "key or keys", Scope: "engine"},
	"securitytrails":  {API: "SecurityTrails API", URL: "https://securitytrails.com/corp/apidocs", Credential: "key", Scope: "source"},
	"shodan":          {API: "Shodan API", URL: "https://account.shodan.io/", Credential: "key or keys", Scope: "engine"},
	"shodan_enrich":   {API: "Shodan Host API", URL: "https://account.shodan.io/", Credential: "key; can reuse shodan", Scope: "source"},
	"validin":         {API: "Validin API", URL: "https://app.validin.com/", Credential: "key", Scope: "source"},
	"viewdns":         {API: "ViewDNS.info API", URL: "https://viewdns.info/api/", Credential: "key", Scope: "source"},
	"virustotal":      {API: "VirusTotal API", URL: "https://www.virustotal.com/gui/my-apikey", Credential: "key", Scope: "source"},
	"zerozone":        {API: "0.zone API", URL: "https://0.zone/", Credential: "key or keys", Scope: "engine"},
	"zerozone_extra":  {API: "0.zone extended API", URL: "https://0.zone/", Credential: "key; can reuse zerozone", Scope: "source"},
	"zoomeye":         {API: "ZoomEye API", URL: "https://www.zoomeye.org/", Credential: "key or keys", Scope: "engine"},
}

// engineCategories drives the dashboard's grouped 测绘引擎 Key panel. Order
// here is the order the dashboard renders the sections in. Engine names not
// referenced here automatically fall into the trailing "其它" bucket so a
// new editable engine that someone forgets to categorise still shows up.
type engineCategoryDef struct {
	Title string   `json:"title"`
	Hint  string   `json:"hint,omitempty"`
	Names []string `json:"names"`
}

var engineCategories = []engineCategoryDef{
	{
		Title: "测绘引擎",
		Hint:  "全网测绘 / 资产搜索；多数支持 query DSL 与配额并发。",
		Names: []string{
			"fofa", "quake", "hunter", "zoomeye", "shodan", "censys",
			"binaryedge", "netlas", "fullhunt", "daydaymap", "onyphe",
			"leakix", "publicwww", "shodan_enrich",
			"zerozone", "zerozone_extra",
		},
	},
	{
		Title: "Passive DNS / 反查",
		Hint:  "历史 DNS / WHOIS 反查 / 子域接口。",
		Names: []string{
			"chaos", "securitytrails", "virustotal", "dnsdumpster",
			"viewdns", "pdns_circl", "validin", "hunt_io",
		},
	},
	{
		Title: "威胁情报",
		Hint:  "恶意 IP / 扫描器标签 / IOC 富化。",
		Names: []string{"greynoise", "abuseipdb", "driftnet"},
	},
	{
		Title: "邮件 / 数据泄露",
		Hint:  "邮箱发现、HIBP、公开情报索引。",
		Names: []string{
			"hibp", "breachdirectory", "intelx", "intelx_leaks",
			"hunter_io", "hunter_verify",
		},
	},
	{
		Title: "GitHub / 代码搜索",
		Hint:  "GitHub 代码、commits、密钥泄露扫描。",
		Names: []string{"github_code", "github_commits", "github_secrets"},
	},
}

type webConfigRunner struct {
	EnabledSources []string `json:"enabled_sources"`
	Proxy          string   `json:"proxy"`
	UserAgent      string   `json:"user_agent"`
	MaxConcurrency int      `json:"max_concurrency"`
	Timeout        int      `json:"timeout"`
}

type webConfigEngine struct {
	Enabled    bool   `json:"enabled"`
	HasKey     bool   `json:"has_key"`
	HasKeys    bool   `json:"has_keys"`
	KeysCount  int    `json:"keys_count"`
	Email      string `json:"email"`
	Proxy      string `json:"proxy"`
	Timeout    int    `json:"timeout"`
	Size       int    `json:"size"`
	API        string `json:"api,omitempty"`
	URL        string `json:"url,omitempty"`
	Credential string `json:"credential,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

type webConfigEngineUpdate struct {
	Enabled   bool     `json:"enabled"`
	Key       string   `json:"key"`
	ClearKey  bool     `json:"clear_key"`
	Keys      []string `json:"keys"`
	ClearKeys bool     `json:"clear_keys"`
	Email     string   `json:"email"`
	Proxy     string   `json:"proxy"`
	Timeout   int      `json:"timeout"`
	Size      int      `json:"size"`
}

// engineCategoryView is the response shape for a category section. The
// Engines list inside is the *resolved* set actually present in Engines map,
// preserving the order declared in engineCategories. A trailing "其它" view
// catches any engine the backend returned that isn't categorised yet.
type engineCategoryView struct {
	Title   string   `json:"title"`
	Hint    string   `json:"hint,omitempty"`
	Engines []string `json:"engines"`
}

type webConfigResponse struct {
	OK                    bool                       `json:"ok"`
	Path                  string                     `json:"path"`
	SecretPlaceholder     string                     `json:"secret_placeholder"`
	Runner                webConfigRunner            `json:"runner"`
	Engines               map[string]webConfigEngine `json:"engines"`
	EngineCategories      []engineCategoryView       `json:"engine_categories"`
	SourcesYAML           string                     `json:"sources_yaml"`
	ExtraYAML             string                     `json:"extra_yaml"`
	RegisteredSourceNames []string                   `json:"registered_source_names"`
}

type webConfigUpdate struct {
	Runner      webConfigRunner                  `json:"runner"`
	Engines     map[string]webConfigEngineUpdate `json:"engines"`
	SourcesYAML string                           `json:"sources_yaml"`
	ExtraYAML   string                           `json:"extra_yaml"`
}

func cloneConfig(c *config.Config) (*config.Config, error) {
	if c == nil {
		return &config.Config{
			Engines: make(map[string]config.EngineConfig),
			Sources: make(map[string]any),
			Extra:   make(map[string]any),
		}, nil
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	var out config.Config
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if out.Engines == nil {
		out.Engines = make(map[string]config.EngineConfig)
	}
	if out.Sources == nil {
		out.Sources = make(map[string]any)
	}
	if out.Extra == nil {
		out.Extra = make(map[string]any)
	}
	return &out, nil
}

func (s *server) configSnapshot() *config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	cp, err := cloneConfig(s.cfg)
	if err != nil {
		log.Printf("[server] WARN clone config: %v", err)
		return &config.Config{
			Engines: make(map[string]config.EngineConfig),
			Sources: make(map[string]any),
			Extra:   make(map[string]any),
		}
	}
	return cp
}

func cleanStringList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func isSensitiveConfigKey(k string) bool {
	k = strings.ToLower(k)
	for _, part := range []string{"key", "token", "secret", "password", "passwd", "credential", "auth"} {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

func isSecretPlaceholder(v any) bool {
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == configSecretPlaceholder
}

func hasNonEmptyConfigValue(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x) != "" && strings.TrimSpace(x) != configSecretPlaceholder
	case []string:
		for _, item := range x {
			if hasNonEmptyConfigValue(item) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if hasNonEmptyConfigValue(item) {
				return true
			}
		}
	case map[string]any:
		for _, item := range x {
			if hasNonEmptyConfigValue(item) {
				return true
			}
		}
	default:
		return x != nil
	}
	return false
}

func redactConfigValue(v any, sensitive bool) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = redactConfigValue(item, sensitive || isSensitiveConfigKey(k))
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			ks := fmt.Sprint(k)
			out[ks] = redactConfigValue(item, sensitive || isSensitiveConfigKey(ks))
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = redactConfigValue(item, sensitive)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = redactConfigValue(item, sensitive)
		}
		return out
	case string:
		if sensitive && strings.TrimSpace(x) != "" {
			return configSecretPlaceholder
		}
		return x
	default:
		if sensitive && hasNonEmptyConfigValue(x) {
			return configSecretPlaceholder
		}
		return x
	}
}

func restoreConfigSecrets(next any, old any, sensitive bool) any {
	if sensitive && isSecretPlaceholder(next) {
		return old
	}
	switch n := next.(type) {
	case map[string]any:
		var oldMap map[string]any
		if om, ok := old.(map[string]any); ok {
			oldMap = om
		}
		for k, item := range n {
			n[k] = restoreConfigSecrets(item, oldMap[k], sensitive || isSensitiveConfigKey(k))
		}
		return n
	case []any:
		oldSlice := anySlice(old)
		for i, item := range n {
			var oldItem any
			if i < len(oldSlice) {
				oldItem = oldSlice[i]
			}
			n[i] = restoreConfigSecrets(item, oldItem, sensitive)
		}
		return n
	default:
		return n
	}
}

func anySlice(v any) []any {
	switch x := v.(type) {
	case []any:
		return x
	case []string:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = item
		}
		return out
	default:
		return nil
	}
}

func parseConfigYAMLMap(text string) (map[string]any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return make(map[string]any), nil
	}
	var out map[string]any
	if err := yaml.Unmarshal([]byte(text), &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = make(map[string]any)
	}
	return out, nil
}

func configYAMLString(v any) string {
	data, err := yaml.Marshal(redactConfigValue(v, false))
	if err != nil {
		return "{}\n"
	}
	return string(data)
}

func configHasCredential(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, item := range x {
			if isSensitiveConfigKey(k) && hasNonEmptyConfigValue(item) {
				return true
			}
			if configHasCredential(item) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if configHasCredential(item) {
				return true
			}
		}
	}
	return false
}

func engineHasCredential(ec config.EngineConfig) bool {
	return strings.TrimSpace(ec.Key) != "" || len(cleanStringList(ec.Keys)) > 0
}

func sourceHasConfiguredCredential(cfg *config.Config, name string) bool {
	if cfg == nil {
		return false
	}
	if ec, ok := cfg.Engines[name]; ok && engineHasCredential(ec) {
		return true
	}
	if configHasCredential(cfg.GetSourceConfig(name)) {
		return true
	}
	if name == "supply_pivots" || name == "supply_vendor" || name == "supply_auto" || name == "path_pivot" {
		if ec, ok := cfg.Engines["fofa"]; ok && engineHasCredential(ec) {
			return true
		}
		if ec, ok := cfg.Engines["quake"]; ok && engineHasCredential(ec) {
			return true
		}
	}
	return false
}

func configStringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" && strings.TrimSpace(v) != configSecretPlaceholder {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func configStringListField(m map[string]any, key string) []string {
	if v, ok := m[key].([]string); ok {
		return cleanStringList(v)
	}
	if v, ok := m[key].([]any); ok {
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return cleanStringList(out)
	}
	return nil
}

func configIntField(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case float32:
		return int(v)
	}
	return 0
}

func configMapForSource(cfg *config.Config, name string) map[string]any {
	if cfg == nil {
		return nil
	}
	if cfg.Sources != nil {
		if m, ok := cfg.Sources[name].(map[string]any); ok {
			return m
		}
	}
	return cfg.GetSourceConfig(name)
}

func sourceConfigMapForWrite(sources map[string]any, name string) map[string]any {
	if sources == nil {
		return nil
	}
	if m, ok := sources[name].(map[string]any); ok {
		return m
	}
	m := make(map[string]any)
	sources[name] = m
	return m
}

func fillWebEngineFromSource(e *webConfigEngine, m map[string]any) {
	if len(m) == 0 {
		return
	}
	if !e.HasKey && configHasCredential(m) {
		e.HasKey = true
	}
	if !e.HasKeys {
		keys := configStringListField(m, "keys")
		e.HasKeys = len(keys) > 0
		e.KeysCount = len(keys)
	}
	if e.Email == "" {
		e.Email = configStringField(m, "email", "fofa_email")
	}
	if e.Proxy == "" {
		e.Proxy = configStringField(m, "proxy")
	}
	if e.Timeout == 0 {
		e.Timeout = configIntField(m, "timeout")
	}
	if e.Size == 0 {
		e.Size = configIntField(m, "size")
	}
}

func applyWebConfigUpdateToSource(m map[string]any, upd webConfigEngineUpdate) {
	key := strings.TrimSpace(upd.Key)
	if upd.ClearKey {
		m["key"] = ""
	} else if key != "" && key != configSecretPlaceholder {
		m["key"] = key
	}
	keys := cleanStringList(upd.Keys)
	if upd.ClearKeys {
		delete(m, "keys")
	} else if len(keys) > 0 {
		m["keys"] = keys
	}
	if email := strings.TrimSpace(upd.Email); email != "" {
		m["email"] = email
	} else {
		delete(m, "email")
	}
	if proxy := strings.TrimSpace(upd.Proxy); proxy != "" {
		m["proxy"] = proxy
	} else {
		delete(m, "proxy")
	}
	if upd.Timeout > 0 {
		m["timeout"] = upd.Timeout
	} else {
		delete(m, "timeout")
	}
	if upd.Size > 0 {
		m["size"] = upd.Size
	} else {
		delete(m, "size")
	}
}

func (s *server) webConfigResponse(cfg *config.Config, ok bool) webConfigResponse {
	if cfg == nil {
		cfg = &config.Config{}
	}
	engines := make(map[string]webConfigEngine)
	names := append([]string{}, editableEngineNames...)
	seenNames := make(map[string]bool, len(names)+len(cfg.Engines))
	for _, name := range names {
		seenNames[name] = true
	}
	for name := range cfg.Engines {
		if !seenNames[name] {
			names = append(names, name)
			seenNames[name] = true
		}
	}
	sort.Strings(names)
	for _, name := range names {
		ec := cfg.Engines[name]
		keys := cleanStringList(ec.Keys)
		item := webConfigEngine{
			Enabled:   ec.Enabled,
			HasKey:    strings.TrimSpace(ec.Key) != "",
			HasKeys:   len(keys) > 0,
			KeysCount: len(keys),
			Email:     ec.Email,
			Proxy:     ec.Proxy,
			Timeout:   ec.Timeout,
			Size:      ec.Size,
		}
		fillWebEngineFromSource(&item, configMapForSource(cfg, name))
		if doc, ok := editableEngineDocs[name]; ok {
			item.API = doc.API
			item.URL = doc.URL
			item.Credential = doc.Credential
			item.Scope = doc.Scope
		}
		engines[name] = item
	}
	sourceNames := make([]string, 0, len(s.sources))
	for name := range s.sources {
		sourceNames = append(sourceNames, name)
	}
	sort.Strings(sourceNames)

	// Build the grouped category view. Only include category entries that
	// actually map to an engine in `engines` (defensive against typos in
	// engineCategories). Anything in `engines` but unreferenced by any
	// category falls into the trailing "其它" bucket.
	categorised := make(map[string]bool, len(names))
	cats := make([]engineCategoryView, 0, len(engineCategories)+1)
	for _, def := range engineCategories {
		view := engineCategoryView{Title: def.Title, Hint: def.Hint}
		for _, n := range def.Names {
			if _, present := engines[n]; present {
				view.Engines = append(view.Engines, n)
				categorised[n] = true
			}
		}
		if len(view.Engines) > 0 {
			cats = append(cats, view)
		}
	}
	var leftovers []string
	for _, n := range names {
		if !categorised[n] {
			leftovers = append(leftovers, n)
		}
	}
	if len(leftovers) > 0 {
		cats = append(cats, engineCategoryView{
			Title:   "其它",
			Hint:    "暂未分类的引擎（新加的源会先落在这里）。",
			Engines: leftovers,
		})
	}

	return webConfigResponse{
		OK:                    ok,
		Path:                  s.cfgPath,
		SecretPlaceholder:     configSecretPlaceholder,
		Runner:                webConfigRunner{EnabledSources: cleanStringList(cfg.Runner.EnabledSources), Proxy: cfg.Runner.Proxy, UserAgent: cfg.Runner.UserAgent, MaxConcurrency: cfg.Runner.MaxConcurrency, Timeout: cfg.Runner.Timeout},
		Engines:               engines,
		EngineCategories:      cats,
		SourcesYAML:           configYAMLString(cfg.Sources),
		ExtraYAML:             configYAMLString(cfg.Extra),
		RegisteredSourceNames: sourceNames,
	}
}

// timeoutUnlimitedSec 当用户传 0/负数 表示"不限"时，使用的实际上限（24h）。
// Go 的 context 不支持真正的"无限"，给一个非常大的值即可。
const timeoutUnlimitedSec = 24 * 3600

func (s *server) buildRunnerConfig(enabled []string, timeout int) *runner.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	cfg := s.cfg
	mergedConfigs := make(map[string]any)
	for k, v := range cfg.Sources {
		mergedConfigs[k] = v
	}
	for name, ec := range cfg.Engines {
		// Start from any existing sources.<name> map so we DON'T wipe fields
		// the user set manually in YAML (e.g. sources.intelx.timeout). engines.*
		// only overrides the canonical fields it owns: key/keys/email/proxy/
		// timeout/size.
		m, _ := mergedConfigs[name].(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		if ec.Key != "" {
			m["key"] = ec.Key
		}
		if len(ec.Keys) > 0 {
			m["keys"] = ec.Keys
		}
		if ec.Email != "" {
			m["email"] = ec.Email
		}
		if ec.Proxy != "" {
			m["proxy"] = ec.Proxy
		}
		if ec.Timeout > 0 {
			m["timeout"] = ec.Timeout
		}
		if ec.Size > 0 {
			m["size"] = ec.Size
		}
		mergedConfigs[name] = m
	}
	// 把 engine key 透传给下游链式 source（supply_*/path_pivot）。
	// 这些 source 本身不属于 engines.* 配置段，但需要 fofa/quake 引擎的 key 才能跑；
	// 之前如果用户只在 engines.fofa.key 配了 key，这些 source 会报 "needs fofa_key"。
	getEngineKey := func(engineName string) string {
		if m, ok := mergedConfigs[engineName].(map[string]any); ok {
			if k, ok2 := m["key"].(string); ok2 && k != "" {
				return k
			}
			if ks, ok2 := m["keys"].([]string); ok2 && len(ks) > 0 {
				return ks[0]
			}
			if ks, ok2 := m["keys"].([]any); ok2 && len(ks) > 0 {
				if s, ok3 := ks[0].(string); ok3 {
					return s
				}
			}
		}
		return ""
	}
	fofaKey := getEngineKey("fofa")
	quakeKey := getEngineKey("quake")
	for _, dep := range []string{"supply_pivots", "supply_vendor", "supply_auto", "path_pivot"} {
		m, _ := mergedConfigs[dep].(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		// 仅当用户没在 sources.<dep> 里显式配 fofa_key/quake_key 时才注入
		if _, ok := m["fofa_key"]; !ok && fofaKey != "" {
			m["fofa_key"] = fofaKey
		}
		if _, ok := m["quake_key"]; !ok && quakeKey != "" {
			m["quake_key"] = quakeKey
		}
		mergedConfigs[dep] = m
	}
	if len(enabled) == 0 {
		enabled = cfg.Runner.EnabledSources
	}
	// 语义：timeout > 0 → 用该值；timeout == 0 → "不限"（24h 上限，避免 ctx 永不退出）
	var t int
	switch {
	case timeout > 0:
		t = timeout
	case timeout == 0:
		t = timeoutUnlimitedSec
	default: // 负数当作未指定，回落到配置默认
		t = cfg.Runner.Timeout
		if t <= 0 {
			t = 60
		}
	}
	return &runner.Config{
		EnabledSources: enabled,
		SourceConfigs:  mergedConfigs,
		Proxy:          cfg.Runner.Proxy,
		UserAgent:      cfg.Runner.UserAgent,
		MaxConcurrency: cfg.Runner.MaxConcurrency,
		Timeout:        t,
	}
}

// ----------- API -----------

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "sources": len(s.sources), "time": time.Now().UTC()})
}

type sourceInfo struct {
	Name     string   `json:"name"`
	Accepts  []string `json:"accepts"`
	NeedsKey bool     `json:"needs_key"`
	HasKey   bool     `json:"has_key"`
}

func (s *server) handleSources(w http.ResponseWriter, r *http.Request) {
	cfg := s.configSnapshot()
	out := make([]sourceInfo, 0, len(s.sources))
	for name, src := range s.sources {
		out = append(out, sourceInfo{
			Name: name, Accepts: src.Accepts(), NeedsKey: src.NeedsKey(), HasKey: sourceHasConfiguredCredential(cfg, name),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, 200, out)
}

func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, s.webConfigResponse(s.configSnapshot(), true))
	case http.MethodPost:
		var req webConfigUpdate
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, 400, "invalid json: "+err.Error())
			return
		}
		old := s.configSnapshot()
		next, err := cloneConfig(old)
		if err != nil {
			writeError(w, 500, "clone config: "+err.Error())
			return
		}
		next.Runner.EnabledSources = cleanStringList(req.Runner.EnabledSources)
		next.Runner.Proxy = strings.TrimSpace(req.Runner.Proxy)
		next.Runner.UserAgent = strings.TrimSpace(req.Runner.UserAgent)
		next.Runner.MaxConcurrency = req.Runner.MaxConcurrency
		next.Runner.Timeout = req.Runner.Timeout
		if next.Engines == nil {
			next.Engines = make(map[string]config.EngineConfig)
		}
		for name, upd := range req.Engines {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if !isEditableCoreEngine(name) {
				continue
			}
			ec := next.Engines[name]
			ec.Enabled = upd.Enabled
			key := strings.TrimSpace(upd.Key)
			if upd.ClearKey {
				ec.Key = ""
			} else if key != "" && key != configSecretPlaceholder {
				ec.Key = key
			}
			keys := cleanStringList(upd.Keys)
			if upd.ClearKeys {
				ec.Keys = nil
			} else if len(keys) > 0 {
				ec.Keys = keys
			}
			ec.Email = strings.TrimSpace(upd.Email)
			ec.Proxy = strings.TrimSpace(upd.Proxy)
			ec.Timeout = upd.Timeout
			ec.Size = upd.Size
			next.Engines[name] = ec
		}
		sources, err := parseConfigYAMLMap(req.SourcesYAML)
		if err != nil {
			writeError(w, 400, "sources yaml: "+err.Error())
			return
		}
		extra, err := parseConfigYAMLMap(req.ExtraYAML)
		if err != nil {
			writeError(w, 400, "extra yaml: "+err.Error())
			return
		}
		if restored, ok := restoreConfigSecrets(sources, old.Sources, false).(map[string]any); ok {
			next.Sources = restored
		} else {
			next.Sources = sources
		}
		if next.Sources == nil {
			next.Sources = make(map[string]any)
		}
		for name, upd := range req.Engines {
			name = strings.TrimSpace(name)
			if name == "" || isEditableCoreEngine(name) {
				continue
			}
			m := sourceConfigMapForWrite(next.Sources, name)
			if ec, ok := next.Engines[name]; ok {
				if _, exists := m["key"]; !exists && strings.TrimSpace(ec.Key) != "" {
					m["key"] = ec.Key
				}
				if _, exists := m["keys"]; !exists && len(cleanStringList(ec.Keys)) > 0 {
					m["keys"] = cleanStringList(ec.Keys)
				}
				if _, exists := m["email"]; !exists && strings.TrimSpace(ec.Email) != "" {
					m["email"] = strings.TrimSpace(ec.Email)
				}
				if _, exists := m["proxy"]; !exists && strings.TrimSpace(ec.Proxy) != "" {
					m["proxy"] = strings.TrimSpace(ec.Proxy)
				}
				if _, exists := m["timeout"]; !exists && ec.Timeout > 0 {
					m["timeout"] = ec.Timeout
				}
				if _, exists := m["size"]; !exists && ec.Size > 0 {
					m["size"] = ec.Size
				}
				delete(next.Engines, name)
			}
			applyWebConfigUpdateToSource(m, upd)
		}
		if restored, ok := restoreConfigSecrets(extra, old.Extra, false).(map[string]any); ok {
			next.Extra = restored
		} else {
			next.Extra = extra
		}
		if err := next.SaveToFile(s.cfgPath); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		s.cfgMu.Lock()
		s.cfg = next
		s.cfgMu.Unlock()
		writeJSON(w, 200, s.webConfigResponse(next, true))
	default:
		writeError(w, 405, "method not allowed")
	}
}

type searchReq struct {
	Target      string   `json:"target"`            // 单目标（向后兼容）
	Targets     []string `json:"targets,omitempty"` // 多目标批量：若非空则按顺序串行跑，结果合并到一个 entry
	Sources     []string `json:"sources"`
	MaxAssets   int      `json:"max_assets"`
	Timeout     int      `json:"timeout"`
	Concurrency int      `json:"concurrency"` // 0 = 使用配置默认
	Proxy       string   `json:"proxy"`       // 空 = 使用配置默认
	Active      bool     `json:"active"`      // true = 允许向目标发流量（主动模式）
	Strict      *bool    `json:"strict"`      // true = 全局过滤掉与目标域无关的资产
	SrcTimeout  int      `json:"src_timeout"` // 单源超时（秒），0/负数 = runner 默认 45s
}

func (r *searchReq) strictEnabled() bool {
	if r == nil || r.Strict == nil {
		return true
	}
	return *r.Strict
}

// normalizeTargets 整合 Targets[] 与 Target，去空白、去重、保序。
// 优先级：Targets[] > Target；Target 作为兜底（也支持 "a.com,b.com,c.com" 这种逗号分隔）。
func normalizeTargets(multi []string, single string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(multi)+1)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, t := range multi {
		// 兼容前端把多行/逗号/空白都丢进 Targets[]
		for _, p := range strings.FieldsFunc(t, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
		}) {
			add(p)
		}
	}
	// Target 字段同样支持逗号/换行/空格 分隔
	for _, p := range strings.FieldsFunc(single, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	}) {
		add(p)
	}
	return out
}

// strictFilter 把跑回来的资产按"是否与目标相关"过滤。
// 命中规则（任一）：
//  1. host / domain / 从 url 解析的 hostname  等于 target 或者是 target 的子域
//  2. host 中以 . - _ 切分的 token 里包含 target 的最左标签（适配 cloud_bucket 这类 ajzq.s3.amazonaws.com）
//  3. cert_domains 里有任何一项命中规则 1
//
// IP 形式 target 走单独逻辑：仅当 asset.IP == target 或 asset host 解析到该 IP 才保留。
// 非域非 IP 的关键字 target（如 "中国移动"）不过滤，原样返回。
func strictFilter(target string, assets []*models.Asset) []*models.Asset {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" || len(assets) == 0 {
		return assets
	}
	// IP target
	if isIPLiteral(target) {
		out := make([]*models.Asset, 0, len(assets))
		for _, a := range assets {
			if a == nil {
				continue
			}
			if a.IP == target {
				out = append(out, a)
			}
		}
		return out
	}
	// Domain target
	if !strings.Contains(target, ".") {
		return assets // 不是域名也不是 IP，不过滤
	}
	label := strings.SplitN(target, ".", 2)[0]
	suffix := "." + target

	hostMatch := func(h string) bool {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return false
		}
		// 去端口
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
			h = h[:i]
		}
		if h == target || strings.HasSuffix(h, suffix) {
			return true
		}
		// 标签 token 匹配（cloud_bucket / 反查类的拼接 host）
		parts := strings.FieldsFunc(h, func(r rune) bool { return r == '.' || r == '-' || r == '_' })
		for _, p := range parts {
			if p == label {
				return true
			}
		}
		return false
	}

	out := make([]*models.Asset, 0, len(assets))
	for _, a := range assets {
		if a == nil {
			continue
		}
		if hostMatch(a.Host) || hostMatch(a.Domain) {
			out = append(out, a)
			continue
		}
		if a.URL != "" {
			if u, err := neturl.Parse(a.URL); err == nil && hostMatch(u.Hostname()) {
				out = append(out, a)
				continue
			}
		}
		matched := false
		for _, cd := range a.CertDomains {
			if hostMatch(cd) {
				matched = true
				break
			}
		}
		if matched {
			out = append(out, a)
		}
	}
	return out
}

// isIPLiteral 简单判断字符串是不是 IPv4/IPv6 字面量
func isIPLiteral(s string) bool {
	if strings.Count(s, ".") == 3 {
		for _, p := range strings.Split(s, ".") {
			if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 255 {
				return false
			}
		}
		return true
	}
	if strings.Contains(s, ":") && !strings.Contains(s, ".") {
		return true // 粗略 v6
	}
	return false
}

func (s *server) doSearch(ctx context.Context, req *searchReq) ([]*models.Asset, error) {
	rcfg := s.buildRunnerConfig(req.Sources, req.Timeout)
	// 本次请求覆盖：并发 / 代理
	if req.Concurrency > 0 {
		rcfg.MaxConcurrency = req.Concurrency
	}
	if req.Proxy != "" {
		rcfg.Proxy = req.Proxy
	}
	// 主动模式总开关：默认严格被动；显式开启才允许 source 直连目标
	rcfg.Active = req.Active
	// 单源上限：透传到 runner，让 source/engine 自己提前停止分页（fofa 不再卡 200 上限）
	rcfg.PerSourceMax = req.MaxAssets
	// 单源超时：避免 path_pivot/wayback_params 这种个别源卡死拖整轮
	rcfg.PerSourceTimeout = req.SrcTimeout
	r := runner.NewRunner(rcfg, s.sources)
	timeout := time.Duration(rcfg.Timeout) * time.Second
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	assets, err := r.Run(cctx, req.Target)
	// 严格模式：全局过滤与 target 无关的资产
	if req.strictEnabled() {
		before := len(assets)
		assets = strictFilter(req.Target, assets)
		log.Printf("[strict] %s: %d → %d", req.Target, before, len(assets))
	}
	// per-source 截断：MaxAssets > 0 时每个源最多保留 N 条；0/负数 表示不限
	if req.MaxAssets > 0 && len(assets) > 0 {
		counter := make(map[string]int, 32)
		out := make([]*models.Asset, 0, len(assets))
		for _, a := range assets {
			if counter[a.Source] >= req.MaxAssets {
				continue
			}
			counter[a.Source]++
			out = append(out, a)
		}
		assets = out
	}
	return assets, err
}

func (s *server) handleSearch(w http.ResponseWriter, r *http.Request) {
	var req searchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid json: "+err.Error())
		return
	}
	if req.Target == "" {
		writeError(w, 400, "target required")
		return
	}
	assets, err := s.doSearch(r.Context(), &req)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, assets)
}

// handleRun 异步采集：立刻返回 run_id，后台跑 runner，
// 前端通过 /api/progress?id=... 轮询进度，跑完后取 /api/result?id=...
func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	var req searchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid json: "+err.Error())
		return
	}
	// 归一化目标：Targets[] 优先；空则退回单 Target；首个非空作为展示主目标。
	targets := normalizeTargets(req.Targets, req.Target)
	if len(targets) == 0 {
		writeError(w, 400, "target required")
		return
	}
	displayTarget := targets[0]
	if len(targets) > 1 {
		displayTarget = fmt.Sprintf("%s (+%d)", targets[0], len(targets)-1)
	}

	rcfg := s.buildRunnerConfig(req.Sources, req.Timeout)
	if req.Concurrency > 0 {
		rcfg.MaxConcurrency = req.Concurrency
	}
	if req.Proxy != "" {
		rcfg.Proxy = req.Proxy
	}
	rcfg.Active = req.Active
	// 单源上限 / 单源超时：同 doSearch
	rcfg.PerSourceMax = req.MaxAssets
	rcfg.PerSourceTimeout = req.SrcTimeout

	// 多目标场景：Total = 每目标计划源数之和（进度条 0~Total 累加）
	plannedTotal := 0
	for _, t := range targets {
		plannedTotal += countPlannedSources(rcfg.EnabledSources, s.sources, t)
	}

	entry := &runEntry{
		ID:          randomID(),
		Target:      displayTarget,
		Sources:     rcfg.EnabledSources,
		When:        time.Now().UTC(),
		Status:      "running",
		StartedAt:   time.Now().UTC(),
		Total:       plannedTotal,
		TargetTotal: len(targets),
		TargetIdx:   0,
	}
	s.store.put(entry)

	// 把 OnEvent 钩到 entry.Events（线程安全）
	rcfg.OnEvent = func(ev runner.SourceEvent) {
		entry.appendEvent(ev)
	}

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				entry.mu.Lock()
				entry.Status = "error"
				entry.ErrMsg = fmt.Sprintf("panic: %v", rec)
				entry.FinishedAt = time.Now().UTC()
				entry.mu.Unlock()
			}
		}()
		rr := runner.NewRunner(rcfg, s.sources)
		// 多目标：总超时 = 配置的 timeout × 目标数，避免单目标超时把后面的全部 cancel。
		// 单目标时退化为原 timeout。
		baseTimeout := time.Duration(rcfg.Timeout) * time.Second
		totalTimeout := baseTimeout * time.Duration(len(targets))
		ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
		defer cancel()
		// 暴露 cancel 给 /api/cancel；defer 里清掉避免泄漏
		entry.mu.Lock()
		entry.cancel = cancel
		entry.mu.Unlock()
		defer func() {
			entry.mu.Lock()
			entry.cancel = nil
			entry.mu.Unlock()
		}()

		// 多目标顺序跑：每目标独立 sub-ctx 用 baseTimeout，保证一个慢目标不拖死其它。
		var rawAll []*models.Asset
		var firstErr error
		for i, t := range targets {
			entry.mu.Lock()
			entry.TargetIdx = i + 1
			entry.CurrentTarget = t
			entry.mu.Unlock()
			subCtx, subCancel := context.WithTimeout(ctx, baseTimeout)
			batch, err := rr.Run(subCtx, t)
			subCancel()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			if req.strictEnabled() {
				before := len(batch)
				batch = strictFilter(t, batch)
				log.Printf("[strict] target[%d]=%s (run_id=%s): %d → %d", i, t, entry.ID, before, len(batch))
			}
			rawAll = append(rawAll, batch...)
			log.Printf("[run] target[%d/%d]=%s 拉到 %d 条，累计 raw=%d", i+1, len(targets), t, len(batch), len(rawAll))
			if ctx.Err() != nil {
				log.Printf("[run] 全局超时触发，停止剩余目标")
				break
			}
		}
		// 被动跑完 → 主动链：当 Active=true 时自动接 7 件主动套件
		// （subbrute / portscan / httpx / webmeta / tlscert / dnsadv / jscrawl）。
		// 链路用同一个 ctx，不会比被动跑得更久；事件流写进 entry.Events，前端进度条复用。
		if req.Active && ctx.Err() == nil {
			pv := extractChainPivots(targets, rawAll)
			// 把链路计划步数加进 Total，避免进度条卡到 99%
			extraSteps := planChainSteps(pv)
			if extraSteps > 0 {
				entry.mu.Lock()
				entry.Total += extraSteps
				entry.mu.Unlock()
			}
			more := s.runAutoActiveChain(ctx, entry, pv, rcfg.MaxConcurrency, rcfg.Timeout)
			if len(more) > 0 {
				rawAll = append(rawAll, more...)
			}
		}

		assets := rawAll
		err := firstErr
		// per-source 截断：跨所有 target 的累计 source 上限
		if req.MaxAssets > 0 && len(assets) > 0 {
			counter := make(map[string]int, 32)
			out := make([]*models.Asset, 0, len(assets))
			for _, a := range assets {
				if counter[a.Source] >= req.MaxAssets {
					continue
				}
				counter[a.Source]++
				out = append(out, a)
			}
			assets = out
		}
		// 保留原始资产堆（dedup_preview/apply 用），同时默认跑 smart 去重作为展示视图。
		rawAssets := assets
		dedupAssets, _ := core.DedupWithStats(rawAssets, core.KeySmart)
		entry.mu.Lock()
		entry.RawAssets = rawAssets
		entry.Assets = dedupAssets
		entry.FinishedAt = time.Now().UTC()
		// 区分 3 种结束态：用户主动取消 / 真错 / 正常完成
		if entry.Canceled {
			entry.Status = "canceled"
			entry.ErrMsg = "用户取消"
		} else if err != nil {
			entry.Status = "error"
			entry.ErrMsg = err.Error()
		} else {
			entry.Status = "done"
		}
		entry.mu.Unlock()
		// 持久化到 SQLite（dbReady=false 时跳过；空资产也保留一条空 session，方便排错）
		if s.dbReady {
			meta := map[string]any{
				"run_id":       entry.ID,
				"sources":      entry.Sources,
				"status":       entry.Status,
				"err":          entry.ErrMsg,
				"started_at":   entry.StartedAt,
				"finished_at":  entry.FinishedAt,
				"per_src_max":  req.MaxAssets,
				"timeout":      req.Timeout,
				"concurrency":  req.Concurrency,
				"proxy":        req.Proxy,
				"active":       req.Active,
				"strict":       req.strictEnabled(),
				"src_timeout":  req.SrcTimeout,
				"target_total": len(targets),
				"event_count":  len(entry.snapshotEvents()),
			}
			joinedTargets := strings.Join(targets, ",")
			name := displayTarget
			if entry.Status == "error" {
				name = displayTarget + " [error]"
			}
			// db 同时存 deduped 视图（is_raw=0）和原始堆（is_raw=1）；后者重启后能继续切 dedup 策略。
			// 为避免会话存档膨胀过大：raw 比 dedup 多出超过 5 万条时只存 dedup（仍可用，只是 raw 切策略回退到 deduped 视图）。
			rawForSave := rawAssets
			if len(rawAssets)-len(dedupAssets) > 50000 {
				log.Printf("[server] INFO run=%s raw too large (%d) → only save deduped view", entry.ID, len(rawAssets))
				rawForSave = nil
			}
			if dbID, saveErr := core.SaveSessionWithRaw(name, joinedTargets, joinedTargets, dedupAssets, rawForSave, meta); saveErr != nil {
				log.Printf("[server] WARN SaveSession run_id=%s: %v", entry.ID, saveErr)
			} else {
				entry.mu.Lock()
				entry.DBID = dbID
				entry.mu.Unlock()
			}
		}
	}()

	writeJSON(w, 202, map[string]any{
		"id":     entry.ID,
		"target": entry.Target,
		"total":  entry.Total,
		"status": entry.Status,
	})
}

// countPlannedSources 估算本次会真正运行的 source 数（与 runner.accepts 同语义需保守估）。
// 这里只过滤"name 不在 registry"，不做 accepts 判定（因为那需要 target 类型分类）。
// 实际运行中跳过的 source 表现为该 source 永远不会发 start 事件，
// 前端按 done/start 比例展示进度即可，不依赖 total 准确。
func countPlannedSources(enabled []string, all map[string]source.Source, _ string) int {
	n := 0
	for _, name := range enabled {
		if _, ok := all[name]; ok {
			n++
		}
	}
	return n
}

// handleProgress 轮询进度。?id=...&since=N 返回 events[N:]
func (s *server) handleProgress(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, 400, "id required")
		return
	}
	since := 0
	if v := r.URL.Query().Get("since"); v != "" {
		fmt.Sscanf(v, "%d", &since)
	}
	e, ok := s.store.get(id)
	if !ok {
		writeError(w, 404, "not found")
		return
	}
	all := e.snapshotEvents()
	if since < 0 {
		since = 0
	}
	if since > len(all) {
		since = len(all)
	}
	new := all[since:]

	e.mu.Lock()
	status := e.Status
	errMsg := e.ErrMsg
	total := e.Total
	finished := e.FinishedAt
	count := len(e.Assets)
	tgtTotal := e.TargetTotal
	tgtIdx := e.TargetIdx
	curTarget := e.CurrentTarget
	e.mu.Unlock()

	// 统计 start / done / err
	started, done, errs := 0, 0, 0
	for _, ev := range all {
		switch ev.Phase {
		case "start":
			started++
		case "done":
			done++
			if ev.Err != "" {
				errs++
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"id":             id,
		"status":         status,
		"total":          total,
		"started":        started,
		"done":           done,
		"errors":         errs,
		"count":          count,
		"finished":       finished,
		"err_msg":        errMsg,
		"events":         new,
		"next":           len(all),
		"target_total":   tgtTotal,
		"target_idx":     tgtIdx,
		"current_target": curTarget,
	})
}

// handleCancel POST /api/cancel?id=<run_id>
// 用户点取消按钮时调用：触发该会话的 context.cancel，runner 内的网络请求会立即返回错误，
// 协程随后走到 finishing 块、标 Canceled=true / Status=canceled。
func (s *server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, 400, "id required")
		return
	}
	e, ok := s.store.get(id)
	if !ok {
		writeError(w, 404, "not found")
		return
	}
	e.mu.Lock()
	if e.Status != "running" {
		status := e.Status
		e.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": false, "id": id, "reason": "not running", "status": status})
		return
	}
	cancel := e.cancel
	e.Canceled = true
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": id, "status": "canceling"})
}

// handleProgressSSE 通过 Server-Sent Events 推送进度，避免 700ms 轮询的开销和延迟。
// 协议（每条 event）：
//
//	event: progress
//	data: {<同 /api/progress 返回体>}
//
// 完成（status != running）后发送一条 event: done 并关闭。
// 客户端连接断开（CloseNotifier / ctx.Done()）时退出循环。
func (s *server) handleProgressSSE(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, 400, "id required")
		return
	}
	e, ok := s.store.get(id)
	if !ok {
		writeError(w, 404, "not found")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // 兼容 nginx 反代
	w.WriteHeader(200)
	flusher.Flush()

	since := 0
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		all := e.snapshotEvents()
		if since > len(all) {
			since = len(all)
		}
		newEvents := all[since:]
		since = len(all)

		e.mu.Lock()
		status := e.Status
		errMsg := e.ErrMsg
		total := e.Total
		finished := e.FinishedAt
		count := len(e.Assets)
		tgtTotal := e.TargetTotal
		tgtIdx := e.TargetIdx
		curTarget := e.CurrentTarget
		e.mu.Unlock()

		started, done, errs := 0, 0, 0
		for _, ev := range all {
			switch ev.Phase {
			case "start":
				started++
			case "done":
				done++
				if ev.Err != "" {
					errs++
				}
			}
		}
		payload := map[string]any{
			"id":             id,
			"status":         status,
			"total":          total,
			"started":        started,
			"done":           done,
			"errors":         errs,
			"count":          count,
			"finished":       finished,
			"err_msg":        errMsg,
			"events":         newEvents,
			"next":           len(all),
			"target_total":   tgtTotal,
			"target_idx":     tgtIdx,
			"current_target": curTarget,
		}
		buf, _ := json.Marshal(payload)
		if _, err := fmt.Fprintf(w, "event: progress\ndata: %s\n\n", string(buf)); err != nil {
			return
		}
		flusher.Flush()
		if status != "running" {
			fmt.Fprintf(w, "event: done\ndata: {}\n\n")
			flusher.Flush()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *server) handleResult(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, 400, "id required")
		return
	}
	e, ok := s.store.get(id)
	if !ok {
		writeError(w, 404, "not found")
		return
	}
	writeJSON(w, 200, e)
}

type statsResp struct {
	ID         string    `json:"id"`
	Total      int       `json:"total"`
	Target     string    `json:"target"`
	BySource   []kvCount `json:"by_source"`
	ByCountry  []kvCount `json:"by_country"`
	ByPort     []kvCount `json:"by_port"`
	ByASN      []kvCount `json:"by_asn"`
	ByProtocol []kvCount `json:"by_protocol"`
	ByTag      []kvCount `json:"by_tag"`
	ByService  []kvCount `json:"by_service"`
}

type kvCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func topN(m map[string]int, n int) []kvCount {
	out := make([]kvCount, 0, len(m))
	for k, v := range m {
		if k == "" {
			continue
		}
		out = append(out, kvCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, 400, "id required")
		return
	}
	e, ok := s.store.get(id)
	if !ok {
		writeError(w, 404, "not found")
		return
	}
	bySrc := map[string]int{}
	byCountry := map[string]int{}
	byPort := map[string]int{}
	byASN := map[string]int{}
	byProto := map[string]int{}
	byTag := map[string]int{}
	bySvc := map[string]int{}
	for _, a := range e.Assets {
		bySrc[a.Source]++
		byCountry[a.Country]++
		if a.Port > 0 {
			byPort[fmt.Sprintf("%d", a.Port)]++
		}
		byASN[a.ASN]++
		byProto[a.Protocol]++
		bySvc[a.Service]++
		for _, t := range a.Tags {
			byTag[t]++
		}
	}
	writeJSON(w, 200, statsResp{
		ID: e.ID, Total: len(e.Assets), Target: e.Target,
		BySource: topN(bySrc, 20), ByCountry: topN(byCountry, 20),
		ByPort: topN(byPort, 20), ByASN: topN(byASN, 20),
		ByProtocol: topN(byProto, 10), ByTag: topN(byTag, 30), ByService: topN(bySvc, 20),
	})
}

func (s *server) handleImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, 400, "parse multipart: "+err.Error())
		return
	}
	kind := strings.ToLower(r.FormValue("kind"))
	if kind == "" {
		kind = "auto"
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "missing file: "+err.Error())
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "import-*"+filepath.Ext(header.Filename))
	if err != nil {
		writeError(w, 500, "tempfile: "+err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, file); err != nil {
		writeError(w, 500, "save: "+err.Error())
		return
	}
	tmp.Close()

	var assets []*models.Asset
	switch kind {
	case "fofa":
		assets, err = importers.ImportFOFAXLSX(tmp.Name())
	case "quake":
		assets, err = importers.ImportQuakeXLSX(tmp.Name())
	case "recon":
		assets, err = importers.ImportReconXLSX(tmp.Name())
	default: // auto
		rows, e := importers.ReadXLSXRows(tmp.Name())
		if e != nil {
			writeError(w, 400, e.Error())
			return
		}
		if len(rows) == 0 {
			writeJSON(w, 200, []any{})
			return
		}
		headers := rows[0]
		switch {
		case headers["ICP备案号"] != "":
			assets, err = importers.ImportFOFAXLSX(tmp.Name())
			kind = "fofa"
		case headers["传输协议"] != "":
			assets, err = importers.ImportQuakeXLSX(tmp.Name())
			kind = "quake"
		default:
			assets, err = importers.ImportReconXLSX(tmp.Name())
			kind = "recon"
		}
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	// 导入文件不知道是否去过重，统一把同一份既挂 RawAssets 也挂 Assets。
	// 用户进 dedup tab 可以再切策略；切换走的是同一份原始堆，不会丢数据。
	entry := &runEntry{
		ID: randomID(), Target: "imported:" + header.Filename,
		Sources: []string{"import_" + kind}, Assets: assets, RawAssets: assets, When: time.Now().UTC(),
	}
	s.store.put(entry)
	writeJSON(w, 200, map[string]any{
		"id": entry.ID, "count": len(assets), "kind": kind, "file": header.Filename,
	})
}

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	html, err := templateFS.ReadFile("templates/dashboard.html")
	if err != nil {
		writeError(w, 500, "template not found: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(html)
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// authExempt 这些路径不需要鉴权（健康检查 + 仪表盘 HTML 本体；HTML 由前端再去 prompt token）
var authExempt = map[string]bool{
	"/api/health": true,
	"/":           true,
}

// withAuth 鉴权中间件：当 server.authToken 非空时，所有非豁免路径必须带匹配 token。
// 接受位置：
//  1. HTTP Header `Authorization: Bearer <tok>`
//  2. Query string `?token=<tok>`（兼容 EventSource —— 它不支持自定义 header）
func (s *server) withAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" || authExempt[r.URL.Path] {
			h.ServeHTTP(w, r)
			return
		}
		got := ""
		if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
			got = strings.TrimPrefix(v, "Bearer ")
		}
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		// constant-time 比较，避免计时侧信道（token 不长，性能可忽略）
		if got == "" || subtleConstEq(got, s.authToken) == false {
			writeError(w, 401, "unauthorized: missing or invalid token (Authorization: Bearer <tok> 或 ?token=<tok>)")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// subtleConstEq constant-time 字符串相等比较
func subtleConstEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ----------------- 历史会话 (SQLite) -----------------

// handleSessions
//
//	GET    /api/sessions               → 列出全部历史会话
//	DELETE /api/sessions?id=<dbID>     → 删除单条（级联删 assets）
func (s *server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if !s.dbReady {
		writeError(w, 503, "history db not initialized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := core.ListSessions()
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, list)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, 400, "id required")
			return
		}
		var sid int
		if _, err := fmt.Sscanf(id, "%d", &sid); err != nil || sid <= 0 {
			writeError(w, 400, "invalid id")
			return
		}
		if err := core.DeleteSession(sid); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		// 顺手把 runStore 里 db-<sid> 的影子条目也删了，避免下次 load 拿到陈旧缓存
		s.store.mu.Lock()
		delete(s.store.data, fmt.Sprintf("db-%d", sid))
		s.store.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true, "deleted": sid})
	case http.MethodPatch:
		// PATCH /api/sessions?id=<dbID>   body: {"notes": "..."}  → 更新备注
		id := r.URL.Query().Get("id")
		var sid int
		if _, err := fmt.Sscanf(id, "%d", &sid); err != nil || sid <= 0 {
			writeError(w, 400, "invalid id")
			return
		}
		var body struct {
			Notes string `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, 400, "invalid body: "+err.Error())
			return
		}
		if err := core.UpdateSessionNotes(sid, body.Notes); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "id": sid, "notes": body.Notes})
	default:
		writeError(w, 405, "method not allowed")
	}
}

// handleSessionLoad: POST /api/sessions/load?id=<dbID>
// 把 SQLite 里的会话 hydrate 进 runStore（id="db-<dbID>"），返回新 id；
// 前端拿到 id 后用 /api/result?id=... 和 /api/stats?id=... 渲染（复用现有逻辑）。
func (s *server) handleSessionLoad(w http.ResponseWriter, r *http.Request) {
	if !s.dbReady {
		writeError(w, 503, "history db not initialized")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		writeError(w, 400, "id required")
		return
	}
	var sid int
	if _, err := fmt.Sscanf(idStr, "%d", &sid); err != nil || sid <= 0 {
		writeError(w, 400, "invalid id")
		return
	}
	// 查一次 ListSessions 拿元信息（target / when / name）
	all, err := core.ListSessions()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	var meta *core.Session
	for i := range all {
		if all[i].ID == sid {
			meta = &all[i]
			break
		}
	}
	if meta == nil {
		writeError(w, 404, "session not found")
		return
	}
	assets, err := core.LoadSession(sid)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	// 优先取 raw 视图（is_raw=1），不存在则回退到 deduped（老库兼容）
	raw, rawErr := core.LoadSessionRaw(sid)
	if rawErr != nil || len(raw) == 0 {
		raw = assets
	}
	runID := fmt.Sprintf("db-%d", sid)
	entry := &runEntry{
		ID:        runID,
		Target:    meta.Targets,
		Sources:   []string{"history:" + meta.Name},
		Assets:    assets,
		RawAssets: raw, // 优先用 db 里真正的 raw 堆；老会话回退到 Assets 也能切策略

		When:       meta.CreatedAt,
		Status:     "done",
		StartedAt:  meta.CreatedAt,
		FinishedAt: meta.CreatedAt,
		Total:      len(assets),
		DBID:       sid,
	}
	s.store.put(entry)
	writeJSON(w, 200, map[string]any{
		"id":     runID,
		"target": meta.Targets,
		"count":  len(assets),
		"db_id":  sid,
	})
}

// handleSessionDiff GET /api/sessions/diff?a=<id_a>&b=<id_b>
// 比较 2 个会话的资产差（按 a.Key() 做主键 = smart 策略）：
//   - added：在 B 中但不在 A 中（新增）
//   - removed：在 A 中但不在 B 中（消失）
//   - common：两边都有的条数（不返回明细，仅计数）
//
// 大资产集（>5k 条）也仅返回前 500 条明细 + 完整计数，避免响应体过大。
func (s *server) handleSessionDiff(w http.ResponseWriter, r *http.Request) {
	if !s.dbReady {
		writeError(w, 503, "history db not initialized")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, 405, "method not allowed")
		return
	}
	parseID := func(name string) (int, error) {
		v := r.URL.Query().Get(name)
		if v == "" {
			return 0, fmt.Errorf("%s required", name)
		}
		var id int
		if _, err := fmt.Sscanf(v, "%d", &id); err != nil || id <= 0 {
			return 0, fmt.Errorf("invalid %s", name)
		}
		return id, nil
	}
	aID, err := parseID("a")
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	bID, err := parseID("b")
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if aID == bID {
		writeError(w, 400, "a and b must differ")
		return
	}
	aAssets, err := core.LoadSession(aID)
	if err != nil {
		writeError(w, 500, "load A: "+err.Error())
		return
	}
	bAssets, err := core.LoadSession(bID)
	if err != nil {
		writeError(w, 500, "load B: "+err.Error())
		return
	}
	// 以 a.Key() (smart) 作为身份键；空 key 单独归入 noKey 桶不参与 diff
	indexBy := func(arr []*models.Asset) map[string]*models.Asset {
		m := make(map[string]*models.Asset, len(arr))
		for _, a := range arr {
			k := a.Key()
			if k == "" {
				continue
			}
			if _, exists := m[k]; !exists {
				m[k] = a
			}
		}
		return m
	}
	aIdx := indexBy(aAssets)
	bIdx := indexBy(bAssets)
	var addedAll, removedAll []*models.Asset
	common := 0
	for k, asset := range bIdx {
		if _, in := aIdx[k]; in {
			common++
		} else {
			addedAll = append(addedAll, asset)
		}
	}
	for k, asset := range aIdx {
		if _, in := bIdx[k]; !in {
			removedAll = append(removedAll, asset)
		}
	}
	const sampleLimit = 500
	truncate := func(arr []*models.Asset) ([]*models.Asset, bool) {
		if len(arr) <= sampleLimit {
			return arr, false
		}
		return arr[:sampleLimit], true
	}
	addedSample, addedTrunc := truncate(addedAll)
	removedSample, removedTrunc := truncate(removedAll)
	writeJSON(w, 200, map[string]any{
		"a":                 aID,
		"b":                 bID,
		"a_total":           len(aAssets),
		"b_total":           len(bAssets),
		"a_keyed":           len(aIdx),
		"b_keyed":           len(bIdx),
		"common":            common,
		"added_count":       len(addedAll),
		"removed_count":     len(removedAll),
		"added":             addedSample,
		"removed":           removedSample,
		"added_truncated":   addedTrunc,
		"removed_truncated": removedTrunc,
		"sample_limit":      sampleLimit,
	})
}
