package runner

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// Runner 运行器，负责调度多个数据源
type Runner struct {
	sources map[string]source.Source
	cfg     *Config
	limiter *Limiter
}

// defaultNoProxy 默认绕过代理的国内站点（域名后缀匹配）。
//
// 这些都是国产服务，从国内直连最快、不走代理：
//
//	0.zone / 0zone.ai / 0zone.cc / daydaymap.com / fofa / hunter / quake / zoomeye / chinaz / bdziyi / 各大云厂商。
//
// 注意：这要求**真实 DNS 解析能拿到真实 IP**。如果用户开了 Clash fake-ip 模式，
// 系统 DNS 被劫持，所有域名都返回 198.18.x.x 假 IP，直连必死。
// runner 启动时会安装一个自定义 net.Resolver（默认走 223.5.5.5 / 119.29.29.29 / 8.8.8.8）
// 绕过系统 DNS，确保拿到真 IP；用户也可在 config 里通过 dns_servers 自定义。
var defaultNoProxy = "localhost,127.0.0.1,.cn,.gov.cn,.edu.cn,beian.miit.gov.cn,beianx.cn,bdziyi.com,chinaz.com,fofa.info,fofa.so,hunter.qianxin.com,quake.360.net,zoomeye.org,zoomeye.hk,0.zone,0zone.ai,0zone.cc,daydaymap.com,gitee.com,gitee.io,tencent.com,tencentcloud.com,qq.com,myqcloud.com,aliyun.com,aliyuncs.com,alipay.com,huaweicloud.com,myhuaweicloud.com,baidu.com,bdstatic.com,bytedance.com,volcengine.com,feishu.cn,tianyancha.com,qcc.com,qichacha.com"

// defaultDNSServers 默认使用的 DNS 服务器（顺序优先级，第一个失败 fallback 第二个…）
// 国内顺手 anycast：223.5.5.5 (阿里) / 119.29.29.29 (DNSPod) / 8.8.8.8 (Google) / 1.1.1.1 (Cloudflare)
var defaultDNSServers = []string{"223.5.5.5:53", "119.29.29.29:53", "8.8.8.8:53", "1.1.1.1:53"}

// Config 运行器配置
type Config struct {
	EnabledSources []string       `yaml:"enabled"`
	SourceConfigs  map[string]any `yaml:"sources"`
	Proxy          string         `yaml:"proxy"`
	NoProxy        string         `yaml:"no_proxy"` // 逗号分隔的不走代理的主机/后缀；空=用默认国内列表
	UserAgent      string         `yaml:"user_agent"`
	MaxConcurrency int            `yaml:"max_concurrency"`
	Timeout        int            `yaml:"timeout"` // seconds
	Extra          map[string]any `yaml:"extra"`
	// Active 主动模式总开关。
	// 关：所有 source 强制零流量到目标（js_endpoints/source_map_leak 走 Wayback；asn_recon 不本地端口扫；…）
	// 开：放行各 source 的"直连/主动"路径（cfg.Extra.direct_fetch / enable_active 注入 true）
	Active bool `yaml:"active"`
	// PerSourceMax 每个 source 最多保留多少条资产；0 / 负数 = 不限。
	// runner 会通过 source.WithMaxAssets(N) 把这个值透传到每个 source 的 Search 调用，
	// 然后 source / engine_adapter 会用它做内部分页停止条件（比如 fofa 的 MaxTotal）。
	// dashboard 上的"单源上限"字段最终落到这里。
	PerSourceMax int `yaml:"per_source_max"`
	// PerSourceTimeout 单源最多跑多少秒；0 = 用默认 45s。
	// 防止个别 source（path_pivot/wayback_params/ ze 之类）卡住整轮采集。
	// 超时只影响该 source，本身被 ctx 强制取消，并以 error 形式上报；
	// 其他 source 不受影响（OSINT 被动收集语义）。
	PerSourceTimeout int `yaml:"per_source_timeout"`
	// DNSServers 自定义 DNS 服务器列表（绕过系统 DNS，避免 Clash fake-ip 污染）。
	// 例：["223.5.5.5:53", "8.8.8.8:53"]。空 = 走系统 DNS（不安装自定义 resolver）。
	// 字符串形式接受 "1.2.3.4" 也接受 "1.2.3.4:53"，缺端口会自动补 :53。
	// 设为 ["off"] 显式关闭（即使默认行为是开）。
	DNSServers []string `yaml:"dns_servers"`
	// OnEvent 进度回调（可选）。每个 source 开始/结束时各调一次。
	// 不持锁，调用者自行做线程安全。yaml 不序列化。
	OnEvent func(ev SourceEvent) `yaml:"-"`
}

// SourceEvent runner 在采集过程中向上游回调的事件
type SourceEvent struct {
	Source string        `json:"source"`
	Phase  string        `json:"phase"` // "start" | "done"
	Count  int           `json:"count"` // done 时的资产数
	Dur    time.Duration `json:"dur"`   // done 时的耗时
	Err    string        `json:"err"`   // done 时的错误（空=成功）
}

// NewRunner 创建运行器
func NewRunner(cfg *Config, sources map[string]source.Source) *Runner {
	r := &Runner{
		sources: sources,
		cfg:     cfg,
		limiter: NewLimiter(cfg.MaxConcurrency, cfg.MaxConcurrency),
	}
	// 安装自定义 DNS resolver（绕过 Clash fake-ip 污染）。
	// 默认开启（用 223.5.5.5 / 8.8.8.8 等公网 DNS）；用户可在 cfg.DNSServers
	// 显式覆盖或填 ["off"] 完全禁用走系统 DNS。
	installCustomDNS(cfg.DNSServers)
	// 全局 proxy：注入 HTTPS_PROXY/HTTP_PROXY 让所有 req.C()
	// 通过 http.ProxyFromEnvironment 自动拾取（与 Python requests 行为一致）。
	// 国内站点走 NO_PROXY 直连，国外站点走代理。
	if cfg.Proxy != "" {
		// Go 的 http.ProxyFromEnvironment + socks5 dialer 默认就是
		// 把主机名透传给 SOCKS 服务端解析（等同 socks5h），
		// 不要把 socks5:// 改成 socks5h://（Go 不识别 socks5h scheme，会把 socks5h 当 host）。
		proxy := cfg.Proxy
		_ = os.Setenv("HTTPS_PROXY", proxy)
		_ = os.Setenv("HTTP_PROXY", proxy)
		_ = os.Setenv("ALL_PROXY", proxy)
		// NO_PROXY 默认包含常见国内站点；用户可在 config 里覆盖
		noProxy := cfg.NoProxy
		if noProxy == "" {
			noProxy = defaultNoProxy
		}
		_ = os.Setenv("NO_PROXY", noProxy)
		_ = os.Setenv("no_proxy", noProxy)
	}
	// 初始化各数据源配置。注意不把全局 cfg.Proxy 合并到 per-source，
	// 否则国内 source 调 SetProxyURL 会强制走代理、绕过 NO_PROXY。
	// proxy 完全靠 env + http.ProxyFromEnvironment + NO_PROXY 路由。
	// 仅合并 timeout 与用户显式的 per-source 配置（用户自己写 proxy 视为强制）。
	for name, src := range sources {
		merged := map[string]any{}
		if cfg.Timeout > 0 {
			merged["timeout"] = cfg.Timeout
		}
		if srcCfg, ok := cfg.SourceConfigs[name]; ok {
			if m, ok2 := srcCfg.(map[string]any); ok2 {
				for k, v := range m {
					merged[k] = v
				}
			}
		}
		if len(merged) > 0 {
			_ = src.SetConfig(merged)
		}
	}
	return r
}

// Run 运行指定目标的所有启用数据源。
// 各 source 互相独立：单源失败不取消其他源（OSINT 被动收集语义）。
// 全部完成后聚合返回 (assets, joined-err)。joined-err 仅作日志参考。
func (r *Runner) Run(ctx context.Context, target string) ([]*models.Asset, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allAssets []*models.Asset
	var errs []error

	for _, name := range r.cfg.EnabledSources {
		src, ok := r.sources[name]
		if !ok {
			continue
		}
		if !r.accepts(src, target) {
			continue
		}

		name, src := name, src
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("source %s panic: %v", name, rec))
					mu.Unlock()
				}
			}()
			if err := r.limiter.Wait(ctx); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("source %s: %w", name, err))
				mu.Unlock()
				return
			}
			// 仅当 Active=true 时透传"主动模式"开关给 source。
			// 默认关：source 必须按零流量路径执行。
			var opts []source.SearchOption
			if r.cfg.Active {
				opts = append(opts,
					source.WithExtra("direct_fetch", true),  // js_endpoints / source_map_leak
					source.WithExtra("enable_active", true), // asn_recon 本地端口扫描
				)
			}
			// 单源上限：>0 才透传，0/负数交给 source 自己的默认（一般 0=不限）
			if r.cfg.PerSourceMax > 0 {
				opts = append(opts, source.WithMaxAssets(r.cfg.PerSourceMax))
			}
			emit := func(ev SourceEvent) {
				if r.cfg.OnEvent != nil {
					r.cfg.OnEvent(ev)
				}
			}
			emit(SourceEvent{Source: name, Phase: "start"})
			t0 := time.Now()
			// 给每个 source 套一个独立的超时 ctx：单源卡死不再拖整轮采集。
			perTimeoutSec := r.cfg.PerSourceTimeout
			if perTimeoutSec <= 0 {
				perTimeoutSec = 45 // 默认 45s
			}
			srcCtx, srcCancel := context.WithTimeout(ctx, time.Duration(perTimeoutSec)*time.Second)
			assets, err := src.Search(srcCtx, target, opts...)
			srcCancel()
			// ctx 主动取消（顶层超时）跟单源超时区分开：
			//   - ctx.Err() != nil  → 顶层 ctx 已死，整轮结束，正常上报
			//   - srcCtx 超时但 ctx 还活着 → 单源超时，标错继续跑别的
			if err != nil && ctx.Err() == nil && srcCtx.Err() == context.DeadlineExceeded {
				err = fmt.Errorf("source %s timeout after %ds", name, perTimeoutSec)
			}
			dur := time.Since(t0)
			done := SourceEvent{Source: name, Phase: "done", Count: len(assets), Dur: dur}
			if err != nil {
				done.Err = err.Error()
			}
			emit(done)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("source %s: %w", name, err))
			}
			allAssets = append(allAssets, assets...)
		}()
	}
	wg.Wait()

	if len(errs) > 0 {
		// 用 errors.Join 聚合，调用方可 errors.As/Is 检索
		return allAssets, joinErrs(errs)
	}
	return allAssets, nil
}

// joinErrs 简易 errors.Join 兼容（避免要求 Go 1.20+ 没意义的 import 切换）
func joinErrs(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return fmt.Errorf("%d source errors: %s", len(errs), strings.Join(msgs, "; "))
}

// accepts 检查数据源是否接受该目标类型
func (r *Runner) accepts(src source.Source, target string) bool {
	for _, typ := range src.Accepts() {
		switch typ {
		case "domain":
			if isDomain(target) {
				return true
			}
		case "company":
			if isCompany(target) {
				return true
			}
		case "ip":
			if isIP(target) {
				return true
			}
		case "url":
			if isURL(target) {
				return true
			}
		case "email":
			if isEmail(target) {
				return true
			}
		case "asn":
			if isASN(target) {
				return true
			}
		case "icp":
			if isICP(target) {
				return true
			}
		case "keyword":
			// keyword 兜底：任何非 IP/URL 字符串都接受（域名/公司名/纯字符串都行）
			if !isIP(target) && !isURL(target) && target != "" {
				return true
			}
		}
	}
	return false
}

// 目标类型判断
func isURL(target string) bool {
	if !strings.Contains(target, "://") {
		return false
	}
	u, err := url.Parse(target)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func isIP(target string) bool {
	return net.ParseIP(target) != nil
}

func isDomain(target string) bool {
	if target == "" || isIP(target) || isURL(target) || isEmail(target) {
		return false
	}
	// 含点且不含中文与空格的 ASCII 串视为域名
	if !strings.Contains(target, ".") {
		return false
	}
	for _, r := range target {
		if r > unicode.MaxASCII || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// isEmail 判断 email 格式（粗略：含且仅含一个 @ + 后续合法域名）
func isEmail(target string) bool {
	if !strings.Contains(target, "@") {
		return false
	}
	parts := strings.Split(target, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return strings.Contains(parts[1], ".")
}

// isASN 判断 ASN 格式："AS15169" 或 "15169"
func isASN(target string) bool {
	t := strings.TrimSpace(strings.ToUpper(target))
	t = strings.TrimPrefix(t, "AS")
	if t == "" {
		return false
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isICP 判断 ICP 备案号格式：含 "ICP" / "备案" / "京...号"
func isICP(target string) bool {
	upper := strings.ToUpper(target)
	return strings.Contains(upper, "ICP") ||
		strings.Contains(target, "备案") ||
		(strings.Contains(target, "京") && strings.Contains(target, "号"))
}

func isCompany(target string) bool {
	// 含中文，或包含公司后缀关键词，则视为公司名
	for _, r := range target {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
	}
	suffixes := []string{"公司", "集团", "股份", "有限", "Inc", "Corp", "Ltd", "LLC", "GmbH"}
	for _, s := range suffixes {
		if strings.Contains(target, s) {
			return true
		}
	}
	return false
}
