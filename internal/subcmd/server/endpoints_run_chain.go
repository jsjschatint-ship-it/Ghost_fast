// Post-passive auto active chain for /api/run with Active=true.
//
// When the user ticks 主动模式 on the top form, after the passive runner finishes
// we mine the collected assets for hosts / roots / IPs / URLs and fan out
// into the seven active probes. Stage order is tuned for maximum recall —
// "完整 > 速度" — so we never drop pivots for speed; the cost is bounded by
// the run's overall ctx deadline only.
//
//	subbrute  → enumerate per root
//	portscan  → top1000 by default, 'all' (full 65535) for ≤2 IPs;
//	            banner is promoted into Asset.Service / Asset.Port
//	httpx-1   → every host + every URL + every IP:port from portscan
//	tlscert   → live TLS + favicon, then mine SANs for new hostnames
//	httpx-2   → SAN-only second pass so siblings get into the alive set
//	webmeta   → all alive URLs (primary + SAN pass merged)
//	dnsadv    → AXFR + takeover per root, takeover gets accumulated subs
//	jscrawl   → all alive URLs as seeds
//
// Every stage emits start/done events into entry.Events so the dashboard's
// existing progress UI and SSE stream keep working without changes.
package server

import (
	"context"
	"fmt"
	"log"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wgpsec/ENScan/pkg/active/dnsadv"
	"github.com/wgpsec/ENScan/pkg/active/httpx"
	"github.com/wgpsec/ENScan/pkg/active/jscrawl"
	"github.com/wgpsec/ENScan/pkg/active/portscan"
	"github.com/wgpsec/ENScan/pkg/active/subdomain"
	"github.com/wgpsec/ENScan/pkg/active/tlscert"
	"github.com/wgpsec/ENScan/pkg/active/webmeta"
	"github.com/wgpsec/ENScan/pkg/core"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/runner"
)

// chainPivots is what we mine out of (passive assets + original targets) to
// feed every downstream stage.
type chainPivots struct {
	Hosts map[string]struct{} // bare FQDNs (no port)
	Roots map[string]struct{} // eTLD+1
	IPs   map[string]struct{} // IPv4/v6 literals
	URLs  map[string]struct{} // full URLs with scheme
}

// Chain caps — sized for maximum recall on realistic enterprise targets.
// We let runs take longer but never silently drop pivots. The overall run
// budget still caps things (context deadline propagates).
const (
	chainMaxRootsForBrute     = 50    // subbrute per root cap
	chainMaxIPsForScan        = 65536 // portscan IPs cap (one /16 worth)
	chainMaxHTTPXInputs       = 100000
	chainMaxTLSTargets        = 5000
	chainMaxJSSeeds           = 500
	chainMaxRootsForDNS       = 200
	chainMaxSANReprobe        = 5000 // SAN-new hosts re-fed into httpx pass 2
	adaptivePortPresetTiny    = 2    // ≤ this many IPs → scan full 65535
	adaptivePortPresetDefault = "top1000"
)

// extractChainPivots mines hosts / roots / IPs / URLs from raw passive results
// plus the original user-supplied targets. All IP-literal hosts are sent to
// the IP bucket so portscan picks them up.
func extractChainPivots(targets []string, assets []*models.Asset) chainPivots {
	pv := chainPivots{
		Hosts: map[string]struct{}{},
		Roots: map[string]struct{}{},
		IPs:   map[string]struct{}{},
		URLs:  map[string]struct{}{},
	}
	addHost := func(raw string) {
		h := strings.ToLower(strings.TrimSpace(raw))
		if h == "" {
			return
		}
		// Strip optional :port tail (skip for IPv6-in-brackets).
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
			h = h[:i]
		}
		h = strings.Trim(h, ".")
		// Wildcard / leading-dot artefacts from cert SANs.
		h = strings.TrimPrefix(h, "*.")
		if h == "" {
			return
		}
		if isIPLiteral(h) {
			pv.IPs[h] = struct{}{}
			return
		}
		if !strings.Contains(h, ".") {
			return
		}
		pv.Hosts[h] = struct{}{}
		if root := core.RootDomain(h); root != "" {
			pv.Roots[root] = struct{}{}
		}
	}
	for _, t := range targets {
		addHost(t)
	}
	for _, a := range assets {
		if a == nil {
			continue
		}
		addHost(a.Host)
		addHost(a.Domain)
		if a.IP != "" && isIPLiteral(a.IP) {
			pv.IPs[a.IP] = struct{}{}
		}
		if a.URL != "" {
			if u, err := neturl.Parse(a.URL); err == nil && u.Host != "" {
				addHost(u.Hostname())
				pv.URLs[a.URL] = struct{}{}
			}
		}
		// Cert SAN list from passive engines (fofa/quake/etc.) is already a
		// goldmine — extract any siblings we don't have yet.
		for _, cd := range a.CertDomains {
			addHost(cd)
		}
	}
	return pv
}

// planChainSteps returns the upfront step count the progress bar should expect
// once the active chain kicks in. Matches the start/done pairs emitted by
// runAutoActiveChain.
func planChainSteps(pv chainPivots) int {
	steps := 0
	bruteRoots := len(pv.Roots)
	if bruteRoots > chainMaxRootsForBrute {
		bruteRoots = chainMaxRootsForBrute
	}
	steps += bruteRoots // subbrute per root
	steps++             // portscan (always emits start/done, even with 0 IPs)
	steps++             // httpx pass 1
	steps++             // tlscert (always emits)
	steps++             // httpx pass 2 (SAN reprobe)
	steps++             // webmeta
	dnsRoots := len(pv.Roots)
	if dnsRoots > chainMaxRootsForDNS {
		dnsRoots = chainMaxRootsForDNS
	}
	steps += dnsRoots // dnsadv per root
	steps++           // jscrawl batch
	return steps
}

// adaptivePortPreset picks a port preset by target population. ≤2 IPs (typical
// when the user pasted one target) scans the entire TCP range; otherwise we
// fall back to top1000 to keep bulk scans bounded while still covering the
// long tail of K8s / DB / mgmt ports beyond nmap top-100.
func adaptivePortPreset(ipCount int) string {
	if ipCount <= adaptivePortPresetTiny {
		return "all"
	}
	return adaptivePortPresetDefault
}

// runAutoActiveChain runs the full chain on the supplied pivots. Emits
// progress events into entry, returns the newly discovered assets (caller
// merges them into rawAll before dedup/save).
func (s *server) runAutoActiveChain(ctx context.Context, entry *runEntry, pv chainPivots, conc, timeoutSec int) []*models.Asset {
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	var extra []*models.Asset
	emit := func(name, target, phase string, count int, dur time.Duration, errMsg string) {
		entry.appendEvent(runner.SourceEvent{
			Source: name + "[" + target + "]", Phase: phase,
			Count: count, Dur: dur, Err: errMsg,
		})
	}
	setCur := func(s string) {
		entry.mu.Lock()
		entry.CurrentTarget = s
		entry.mu.Unlock()
	}

	// Live set of hosts that grows across stages. portscan, subbrute, and the
	// SAN-extraction stage all push new entries into here. Anything in
	// `hosts` ends up probed by some httpx pass.
	hosts := map[string]struct{}{}
	for h := range pv.Hosts {
		hosts[h] = struct{}{}
	}

	// ---- 1) subbrute per root (always run; never skipped for speed) ----
	roots := setToSlice(pv.Roots)
	if len(roots) > chainMaxRootsForBrute {
		log.Printf("[chain] subbrute capped at %d/%d roots (raise chainMaxRootsForBrute if needed)", chainMaxRootsForBrute, len(roots))
		roots = roots[:chainMaxRootsForBrute]
	}
	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		setCur("subbrute:" + root)
		emit("subbrute", root, "start", 0, 0, "")
		t0 := time.Now()
		brute := subdomain.New(subdomain.Config{
			Concurrency: clampConc(conc, 50, 500),
			Timeout:     time.Duration(maxIntS(timeoutSec, 30)) * time.Second,
			IncludeRoot: true,
		})
		res, berr := brute.Run(ctx, root, nil)
		errStr := ""
		if berr != nil {
			errStr = berr.Error()
		}
		emit("subbrute", root, "done", len(res), time.Since(t0), errStr)
		for _, sub := range res {
			if sub == nil {
				continue
			}
			a := sub.ToAsset()
			a.Tags = append(a.Tags, "auto-active")
			extra = append(extra, a)
			if sub.Name != "" {
				hosts[strings.ToLower(sub.Name)] = struct{}{}
			}
		}
	}

	// ---- 2) portscan on collected IPs (always emits start/done) ----
	// Adaptive preset: ≤2 IPs → "all" (full 65535), otherwise "top1000".
	{
		setCur("portscan")
		emit("portscan", "batch", "start", 0, 0, "")
		t0 := time.Now()
		open := 0
		errStr := ""
		if len(pv.IPs) > 0 && ctx.Err() == nil {
			ips := setToSlice(pv.IPs)
			if len(ips) > chainMaxIPsForScan {
				log.Printf("[chain] portscan capped at %d/%d IPs", chainMaxIPsForScan, len(ips))
				ips = ips[:chainMaxIPsForScan]
			}
			preset := adaptivePortPreset(len(ips))
			sc := portscan.New(portscan.Config{
				PortPreset:     preset,
				Concurrency:    clampConc(conc, 200, 2000),
				Timeout:        1500 * time.Millisecond,
				RetryTimeout:   1500 * time.Millisecond,
				GrabBanner:     true,
				BannerTimeout:  2 * time.Second,
				BannerMaxBytes: 512,
			})
			res, perr := sc.Run(ctx, ips, nil)
			if perr != nil {
				errStr = perr.Error()
			}
			open = len(res)
			for _, r := range res {
				if r == nil {
					continue
				}
				a := r.ToAsset()
				a.Port = r.Port
				a.Service = r.Service
				a.Tags = append(a.Tags, "auto-active")
				extra = append(extra, a)
				host := r.IP
				if host == "" {
					host = r.Target
				}
				hosts[fmt.Sprintf("%s:%d", host, r.Port)] = struct{}{}
			}
		}
		emit("portscan", "batch", "done", open, time.Since(t0), errStr)
	}

	// ---- 3) httpx pass 1: every host + every URL + every portscan IP:port ----
	// We do NOT filter by "web-looking" ports — completeness over speed.
	var aliveURLs []string
	{
		setCur("httpx")
		emit("httpx", "batch", "start", 0, 0, "")
		t0 := time.Now()
		inputSet := map[string]struct{}{}
		for h := range hosts {
			inputSet[h] = struct{}{}
		}
		for u := range pv.URLs {
			inputSet[u] = struct{}{}
		}
		inputs := setToSlice(inputSet)
		if len(inputs) > chainMaxHTTPXInputs {
			log.Printf("[chain] httpx inputs capped at %d/%d", chainMaxHTTPXInputs, len(inputs))
			inputs = inputs[:chainMaxHTTPXInputs]
		}
		alive := 0
		if len(inputs) > 0 && ctx.Err() == nil {
			pr := httpx.New(httpx.Config{
				Concurrency:     clampConc(conc, 50, 500),
				Timeout:         8 * time.Second,
				FollowRedirects: true,
				SchemesAuto:     true,
				FetchFavicon:    true,
				ResolveDNS:      true,
			})
			results := pr.Run(ctx, inputs, nil)
			for _, hr := range results {
				if hr == nil {
					continue
				}
				if hr.Status > 0 {
					alive++
					a := hr.ToAsset()
					a.Tags = append(a.Tags, "auto-active")
					extra = append(extra, a)
					u := hr.FinalURL
					if u == "" {
						u = hr.URL
					}
					if u != "" {
						aliveURLs = append(aliveURLs, u)
					}
				}
			}
		}
		emit("httpx", "batch", "done", alive, time.Since(t0), "")
	}

	// ---- 4) tlscert (live TLS + favicon) + mine SANs (always emits) ----
	sanNew := map[string]struct{}{} // SAN-discovered hosts not in `hosts` yet
	{
		setCur("tlscert")
		emit("tlscert", "batch", "start", 0, 0, "")
		t0 := time.Now()
		if len(hosts) == 0 || ctx.Err() != nil {
			emit("tlscert", "batch", "done", 0, time.Since(t0), "")
			goto afterTLS
		}
		tlsTargets := setToSlice(hosts)
		if len(tlsTargets) > chainMaxTLSTargets {
			log.Printf("[chain] tlscert capped at %d/%d hosts", chainMaxTLSTargets, len(tlsTargets))
			tlsTargets = tlsTargets[:chainMaxTLSTargets]
		}
		cr := tlscert.Run(ctx, tlscert.Config{
			Targets:     tlsTargets,
			DoLiveTLS:   true,
			DoFavicon:   true,
			DoCrtSh:     false, // crt.sh is heavily rate-limited; we lean on cert SANs we hit live + CT from passive sources
			Concurrency: clampConc(conc, 16, 64),
			TLSTimeout:  6 * time.Second,
			HTTPTimeout: 10 * time.Second,
		})
		emit("tlscert", "batch", "done",
			cr.Stats.CertsOK+cr.Stats.FaviconsHashed, time.Since(t0), "")
		for _, c := range cr.Certs {
			if c == nil || c.Err != "" || c.SHA256 == "" {
				continue
			}
			a := models.NewAsset()
			a.Host = c.Host
			a.Domain = c.Host
			if c.Port != "" {
				if p, err := strconv.Atoi(c.Port); err == nil {
					a.Port = p
				}
			}
			a.Protocol = "https"
			a.CertSubject = c.Subject
			a.CertIssuer = c.Issuer
			a.CertDomains = c.SANs
			a.Source = "tlscert"
			a.Tags = append(a.Tags, "auto-active")
			a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
			a.Raw = map[string]string{"cert_sha256": c.SHA256, "cert_cn": c.SubjectCN}
			extra = append(extra, a)
			// Pull SAN siblings into the chain's discovery set.
			for _, san := range c.SANs {
				san = strings.ToLower(strings.TrimSpace(san))
				san = strings.TrimPrefix(san, "*.")
				san = strings.Trim(san, ".")
				if san == "" || !strings.Contains(san, ".") {
					continue
				}
				if _, already := hosts[san]; already {
					continue
				}
				if _, already := sanNew[san]; already {
					continue
				}
				sanNew[san] = struct{}{}
			}
		}
		for _, fv := range cr.Favicons {
			if fv == nil || fv.Err != "" || fv.MMH3 == 0 {
				continue
			}
			a := models.NewAsset()
			a.URL = fv.URL
			if pu, err := neturl.Parse(fv.URL); err == nil {
				a.Host = pu.Hostname()
				a.Domain = pu.Hostname()
				a.Protocol = pu.Scheme
			}
			a.FaviconHash = strconv.FormatInt(int64(fv.MMH3), 10)
			a.Source = "tlscert_favicon"
			a.Tags = append(a.Tags, "auto-active", "favicon")
			a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
			extra = append(extra, a)
		}
	}
afterTLS:

	// ---- 5) httpx pass 2: SAN-new hosts (so SAN siblings reach webmeta/jscrawl) ----
	// This recovers admin aliases that passive + subbrute missed but the cert
	// SAN list revealed.
	if len(sanNew) > 0 && ctx.Err() == nil {
		setCur("httpx-san")
		emit("httpx_san", "batch", "start", 0, 0, "")
		t0 := time.Now()
		inputs := setToSlice(sanNew)
		if len(inputs) > chainMaxSANReprobe {
			log.Printf("[chain] httpx_san capped at %d/%d SANs", chainMaxSANReprobe, len(inputs))
			inputs = inputs[:chainMaxSANReprobe]
		}
		pr := httpx.New(httpx.Config{
			Concurrency:     clampConc(conc, 50, 500),
			Timeout:         8 * time.Second,
			FollowRedirects: true,
			SchemesAuto:     true,
			FetchFavicon:    true,
			ResolveDNS:      true,
		})
		results := pr.Run(ctx, inputs, nil)
		alive := 0
		for _, hr := range results {
			if hr == nil {
				continue
			}
			// Always promote SAN-new hosts as assets, even when dead, so the
			// user sees the certificate-revealed siblings.
			a := hr.ToAsset()
			a.Tags = append(a.Tags, "auto-active", "san")
			extra = append(extra, a)
			if hr.Status > 0 {
				alive++
				u := hr.FinalURL
				if u == "" {
					u = hr.URL
				}
				if u != "" {
					aliveURLs = append(aliveURLs, u)
				}
			}
		}
		emit("httpx_san", "batch", "done", alive, time.Since(t0), "")
		// Merge SAN-new hosts into `hosts` for later stages (dnsadv takeover).
		for s := range sanNew {
			hosts[s] = struct{}{}
		}
	} else {
		// Still emit start/done so progress bar accounting matches the plan.
		emit("httpx_san", "batch", "start", 0, 0, "")
		emit("httpx_san", "batch", "done", 0, 0, "")
	}

	// ---- 6) webmeta on the full alive set ----
	{
		setCur("webmeta")
		emit("webmeta", "batch", "start", 0, 0, "")
		t0 := time.Now()
		ok := 0
		if len(aliveURLs) > 0 && ctx.Err() == nil {
			wm := webmeta.Collect(ctx, webmeta.Config{
				Targets:         aliveURLs,
				Concurrency:     clampConc(conc, 8, 32),
				Timeout:         8 * time.Second,
				FetchRobots:     true,
				FetchSitemap:    true,
				FollowRedirects: true,
				TryHTTPFallback: true,
				SkipTLSVerify:   true,
			})
			ok = wm.Stats.OK
			for _, rep := range wm.Reports {
				if rep == nil {
					continue
				}
				a := models.NewAsset()
				a.URL = rep.FinalURL
				if a.URL == "" {
					a.URL = rep.URL
				}
				if pu, err := neturl.Parse(a.URL); err == nil {
					a.Host = pu.Hostname()
					a.Domain = pu.Hostname()
					a.Protocol = pu.Scheme
				}
				a.Title = rep.Title
				a.Server = rep.Server
				if len(rep.ICPNumbers) > 0 {
					a.ICP = rep.ICPNumbers[0]
				}
				a.Source = "webmeta"
				a.Tags = append(a.Tags, "auto-active")
				a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
				extra = append(extra, a)
			}
		}
		emit("webmeta", "batch", "done", ok, time.Since(t0), "")
	}

	// ---- 7) dnsadv per root (AXFR + takeover, with full sub list) ----
	dnsRoots := setToSlice(pv.Roots)
	if len(dnsRoots) > chainMaxRootsForDNS {
		log.Printf("[chain] dnsadv capped at %d/%d roots", chainMaxRootsForDNS, len(dnsRoots))
		dnsRoots = dnsRoots[:chainMaxRootsForDNS]
	}
	for _, root := range dnsRoots {
		if ctx.Err() != nil {
			break
		}
		setCur("dnsadv:" + root)
		emit("dnsadv", root, "start", 0, 0, "")
		t0 := time.Now()
		var subsForRoot []string
		dotRoot := "." + root
		for h := range hosts {
			// Skip IP:port combos and non-bare hostnames; takeover wants FQDNs.
			if strings.Contains(h, ":") || isIPLiteral(h) {
				continue
			}
			if h == root || strings.HasSuffix(h, dotRoot) {
				subsForRoot = append(subsForRoot, h)
			}
		}
		scanner := dnsadv.New(dnsadv.Config{
			Mode:                "both",
			AXFRTimeout:         8 * time.Second,
			TakeoverConcurrency: clampConc(conc, 30, 100),
			TakeoverHTTPTimeout: 6 * time.Second,
		})
		result := scanner.Scan(ctx, root, subsForRoot)
		axfrSuccess := 0
		for _, ax := range result.AXFR {
			if ax != nil && ax.Success {
				axfrSuccess++
				// Surface AXFR records as assets so the operator can see the
				// leaked zone hosts straight in the table.
				for _, rec := range ax.Records {
					a := models.NewAsset()
					a.Domain = root
					a.Host = root
					a.Source = "dnsadv_axfr"
					a.Tags = append(a.Tags, "auto-active", "axfr")
					a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
					a.Raw = map[string]string{"axfr_record": rec, "ns": ax.NameServer}
					extra = append(extra, a)
				}
			}
		}
		takeovers := 0
		for _, tr := range result.Takeovers {
			if tr == nil {
				continue
			}
			if a := tr.ToAsset(); a != nil {
				a.Tags = append(a.Tags, "auto-active")
				extra = append(extra, a)
				takeovers++
			}
		}
		emit("dnsadv", root, "done", axfrSuccess+takeovers, time.Since(t0), "")
	}

	// ---- 8) jscrawl on alive URLs ----
	{
		setCur("jscrawl")
		emit("jscrawl", "batch", "start", 0, 0, "")
		t0 := time.Now()
		found := 0
		if len(aliveURLs) > 0 && ctx.Err() == nil {
			seeds := uniqStringList(aliveURLs)
			if len(seeds) > chainMaxJSSeeds {
				log.Printf("[chain] jscrawl seeds capped at %d/%d URLs", chainMaxJSSeeds, len(seeds))
				seeds = seeds[:chainMaxJSSeeds]
			}
			// 在主动链路里默认开启 katana-class 三件套：
			//   KnownFiles      = robots.txt / sitemap.xml 自动种子收割
			//   FetchSourceMaps = .js.map -> 还原原始源码 + 扫密钥
			//   ExtractForms    = <form> 抽取登录入口和参数
			// 这些都是低成本、高情报密度的扩展，符合"宁慢勿丢"的链路哲学。
			cr := jscrawl.Crawl(ctx, jscrawl.Config{
				Seeds:           seeds,
				MaxDepth:        2,
				MaxPages:        500,
				Concurrency:     clampConc(conc, 8, 32),
				Timeout:         12 * time.Second,
				SameHostOnly:    true,
				FollowRedirects: true,
				KnownFiles:      true,
				FetchSourceMaps: true,
				ExtractForms:    true,
				MaxRetries:      1,
			})
			for _, ep := range cr.Endpoints {
				if ep == "" {
					continue
				}
				a := models.NewAsset()
				a.URL = ep
				a.Source = "jscrawl_endpoint"
				a.Tags = append(a.Tags, "auto-active", "endpoint")
				a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
				extra = append(extra, a)
				found++
			}
			for _, sec := range cr.Secrets {
				if sec == nil {
					continue
				}
				a := models.NewAsset()
				a.Source = "jscrawl_secret"
				a.Tags = append(a.Tags, "auto-active", "secret", sec.Rule)
				a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
				a.Raw = map[string]string{
					"rule":     sec.Rule,
					"value":    sec.Value,
					"severity": sec.Severity,
				}
				extra = append(extra, a)
				found++
			}
			// 把 form 也作为资产沉淀：每个 form 转一条 URL 资产，附带 method/inputs 元数据。
			// 用途：登录端点发现、参数挖掘种子。
			for _, f := range cr.Forms {
				if f == nil || f.Action == "" {
					continue
				}
				a := models.NewAsset()
				a.URL = f.Action
				a.Source = "jscrawl_form"
				a.Tags = append(a.Tags, "auto-active", "form", strings.ToLower(f.Method))
				a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
				names := make([]string, 0, len(f.Inputs))
				for _, in := range f.Inputs {
					if in != nil && in.Name != "" {
						names = append(names, in.Name)
					}
				}
				a.Raw = map[string]string{
					"method":  f.Method,
					"page":    f.URL,
					"inputs":  strings.Join(names, ","),
					"enctype": f.EncType,
				}
				extra = append(extra, a)
				found++
			}
			// WebSocket endpoints 单独沉淀（区分于 HTTP endpoints）。
			for _, ws := range cr.WebSockets {
				if ws == "" {
					continue
				}
				a := models.NewAsset()
				a.URL = ws
				a.Source = "jscrawl_ws"
				a.Tags = append(a.Tags, "auto-active", "websocket")
				a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
				extra = append(extra, a)
				found++
			}
		}
		emit("jscrawl", "batch", "done", found, time.Since(t0), "")
	}

	log.Printf("[run] auto-active chain finished, +%d assets (roots=%d ips=%d hosts=%d urls=%d alive=%d san_new=%d)",
		len(extra), len(pv.Roots), len(pv.IPs), len(pv.Hosts), len(pv.URLs), len(aliveURLs), len(sanNew))
	return extra
}

// uniqStringList returns a stable deduped copy of in.
func uniqStringList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
