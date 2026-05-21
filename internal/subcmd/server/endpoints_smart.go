// Smart import + automatic recon orchestration.
//
// POST /api/import_smart  (multipart/form-data)
//
//	file        — required. .xlsx or .txt/.csv (one target per line/cell).
//	active      — "1"/"true" to enable active modules (subbrute / portscan / httpx / webmeta).
//	concurrency — int, runner concurrency.
//	timeout_sec — int, runner per-target timeout.
//	proxy       — string, optional.
//
// The handler classifies every target into one of {ip, ipcidr, url, domain, subdomain, company},
// then schedules a single async run that reuses the existing runEntry / progress / result
// pipeline. Active stages (subbrute → httpx → webmeta, portscan → httpx) only execute when
// `active=1`; otherwise we just run the passive sources via runner.Runner.
package server

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/wgpsec/ENScan/pkg/active/httpx"
	"github.com/wgpsec/ENScan/pkg/active/portscan"
	"github.com/wgpsec/ENScan/pkg/active/subdomain"
	"github.com/wgpsec/ENScan/pkg/active/webmeta"
	"github.com/wgpsec/ENScan/pkg/core"
	"github.com/wgpsec/ENScan/pkg/importers"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/runner"
)

// smartTargetClass enumerates the categories we orchestrate on.
type smartTargetClass string

const (
	classIP      smartTargetClass = "ip"
	classCIDR    smartTargetClass = "cidr"
	classURL     smartTargetClass = "url"
	classRoot    smartTargetClass = "domain" // eTLD+1
	classSub     smartTargetClass = "subdomain"
	classCorp    smartTargetClass = "company"
	classIPRange smartTargetClass = "ip_range"
	classUnkown  smartTargetClass = "unknown"
)

// parseIPRange parses "A.B.C.D-E.F.G.H" or shorthand "A.B.C.D-N" (N = last octet
// in the same /24) and returns the inclusive list of IPv4 addresses. It caps
// the expansion at maxIPRangeExpand to keep planning bounded; oversized ranges
// return nil and should be reported as unknown by the caller.
func parseIPRange(s string) []string {
	s = strings.TrimSpace(s)
	// Strip whitespace around the dash (some exports add spaces).
	s = strings.ReplaceAll(s, " ", "")
	idx := strings.Index(s, "-")
	if idx <= 0 || idx == len(s)-1 {
		return nil
	}
	left := s[:idx]
	right := s[idx+1:]
	startIP := net.ParseIP(left).To4()
	if startIP == nil {
		return nil
	}
	var endIP net.IP
	if rightIP := net.ParseIP(right); rightIP != nil {
		endIP = rightIP.To4()
	} else if onlyDigits(right) {
		// Shorthand "A.B.C.D-N": replace last octet.
		parts := strings.Split(left, ".")
		if len(parts) != 4 {
			return nil
		}
		parts[3] = right
		endIP = net.ParseIP(strings.Join(parts, ".")).To4()
	}
	if endIP == nil {
		return nil
	}
	startN := ipv4ToUint32(startIP)
	endN := ipv4ToUint32(endIP)
	if endN < startN {
		startN, endN = endN, startN
	}
	if endN-startN+1 > maxIPRangeExpand {
		return nil
	}
	out := make([]string, 0, endN-startN+1)
	for v := startN; v <= endN; v++ {
		out = append(out, uint32ToIPv4(v).String())
		if v == endN { // guard against uint32 wrap (endN == math.MaxUint32)
			break
		}
	}
	return out
}

const maxIPRangeExpand uint32 = 4096

func onlyDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIPv4(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).To4()
}

// smartBuckets groups raw file inputs by classification.
type smartBuckets struct {
	IPs        []string // single IPs
	CIDRs      []string
	URLs       []string
	Roots      []string // already-root domains
	Subs       []string // hostnames whose eTLD+1 differs from themselves
	Companies  []string
	Unknown    []string
	OrderTotal int // total raw count post-dedup (for stats)
}

// classifyOne categorises a single trimmed target string.
func classifyOne(raw string) (smartTargetClass, string) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return classUnkown, ""
	}
	// IP range: "A.B.C.D-E.F.G.H" or shorthand "A.B.C.D-N" (last octet)
	if ips := parseIPRange(t); len(ips) > 0 {
		// Returned as classIPRange — classifyAll expands it into the IPs bucket.
		return classIPRange, t
	}
	// CIDR
	if _, _, err := net.ParseCIDR(t); err == nil {
		return classCIDR, t
	}
	// IP
	if net.ParseIP(t) != nil {
		return classIP, t
	}
	// URL with scheme
	if strings.Contains(t, "://") {
		if u, err := neturl.Parse(t); err == nil && u.Host != "" {
			return classURL, t
		}
	}
	// Bare host:port → treat as URL
	if strings.Contains(t, ":") && !strings.Contains(t, " ") {
		if h, _, err := net.SplitHostPort(t); err == nil {
			if net.ParseIP(h) != nil {
				return classURL, "http://" + t
			}
			if isLikelyDomain(h) {
				return classURL, "http://" + t
			}
		}
	}
	// CJK / spaces / company suffix → company name
	if hasCJK(t) || hasCompanyKeyword(t) {
		return classCorp, t
	}
	// Looks like a domain
	if isLikelyDomain(t) {
		host := strings.ToLower(strings.TrimSuffix(t, "."))
		root := core.RootDomain(host)
		if root != "" && root == host {
			return classRoot, host
		}
		return classSub, host
	}
	return classUnkown, t
}

func isLikelyDomain(s string) bool {
	if s == "" || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	last := parts[len(parts)-1]
	if len(last) < 2 {
		return false
	}
	return true
}

func hasCJK(s string) bool {
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
	}
	return false
}

func hasCompanyKeyword(s string) bool {
	lower := strings.ToLower(s)
	keywords := []string{"co., ltd", "co.,ltd", "inc.", "inc ", "llc", "ltd.", "corp", "company", "group"}
	for _, k := range keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// readSmartFile dispatches by extension and returns a flat list of raw target strings.
// Supports .xlsx (any sheet, every non-empty cell), .csv, .txt (one per line).
func readSmartFile(path string) ([]string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".xlsx":
		rows, err := importers.ReadXLSXRows(path)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(rows)*2)
		for _, r := range rows {
			for _, v := range r {
				v = strings.TrimSpace(v)
				if v != "" {
					out = append(out, v)
				}
			}
		}
		return out, nil
	case ".csv":
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		rd := csv.NewReader(f)
		rd.FieldsPerRecord = -1
		rd.LazyQuotes = true
		out := []string{}
		for {
			rec, err := rd.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			for _, v := range rec {
				v = strings.TrimSpace(v)
				if v != "" {
					out = append(out, v)
				}
			}
		}
		return out, nil
	default:
		// .txt and anything else: treat as line-delimited.
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		lines := strings.FieldsFunc(string(b), func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';' || r == '\t'
		})
		out := make([]string, 0, len(lines))
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" {
				out = append(out, l)
			}
		}
		return out, nil
	}
}

// classifyAll dedupes and buckets every raw input string.
func classifyAll(raws []string) smartBuckets {
	seen := map[string]struct{}{}
	var bk smartBuckets
	for _, raw := range raws {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		key := strings.ToLower(t)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		bk.OrderTotal++
		cls, norm := classifyOne(t)
		switch cls {
		case classIP:
			bk.IPs = append(bk.IPs, norm)
		case classIPRange:
			// Expand "A-B" into individual IPs; record under IPs bucket so the
			// portscan / httpx stages see them as ordinary single hosts. Falls
			// back to CIDR (unlikely) or unknown if expansion failed.
			expanded := parseIPRange(norm)
			if len(expanded) == 0 {
				bk.Unknown = append(bk.Unknown, norm)
			} else {
				for _, ip := range expanded {
					ipKey := strings.ToLower(ip)
					if _, dup := seen[ipKey]; dup {
						continue
					}
					seen[ipKey] = struct{}{}
					bk.IPs = append(bk.IPs, ip)
				}
			}
		case classCIDR:
			bk.CIDRs = append(bk.CIDRs, norm)
		case classURL:
			bk.URLs = append(bk.URLs, norm)
		case classRoot:
			bk.Roots = append(bk.Roots, norm)
		case classSub:
			bk.Subs = append(bk.Subs, norm)
		case classCorp:
			bk.Companies = append(bk.Companies, norm)
		default:
			bk.Unknown = append(bk.Unknown, norm)
		}
	}
	sort.Strings(bk.IPs)
	sort.Strings(bk.CIDRs)
	sort.Strings(bk.URLs)
	sort.Strings(bk.Roots)
	sort.Strings(bk.Subs)
	sort.Strings(bk.Companies)
	return bk
}

// handleImportSmart parses the uploaded file, classifies its targets, and asynchronously
// orchestrates passive + active reconnaissance.
func (s *server) handleImportSmart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "method not allowed")
		return
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, 400, "parse multipart: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "missing file: "+err.Error())
		return
	}
	defer file.Close()

	tmp, err := os.CreateTemp("", "smart-*"+filepath.Ext(header.Filename))
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

	raws, err := readSmartFile(tmp.Name())
	if err != nil {
		writeError(w, 400, "read file: "+err.Error())
		return
	}
	bk := classifyAll(raws)
	if bk.OrderTotal == 0 {
		writeError(w, 400, "no targets found in file")
		return
	}

	active := boolForm(r.FormValue("active"))
	proxy := r.FormValue("proxy")
	conc := atoiForm(r.FormValue("concurrency"))
	timeoutSec := atoiForm(r.FormValue("timeout_sec"))
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	srcTimeout := atoiForm(r.FormValue("src_timeout"))
	perSrcMax := atoiForm(r.FormValue("max_assets"))

	// Passive runner: empty EnabledSources lets buildRunnerConfig fall back to the
	// server's configured default list. We will only call runner.Run for company /
	// root-domain / IP / URL targets where passive sources actually contribute.
	rcfg := s.buildRunnerConfig(nil, timeoutSec)
	if conc > 0 {
		rcfg.MaxConcurrency = conc
	}
	if proxy != "" {
		rcfg.Proxy = proxy
	}
	rcfg.Active = active
	rcfg.PerSourceMax = perSrcMax
	rcfg.PerSourceTimeout = srcTimeout

	// Single runEntry covers the whole orchestration; UI polls /api/progress as usual.
	displayTarget := fmt.Sprintf("smart:%s (ip=%d cidr=%d url=%d root=%d sub=%d corp=%d)",
		header.Filename, len(bk.IPs), len(bk.CIDRs), len(bk.URLs),
		len(bk.Roots), len(bk.Subs), len(bk.Companies))

	plannedTotal := smartPlannedSteps(bk, active)
	entry := &runEntry{
		ID:          randomID(),
		Target:      displayTarget,
		Sources:     []string{"smart_import"},
		When:        time.Now().UTC(),
		Status:      "running",
		StartedAt:   time.Now().UTC(),
		Total:       plannedTotal,
		TargetTotal: bk.OrderTotal,
		TargetIdx:   0,
	}
	s.store.put(entry)

	rcfg.OnEvent = func(ev runner.SourceEvent) {
		entry.appendEvent(ev)
	}

	go runSmartOrchestration(s, entry, bk, rcfg, active, conc, timeoutSec)

	writeJSON(w, 202, map[string]any{
		"id":     entry.ID,
		"target": entry.Target,
		"total":  entry.Total,
		"status": entry.Status,
		"buckets": map[string]int{
			"ips":       len(bk.IPs),
			"cidrs":     len(bk.CIDRs),
			"urls":      len(bk.URLs),
			"roots":     len(bk.Roots),
			"subs":      len(bk.Subs),
			"companies": len(bk.Companies),
			"unknown":   len(bk.Unknown),
		},
	})
}

// smartPlannedSteps gives a coarse total used by the dashboard progress bar.
// Not exact: every passive call counts as N enabled sources, and active stages
// each count as 1 step. Matches what `OnEvent` will emit.
func smartPlannedSteps(bk smartBuckets, active bool) int {
	steps := 0
	// passive: each company / root / ip / url that we feed to runner.Runner emits
	// approximately one start/done pair per accepting source. Without inspecting
	// `accepts`, we treat every passive target as one progress unit.
	steps += len(bk.Companies)
	steps += len(bk.Roots)
	steps += len(bk.Subs)
	steps += len(bk.URLs)
	steps += len(bk.IPs)
	if active {
		// subbrute per root + httpx batch + webmeta batch + portscan batch
		steps += len(bk.Roots)
		steps += 3
	}
	if steps == 0 {
		steps = 1
	}
	return steps
}

// runSmartOrchestration is the goroutine body that walks the recon DAG.
//
//	companies → passive → roots
//	roots     → subbrute → hosts
//	roots+subs+urls → httpx → alive URLs
//	alive URLs → webmeta
//	IPs/CIDRs → portscan → live IP:port → httpx
//
// Each stage feeds runner.SourceEvent into the entry so the dashboard's progress
// panel works unchanged.
func runSmartOrchestration(s *server, entry *runEntry, bk smartBuckets, rcfg *runner.Config, active bool, conc, timeoutSec int) {
	defer func() {
		if rec := recover(); rec != nil {
			entry.mu.Lock()
			entry.Status = "error"
			entry.ErrMsg = fmt.Sprintf("panic: %v", rec)
			entry.FinishedAt = time.Now().UTC()
			entry.mu.Unlock()
		}
	}()

	totalBudget := time.Duration(timeoutSec) * time.Second * time.Duration(maxIntS(bk.OrderTotal, 1))
	if totalBudget < 5*time.Minute {
		totalBudget = 5 * time.Minute
	}
	if totalBudget > 6*time.Hour {
		totalBudget = 6 * time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), totalBudget)
	defer cancel()
	entry.mu.Lock()
	entry.cancel = cancel
	entry.mu.Unlock()
	defer func() {
		entry.mu.Lock()
		entry.cancel = nil
		entry.mu.Unlock()
	}()

	emit := func(name, target, phase string, count int, dur time.Duration, errMsg string) {
		entry.appendEvent(runner.SourceEvent{
			Source: name + "[" + target + "]", Phase: phase,
			Count: count, Dur: dur, Err: errMsg,
		})
	}

	rr := runner.NewRunner(rcfg, s.sources)
	var rawAll []*models.Asset

	roots := append([]string(nil), bk.Roots...)
	rootSet := stringSet(roots)

	// 1) Companies → roots via passive sources (beianx / chinaz / bdziyi_icp / ...).
	for _, corp := range bk.Companies {
		if ctx.Err() != nil {
			break
		}
		setCurrent(entry, corp)
		emit("smart-passive", corp, "start", 0, 0, "")
		t0 := time.Now()
		assets, err := rr.Run(ctx, corp)
		dur := time.Since(t0)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		emit("smart-passive", corp, "done", len(assets), dur, errStr)
		rawAll = append(rawAll, assets...)
		// extract eTLD+1 from collected assets for follow-up.
		for _, a := range assets {
			if a == nil {
				continue
			}
			d := strings.ToLower(strings.TrimSpace(a.Domain))
			if d == "" {
				d = strings.ToLower(strings.TrimSpace(a.Host))
			}
			if d == "" {
				continue
			}
			if root := core.RootDomain(d); root != "" {
				if _, ok := rootSet[root]; !ok {
					rootSet[root] = struct{}{}
					roots = append(roots, root)
				}
			}
		}
	}

	// 2) Subdomains/URLs from the file: also kick passive sources to enrich.
	hostInputs := stringSet(nil)
	for _, h := range bk.Subs {
		hostInputs[h] = struct{}{}
	}
	for _, u := range bk.URLs {
		if pu, err := neturl.Parse(u); err == nil && pu.Host != "" {
			hostInputs[strings.ToLower(pu.Hostname())] = struct{}{}
			if root := core.RootDomain(pu.Hostname()); root != "" {
				if _, ok := rootSet[root]; !ok {
					rootSet[root] = struct{}{}
					roots = append(roots, root)
				}
			}
		}
	}

	// 3) Roots → run passive sources, then optionally subbrute.
	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		setCurrent(entry, root)
		emit("smart-passive", root, "start", 0, 0, "")
		t0 := time.Now()
		assets, err := rr.Run(ctx, root)
		dur := time.Since(t0)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		emit("smart-passive", root, "done", len(assets), dur, errStr)
		rawAll = append(rawAll, assets...)
		// Pull subdomains discovered by passive sources into hostInputs.
		for _, a := range assets {
			if a == nil {
				continue
			}
			h := strings.ToLower(strings.TrimSpace(a.Host))
			if h == "" {
				h = strings.ToLower(strings.TrimSpace(a.Domain))
			}
			if h != "" && strings.Contains(h, ".") {
				hostInputs[h] = struct{}{}
			}
		}
		hostInputs[root] = struct{}{}

		if active {
			emit("subbrute", root, "start", 0, 0, "")
			ts := time.Now()
			brute := subdomain.New(subdomain.Config{
				Concurrency: clampConc(conc, 50, 500),
				Timeout:     time.Duration(maxIntS(timeoutSec, 30)) * time.Second,
				IncludeRoot: true,
			})
			res, berr := brute.Run(ctx, root, nil)
			errStr2 := ""
			if berr != nil {
				errStr2 = berr.Error()
			}
			emit("subbrute", root, "done", len(res), time.Since(ts), errStr2)
			for _, sub := range res {
				if sub == nil {
					continue
				}
				rawAll = append(rawAll, sub.ToAsset())
				if sub.Name != "" {
					hostInputs[strings.ToLower(sub.Name)] = struct{}{}
				}
			}
		}
	}

	// 4) IPs/CIDRs → also feed passive (otx/internetdb…) and active portscan.
	ipScanInputs := append([]string(nil), bk.IPs...)
	ipScanInputs = append(ipScanInputs, bk.CIDRs...)
	for _, ip := range bk.IPs {
		if ctx.Err() != nil {
			break
		}
		setCurrent(entry, ip)
		emit("smart-passive", ip, "start", 0, 0, "")
		t0 := time.Now()
		assets, err := rr.Run(ctx, ip)
		dur := time.Since(t0)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		emit("smart-passive", ip, "done", len(assets), dur, errStr)
		rawAll = append(rawAll, assets...)
	}

	httpxInputs := stringSet(nil)
	for h := range hostInputs {
		httpxInputs[h] = struct{}{}
	}
	for _, u := range bk.URLs {
		httpxInputs[u] = struct{}{}
	}

	if active && len(ipScanInputs) > 0 {
		setCurrent(entry, "portscan")
		emit("portscan", "batch", "start", 0, 0, "")
		t0 := time.Now()
		sc := portscan.New(portscan.Config{
			PortPreset:    "top100",
			Concurrency:   clampConc(conc, 200, 1000),
			Timeout:       1500 * time.Millisecond,
			RetryTimeout:  1500 * time.Millisecond,
			BannerTimeout: 2 * time.Second,
		})
		res, perr := sc.Run(ctx, ipScanInputs, nil)
		errStr := ""
		if perr != nil {
			errStr = perr.Error()
		}
		emit("portscan", "batch", "done", len(res), time.Since(t0), errStr)
		for _, r := range res {
			if r == nil {
				continue
			}
			rawAll = append(rawAll, r.ToAsset())
			host := r.IP
			if host == "" {
				host = r.Target
			}
			httpxInputs[fmt.Sprintf("%s:%d", host, r.Port)] = struct{}{}
		}
	}

	// 5) httpx fan-out for everything we've collected.
	var aliveURLs []string
	if active && len(httpxInputs) > 0 {
		setCurrent(entry, "httpx")
		emit("httpx", "batch", "start", 0, 0, "")
		t0 := time.Now()
		pr := httpx.New(httpx.Config{
			Concurrency:     clampConc(conc, 50, 500),
			Timeout:         8 * time.Second,
			FollowRedirects: true,
			SchemesAuto:     true,
			FetchFavicon:    true,
			ResolveDNS:      true,
		})
		inputs := setToSlice(httpxInputs)
		results := pr.Run(ctx, inputs, nil)
		alive := 0
		for _, hr := range results {
			if hr == nil {
				continue
			}
			if hr.Status > 0 {
				alive++
				rawAll = append(rawAll, hr.ToAsset())
				u := hr.FinalURL
				if u == "" {
					u = hr.URL
				}
				if u != "" {
					aliveURLs = append(aliveURLs, u)
				}
			}
		}
		emit("httpx", "batch", "done", alive, time.Since(t0), "")
	}

	// 6) webmeta on alive URLs (active mode only — needs HTTP traffic).
	if active && len(aliveURLs) > 0 {
		setCurrent(entry, "webmeta")
		emit("webmeta", "batch", "start", 0, 0, "")
		t0 := time.Now()
		wmRes := webmeta.Collect(ctx, webmeta.Config{
			Targets:         aliveURLs,
			Concurrency:     clampConc(conc, 8, 32),
			Timeout:         8 * time.Second,
			FetchRobots:     true,
			FetchSitemap:    true,
			FollowRedirects: true,
			TryHTTPFallback: true,
			SkipTLSVerify:   true,
		})
		emit("webmeta", "batch", "done", wmRes.Stats.OK, time.Since(t0), "")
		// Persist webmeta findings as lightweight assets so they show up in the
		// table / dedup pipelines (titles, ICP, emails).
		for _, rep := range wmRes.Reports {
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
			a.Tags = append(a.Tags, "smart-import")
			a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
			rawAll = append(rawAll, a)
		}
	}

	// Finalise: dedup, persist.
	dedupAssets, _ := core.DedupWithStats(rawAll, core.KeySmart)
	entry.mu.Lock()
	entry.RawAssets = rawAll
	entry.Assets = dedupAssets
	entry.FinishedAt = time.Now().UTC()
	if entry.Canceled {
		entry.Status = "canceled"
		entry.ErrMsg = "用户取消"
	} else if ctx.Err() != nil && ctx.Err() != context.Canceled {
		entry.Status = "done" // timeout still yields partial results
	} else {
		entry.Status = "done"
	}
	entry.TargetIdx = entry.TargetTotal
	entry.mu.Unlock()

	if s.dbReady {
		meta := map[string]any{
			"run_id":      entry.ID,
			"sources":     entry.Sources,
			"status":      entry.Status,
			"started_at":  entry.StartedAt,
			"finished_at": entry.FinishedAt,
			"smart": map[string]any{
				"ips": len(bk.IPs), "cidrs": len(bk.CIDRs), "urls": len(bk.URLs),
				"roots": len(bk.Roots), "subs": len(bk.Subs),
				"companies": len(bk.Companies), "unknown": len(bk.Unknown),
				"active": active,
			},
		}
		joined := strings.Join(append(append(append(append(append(append(
			[]string{}, bk.Companies...), bk.Roots...), bk.Subs...), bk.URLs...),
			bk.IPs...), bk.CIDRs...), ",")
		if dbID, err := core.SaveSessionWithRaw(entry.Target, joined, joined, dedupAssets, rawAll, meta); err != nil {
			log.Printf("[server] WARN smart SaveSession run_id=%s: %v", entry.ID, err)
		} else {
			entry.mu.Lock()
			entry.DBID = dbID
			entry.mu.Unlock()
		}
	}
}

// ---- small helpers ----

func setCurrent(e *runEntry, target string) {
	e.mu.Lock()
	e.CurrentTarget = target
	if e.TargetIdx < e.TargetTotal {
		e.TargetIdx++
	}
	e.mu.Unlock()
}

func boolForm(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func atoiForm(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	n := 0
	neg := false
	for i, c := range v {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		return -n
	}
	return n
}

func stringSet(in []string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		m[strings.ToLower(s)] = struct{}{}
	}
	return m
}

func setToSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clampConc(req, def, max int) int {
	if req <= 0 {
		return def
	}
	if req > max {
		return max
	}
	return req
}

func maxIntS(a, b int) int {
	if a > b {
		return a
	}
	return b
}
