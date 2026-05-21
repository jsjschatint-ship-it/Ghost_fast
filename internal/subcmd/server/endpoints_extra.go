// 额外的 dashboard 后端端点：
//
//	GET  /api/export        ?id=&fmt=xlsx|csv|json   下载结果
//	POST /api/dedup_preview ?id=                     运行所有策略对比
//	POST /api/dedup_apply   ?id=&strategy=           应用策略覆盖 runStore 里的 Assets
//	GET  /api/analyze       ?id=                     根域归集 + 地理/ASN 排行
//
// 这些都不需要落库，只读 / 改 runStore 内存条目。
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/wgpsec/ENScan/pkg/core"
	"github.com/wgpsec/ENScan/pkg/models"
)

// ----------------------------------------------------------------------------
// /api/export
// ----------------------------------------------------------------------------

func (s *server) handleExport(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, 400, "id required")
		return
	}
	fmtType := strings.ToLower(r.URL.Query().Get("fmt"))
	if fmtType == "" {
		fmtType = "xlsx"
	}
	e, ok := s.store.get(id)
	if !ok {
		writeError(w, 404, "not found")
		return
	}
	assets := e.Assets
	safeTarget := sanitizeFilename(e.Target)
	if safeTarget == "" {
		safeTarget = "assets"
	}
	switch fmtType {
	case "xlsx":
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.xlsx"`, safeTarget))
		if err := core.WriteXLSXReport(assets, w); err != nil {
			writeError(w, 500, "xlsx: "+err.Error())
		}
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, safeTarget))
		_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF}) // BOM for Excel
		writeAssetsCSV(w, assets)
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, safeTarget))
		_ = json.NewEncoder(w).Encode(assets)
	default:
		writeError(w, 400, "unsupported fmt: "+fmtType)
	}
}

func sanitizeFilename(s string) string {
	bad := "[]:*?/\\<>|\""
	for _, c := range bad {
		s = strings.ReplaceAll(s, string(c), "_")
	}
	s = strings.TrimSpace(s)
	if len([]rune(s)) > 60 {
		r := []rune(s)
		s = string(r[:60])
	}
	return s
}

func writeAssetsCSV(w http.ResponseWriter, assets []*models.Asset) {
	cols := core.Columns
	// 头
	fmt.Fprintln(w, strings.Join(cols, ","))
	for _, a := range assets {
		row := a.ToDict()
		parts := make([]string, 0, len(cols))
		for _, c := range cols {
			parts = append(parts, csvEsc(fmt.Sprintf("%v", row[c])))
		}
		fmt.Fprintln(w, strings.Join(parts, ","))
	}
}

func csvEsc(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// ----------------------------------------------------------------------------
// /api/dedup_preview  &  /api/dedup_apply
// ----------------------------------------------------------------------------

type dedupStat struct {
	Strategy     string `json:"strategy"`
	TotalIn      int    `json:"total_in"`
	TotalOut     int    `json:"total_out"`
	Reduced      int    `json:"reduced"`
	MergedGroups int    `json:"merged_groups"`
	DroppedNoKey int    `json:"dropped_no_key"`
	ReducedPct   string `json:"reduced_pct"` // "99.3%"
}

type dedupPreviewResp struct {
	Current    string      `json:"current"`  // 当前选用策略
	Original   int         `json:"original"` // 原始堆条数（已含上次去重的 Assets 是这个值；前端可叠加 dropped 反推）
	After      int         `json:"after"`    // 当前 Assets 实际条数
	Strategies []dedupStat `json:"strategies"`
}

func (s *server) handleDedupPreview(w http.ResponseWriter, r *http.Request) {
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
	// 预览统一基于 RawAssets（原始堆）；fallback 到 Assets 兼容老 entry
	raw := e.RawAssets
	if raw == nil {
		raw = e.Assets
	}
	if raw == nil {
		raw = []*models.Asset{}
	}
	strategies := []core.KeyStrategy{
		core.KeySmart, core.KeyIPPort, core.KeyIP, core.KeyDomain, core.KeyURL, core.KeyHostPort,
	}
	resp := dedupPreviewResp{
		Current:    string(core.KeySmart),
		Original:   len(raw),
		After:      len(e.Assets),
		Strategies: make([]dedupStat, 0, len(strategies)),
	}
	for _, strat := range strategies {
		out, stats := core.DedupWithStats(raw, strat)
		pct := "0.0%"
		if stats.TotalIn > 0 {
			pct = fmt.Sprintf("%.1f%%", float64(stats.Reduced)/float64(stats.TotalIn)*100)
		}
		_ = out
		resp.Strategies = append(resp.Strategies, dedupStat{
			Strategy:     string(strat),
			TotalIn:      stats.TotalIn,
			TotalOut:     stats.TotalOut,
			Reduced:      stats.Reduced,
			MergedGroups: stats.MergedGroups,
			DroppedNoKey: stats.DroppedNoKey,
			ReducedPct:   pct,
		})
	}
	writeJSON(w, 200, resp)
}

func (s *server) handleDedupApply(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, 400, "id required")
		return
	}
	strat := core.KeyStrategy(r.URL.Query().Get("strategy"))
	if strat == "" {
		strat = core.KeySmart
	}
	// 自定义字段（仅 strategy=custom 生效），既支持 query (?fields=host,port) 也支持 POST JSON body {fields:[...]}
	var customFields []string
	if strat == core.KeyCustom {
		if q := r.URL.Query().Get("fields"); q != "" {
			for _, f := range strings.Split(q, ",") {
				if f = strings.TrimSpace(f); f != "" {
					customFields = append(customFields, f)
				}
			}
		}
		if r.Body != nil && r.ContentLength != 0 {
			var body struct {
				Fields []string `json:"fields"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
				if len(body.Fields) > 0 {
					customFields = body.Fields
				}
			}
		}
		if len(customFields) == 0 {
			writeError(w, 400, "custom strategy requires non-empty fields[]")
			return
		}
	}
	e, ok := s.store.get(id)
	if !ok {
		writeError(w, 404, "not found")
		return
	}
	// 切策略时从 RawAssets 重算，不会因为之前 apply 过激进策略而丢数据
	raw := e.RawAssets
	if raw == nil {
		raw = e.Assets
	}
	var (
		out   []*models.Asset
		stats core.DedupStats
	)
	if strat == core.KeyCustom {
		out, stats = core.DedupCustom(raw, customFields)
	} else {
		out, stats = core.DedupWithStats(raw, strat)
	}
	e.mu.Lock()
	e.Assets = out
	e.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"strategy":      stats.Strategy,
		"total_in":      stats.TotalIn,
		"total_out":     stats.TotalOut,
		"reduced":       stats.Reduced,
		"merged_groups": stats.MergedGroups,
		"fields":        customFields,
	})
}

// ----------------------------------------------------------------------------
// /api/analyze  ——  根域归集 / 地理 / ASN 多维度分析
// ----------------------------------------------------------------------------

type analyzeRow struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
	Extra any    `json:"extra,omitempty"` // 根域：{sub_count,ip_count}
}

type analyzeResp struct {
	Roots     []analyzeRow `json:"roots"`     // 根域归集
	Countries []analyzeRow `json:"countries"` // 国家
	Cities    []analyzeRow `json:"cities"`    // 城市
	ASNs      []analyzeRow `json:"asns"`      // ASN 组织
	ISPs      []analyzeRow `json:"isps"`      // ISP
}

func (s *server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
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
	resp := analyzeResp{
		Roots:     buildRootDomainRows(e.Assets),
		Countries: simpleCounts(e.Assets, func(a *models.Asset) string { return a.Country }, 50),
		Cities:    simpleCounts(e.Assets, func(a *models.Asset) string { return a.City }, 50),
		ASNs:      simpleCounts(e.Assets, func(a *models.Asset) string { return a.Org }, 50),
		ISPs:      simpleCounts(e.Assets, func(a *models.Asset) string { return a.ISP }, 50),
	}
	writeJSON(w, 200, resp)
}

func buildRootDomainRows(assets []*models.Asset) []analyzeRow {
	type agg struct {
		subs map[string]struct{}
		ips  map[string]struct{}
		tot  int
	}
	groups := map[string]*agg{}
	for _, a := range assets {
		if a.Domain == "" {
			continue
		}
		root := core.RootDomain(a.Domain)
		if root == "" {
			continue
		}
		g, ok := groups[root]
		if !ok {
			g = &agg{subs: map[string]struct{}{}, ips: map[string]struct{}{}}
			groups[root] = g
		}
		g.subs[a.Domain] = struct{}{}
		if a.IP != "" {
			g.ips[a.IP] = struct{}{}
		}
		g.tot++
	}
	rows := make([]analyzeRow, 0, len(groups))
	for k, v := range groups {
		rows = append(rows, analyzeRow{
			Key:   k,
			Count: v.tot,
			Extra: map[string]int{"sub_count": len(v.subs), "ip_count": len(v.ips)},
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Key < rows[j].Key
	})
	if len(rows) > 200 {
		rows = rows[:200]
	}
	return rows
}

func simpleCounts(assets []*models.Asset, getter func(*models.Asset) string, n int) []analyzeRow {
	counts := map[string]int{}
	for _, a := range assets {
		k := getter(a)
		if k == "" {
			k = "未知"
		}
		counts[k]++
	}
	rows := make([]analyzeRow, 0, len(counts))
	for k, v := range counts {
		rows = append(rows, analyzeRow{Key: k, Count: v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Key < rows[j].Key
	})
	if n > 0 && len(rows) > n {
		rows = rows[:n]
	}
	return rows
}
