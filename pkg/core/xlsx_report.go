// Package core: rich multi-sheet XLSX report (port of Python core/exporter.py).
//
// 生成 22 个分析 sheet：
//
//	资产明细 / 摘要 / 来源分布 / 端口统计 / 产品组件 TOP /
//	国家分布 / 城市分布 / ASN组织 / 根域归集 / 资产标签 /
//	路径明细 / 邮箱列表 / 移动应用 / 供应链关联 / 泄露记录 /
//	敏感路径命中 / 证书归集 / CT log 子域 / Wayback 历史 /
//	CDN-防护 / 高价值资产-跨源 / 重点关注
//
// 用 excelize/v2 写真正的 .xlsx，冻结首行 + 自适应列宽。
package core

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/xuri/excelize/v2"
)

// SheetSpec 描述一个 sheet 的内容
type SheetSpec struct {
	Name    string
	Headers []string
	Rows    [][]any // 每行长度应当 == len(Headers)
}

var emailRE = regexp.MustCompile(`[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}`)

// ToXLSXReport 写多 sheet XLSX 报告到文件路径。
func ToXLSXReport(assets []*models.Asset, path string) error {
	f, err := BuildXLSXFile(assets)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.SaveAs(path)
}

// WriteXLSXReport 写到任意 io.Writer（用于 HTTP 响应）。
func WriteXLSXReport(assets []*models.Asset, w io.Writer) error {
	f, err := BuildXLSXFile(assets)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Write(w)
}

// BuildXLSXFile 构造 excelize.File（调用方负责保存）。
func BuildXLSXFile(assets []*models.Asset) (*excelize.File, error) {
	specs := BuildReportSheets(assets)
	if len(specs) == 0 {
		// 至少有一个 sheet
		specs = []SheetSpec{{Name: "资产明细", Headers: []string{"备注"}, Rows: [][]any{{"无数据"}}}}
	}
	f := excelize.NewFile()
	defaultSheet := f.GetSheetName(0)

	for i, s := range specs {
		safeName := safeSheetName(s.Name)
		if i == 0 {
			if err := f.SetSheetName(defaultSheet, safeName); err != nil {
				return nil, fmt.Errorf("rename sheet: %w", err)
			}
		} else {
			if _, err := f.NewSheet(safeName); err != nil {
				return nil, fmt.Errorf("new sheet %q: %w", safeName, err)
			}
		}
		if err := writeSheet(f, safeName, s); err != nil {
			return nil, fmt.Errorf("write sheet %q: %w", safeName, err)
		}
	}
	if idx, err := f.GetSheetIndex(safeSheetName(specs[0].Name)); err == nil {
		f.SetActiveSheet(idx)
	}
	return f, nil
}

// safeSheetName Excel sheet 名不能含 []:*?/\, 最长 31 字符
func safeSheetName(name string) string {
	bad := "[]:*?/\\"
	out := name
	for _, c := range bad {
		out = strings.ReplaceAll(out, string(c), "-")
	}
	if r := []rune(out); len(r) > 31 {
		out = string(r[:31])
	}
	if out == "" {
		return "sheet"
	}
	return out
}

// streamRowThreshold 行数 >= 此值时改用 excelize StreamWriter。
// 经验值：5000 行以下普通写入更快（StreamWriter 启动有开销）；以上 StreamWriter 在 10w 行级数据上
// 速度 ~3-5×、峰值内存 ~40%。
const streamRowThreshold = 5000

// writeSheet 写一个 sheet：行数较少时全量写（含列宽自适应、冻结首行），
// 行数过多时降级到 StreamWriter（牺牲列宽自适应换性能/内存）。
func writeSheet(f *excelize.File, sheet string, s SheetSpec) error {
	if len(s.Rows) >= streamRowThreshold {
		return writeSheetStream(f, sheet, s)
	}
	return writeSheetEager(f, sheet, s)
}

// writeSheetEager 原行为：SetCellValue 全量写 + 列宽自适应 + 冻结首行
func writeSheetEager(f *excelize.File, sheet string, s SheetSpec) error {
	for ci, h := range s.Headers {
		cell, _ := excelize.CoordinatesToCellName(ci+1, 1)
		if err := f.SetCellValue(sheet, cell, h); err != nil {
			return err
		}
	}
	for ri, row := range s.Rows {
		for ci, v := range row {
			if ci >= len(s.Headers) {
				break
			}
			cell, _ := excelize.CoordinatesToCellName(ci+1, ri+2)
			if err := f.SetCellValue(sheet, cell, normalizeCell(v)); err != nil {
				return err
			}
		}
	}
	_ = f.SetPanes(sheet, &excelize.Panes{
		Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft",
	})
	// 自适应列宽
	for ci, h := range s.Headers {
		maxLen := runeLen(h)
		for ri, row := range s.Rows {
			if ri >= 200 || ci >= len(row) {
				if ri >= 200 {
					break
				}
				continue
			}
			ln := runeLen(fmt.Sprintf("%v", row[ci]))
			if ln > 60 {
				ln = 60
			}
			if ln > maxLen {
				maxLen = ln
			}
		}
		col, _ := excelize.ColumnNumberToName(ci + 1)
		width := float64(maxLen + 2)
		if width > 60 {
			width = 60
		}
		if width < 8 {
			width = 8
		}
		_ = f.SetColWidth(sheet, col, col, width)
	}
	return nil
}

// writeSheetStream 用 excelize.StreamWriter 写入大体量数据。
//
// 限制：
//   - Flush 之后该 sheet 不能再用 SetCellValue / SetColWidth / SetPanes，
//     所以列宽用「前 200 行表头采样估计」一次性写入。
//   - 冻结首行也必须在 StreamWriter 写入之前/之中处理：用 SetPanes 在调用方失败，
//     所以这里直接通过 SetPanes 在 NewStreamWriter 之前显式调用一次（部分版本支持）。
func writeSheetStream(f *excelize.File, sheet string, s SheetSpec) error {
	// 冻结首行：必须在 NewStreamWriter 之前
	_ = f.SetPanes(sheet, &excelize.Panes{
		Freeze: true, YSplit: 1, TopLeftCell: "A2", ActivePane: "bottomLeft",
	})
	sw, err := f.NewStreamWriter(sheet)
	if err != nil {
		// 退化到 eager
		return writeSheetEager(f, sheet, s)
	}
	// 列宽：用表头长度 + 前 200 行采样估算
	for ci, h := range s.Headers {
		maxLen := runeLen(h)
		for ri := 0; ri < len(s.Rows) && ri < 200; ri++ {
			row := s.Rows[ri]
			if ci >= len(row) {
				continue
			}
			ln := runeLen(fmt.Sprintf("%v", row[ci]))
			if ln > 60 {
				ln = 60
			}
			if ln > maxLen {
				maxLen = ln
			}
		}
		width := float64(maxLen + 2)
		if width > 60 {
			width = 60
		}
		if width < 8 {
			width = 8
		}
		_ = sw.SetColWidth(ci+1, ci+1, width)
	}
	// 表头行
	headerRow := make([]any, len(s.Headers))
	for i, h := range s.Headers {
		headerRow[i] = h
	}
	if cell, err := excelize.CoordinatesToCellName(1, 1); err == nil {
		_ = sw.SetRow(cell, headerRow)
	}
	// 数据行（StreamWriter 必须按行号递增写）
	for ri, row := range s.Rows {
		cell, _ := excelize.CoordinatesToCellName(1, ri+2)
		// 长度对齐到 headers，越界截断
		vals := make([]any, len(s.Headers))
		for ci := 0; ci < len(s.Headers); ci++ {
			if ci < len(row) {
				vals[ci] = normalizeCell(row[ci])
			} else {
				vals[ci] = ""
			}
		}
		if err := sw.SetRow(cell, vals); err != nil {
			// 单行写入失败不致命，继续后续行
			continue
		}
	}
	return sw.Flush()
}

func runeLen(s string) int { return len([]rune(s)) }

func normalizeCell(v any) any {
	switch x := v.(type) {
	case nil:
		return ""
	case []string:
		return strings.Join(x, ",")
	default:
		return v
	}
}

// MaxRichSheetAssets 当资产数超过此阈值时，跳过 21 张昂贵的分析 sheet 只保留「资产明细」。
// 避免大数据集（>5w 条）在内存里堆全部 sheet 导致 OOM。前端会拿到正常文件，只是少几个 tab。
const MaxRichSheetAssets = 50000

// BuildReportSheets 按 Python core/exporter.py 顺序生成所有 sheet。
//
// 超过 MaxRichSheetAssets 时，第二个 sheet 写一行说明，不再跑高成本的全量聚合。
func BuildReportSheets(assets []*models.Asset) []SheetSpec {
	out := []SheetSpec{buildDetailSheet(assets)}
	if len(assets) == 0 {
		out = append(out, SheetSpec{Name: "摘要", Headers: []string{"备注"}, Rows: [][]any{{"无数据"}}})
		return out
	}
	if len(assets) > MaxRichSheetAssets {
		out = append(out, SheetSpec{
			Name:    "摘要",
			Headers: []string{"项目", "值"},
			Rows: [][]any{
				{"资产总数", len(assets)},
				{"提示", fmt.Sprintf("资产数 > %d，已自动跳过 21 张分析 sheet 以避免内存爆炸。", MaxRichSheetAssets)},
				{"建议", "如需分析图表，请在 dashboard 中按 来源/根域 先筛选后再导出。"},
			},
		})
		return out
	}
	out = append(out, buildSummarySheet(assets))
	out = append(out, valueCountsSheet(assets, "来源分布", "来源", "资产数",
		func(a *models.Asset) string { return a.Source }, 0))
	out = append(out, valueCountsSheet(assets, "端口统计", "端口", "数量",
		func(a *models.Asset) string {
			if a.Port == 0 {
				return ""
			}
			return fmt.Sprintf("%d", a.Port)
		}, 50))
	out = append(out, explodeCountsSheet(assets, "产品组件 TOP", "产品", "数量",
		func(a *models.Asset) []string { return a.Products }, 50))
	out = append(out, valueCountsSheet(assets, "国家分布", "国家", "数量",
		fallback(func(a *models.Asset) string { return a.Country }, "未知"), 50))
	out = append(out, valueCountsSheet(assets, "城市分布", "城市", "数量",
		fallback(func(a *models.Asset) string { return a.City }, "未知"), 50))
	out = append(out, valueCountsSheet(assets, "ASN组织", "组织", "数量",
		fallback(func(a *models.Asset) string { return a.Org }, "未知"), 50))

	if s := buildRootDomainSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := explodeCountsSheetOpt(assets, "资产标签", "标签", "数量",
		func(a *models.Asset) []string { return a.Tags }, 0); s != nil {
		out = append(out, *s)
	}
	if s := buildPathSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildEmailSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildAppSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildSupplySheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildLeakSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildPathPivotSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildCertSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildCTSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildWaybackSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildCDNSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildCrossSourceSheet(assets); s != nil {
		out = append(out, *s)
	}
	if s := buildRiskySheet(assets); s != nil {
		out = append(out, *s)
	}
	return out
}

// ============================================================================
// 通用辅助
// ============================================================================

func fallback(getter func(*models.Asset) string, fb string) func(*models.Asset) string {
	return func(a *models.Asset) string {
		if v := getter(a); v != "" {
			return v
		}
		return fb
	}
}

func uniqueNonEmpty(assets []*models.Asset, getter func(*models.Asset) string) int {
	seen := map[string]struct{}{}
	for _, a := range assets {
		v := getter(a)
		if v != "" {
			seen[v] = struct{}{}
		}
	}
	return len(seen)
}

// valueCountsSheet 标量字段计数（pandas value_counts 等价）
func valueCountsSheet(assets []*models.Asset, sheet, keyLabel, valLabel string,
	getter func(*models.Asset) string, topN int) SheetSpec {
	counts := map[string]int{}
	for _, a := range assets {
		k := getter(a)
		if k == "" {
			continue
		}
		counts[k]++
	}
	return sortedCountsSheet(counts, sheet, keyLabel, valLabel, topN)
}

// explodeCountsSheet 列表字段 explode 后计数
func explodeCountsSheet(assets []*models.Asset, sheet, keyLabel, valLabel string,
	getter func(*models.Asset) []string, topN int) SheetSpec {
	counts := map[string]int{}
	for _, a := range assets {
		for _, k := range getter(a) {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			counts[k]++
		}
	}
	return sortedCountsSheet(counts, sheet, keyLabel, valLabel, topN)
}

// explodeCountsSheetOpt 同 explodeCountsSheet 但空时返回 nil
func explodeCountsSheetOpt(assets []*models.Asset, sheet, keyLabel, valLabel string,
	getter func(*models.Asset) []string, topN int) *SheetSpec {
	s := explodeCountsSheet(assets, sheet, keyLabel, valLabel, getter, topN)
	if len(s.Rows) == 0 {
		return nil
	}
	return &s
}

func sortedCountsSheet(counts map[string]int, sheet, keyLabel, valLabel string, topN int) SheetSpec {
	type kv struct {
		k string
		v int
	}
	kvs := make([]kv, 0, len(counts))
	for k, v := range counts {
		kvs = append(kvs, kv{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool {
		if kvs[i].v != kvs[j].v {
			return kvs[i].v > kvs[j].v
		}
		return kvs[i].k < kvs[j].k
	})
	if topN > 0 && len(kvs) > topN {
		kvs = kvs[:topN]
	}
	rows := make([][]any, 0, len(kvs))
	for _, x := range kvs {
		rows = append(rows, []any{x.k, x.v})
	}
	return SheetSpec{Name: sheet, Headers: []string{keyLabel, valLabel}, Rows: rows}
}

// ============================================================================
// 具体 sheet builders
// ============================================================================

// buildDetailSheet "资产明细"
func buildDetailSheet(assets []*models.Asset) SheetSpec {
	headers := []string{
		"source", "ip", "port", "protocol", "domain", "host", "url",
		"service", "title", "server", "products", "os",
		"country", "province", "city", "asn", "org", "isp",
		"icp", "cert_subject", "cert_issuer", "cert_domains",
		"jarm", "ja3s", "favicon_hash", "tags", "update_time",
	}
	rows := make([][]any, 0, len(assets))
	for _, a := range assets {
		rows = append(rows, []any{
			a.Source, a.IP, portOrEmpty(a.Port), a.Protocol, a.Domain, a.Host, a.URL,
			a.Service, a.Title, a.Server, strings.Join(a.Products, ","), a.OS,
			a.Country, a.Province, a.City, a.ASN, a.Org, a.ISP,
			a.ICP, a.CertSubject, a.CertIssuer, strings.Join(a.CertDomains, ","),
			a.JARM, a.JA3S, a.FaviconHash, strings.Join(a.Tags, ","), a.UpdateTime,
		})
	}
	return SheetSpec{Name: "资产明细", Headers: headers, Rows: rows}
}

func portOrEmpty(p int) any {
	if p == 0 {
		return ""
	}
	return p
}

// buildSummarySheet "摘要"
func buildSummarySheet(assets []*models.Asset) SheetSpec {
	uniqIP := uniqueNonEmpty(assets, func(a *models.Asset) string { return a.IP })
	uniqDomain := uniqueNonEmpty(assets, func(a *models.Asset) string { return a.Domain })
	uniqRoot := uniqueNonEmpty(assets, func(a *models.Asset) string { return rootDomain(a.Domain) })
	uniqPort := uniqueNonEmpty(assets, func(a *models.Asset) string {
		if a.Port == 0 {
			return ""
		}
		return fmt.Sprintf("%d", a.Port)
	})
	sources := map[string]struct{}{}
	for _, a := range assets {
		if a.Source != "" {
			sources[a.Source] = struct{}{}
		}
	}
	srcList := make([]string, 0, len(sources))
	for k := range sources {
		srcList = append(srcList, k)
	}
	sort.Strings(srcList)
	return SheetSpec{
		Name:    "摘要",
		Headers: []string{"指标", "值"},
		Rows: [][]any{
			{"生成时间", time.Now().Format("2006-01-02 15:04:05")},
			{"资产总数", len(assets)},
			{"独立 IP 数", uniqIP},
			{"域名数", uniqDomain},
			{"根域数", uniqRoot},
			{"端口种类", uniqPort},
			{"来源类型", strings.Join(srcList, ", ")},
		},
	}
}

// buildRootDomainSheet "根域归集"：按根域聚合（子域数 / IP 数 / 资产数）
func buildRootDomainSheet(assets []*models.Asset) *SheetSpec {
	type agg struct {
		subdomains map[string]struct{}
		ips        map[string]struct{}
		total      int
	}
	groups := map[string]*agg{}
	for _, a := range assets {
		if a.Domain == "" {
			continue
		}
		root := rootDomain(a.Domain)
		if root == "" {
			continue
		}
		g, ok := groups[root]
		if !ok {
			g = &agg{subdomains: map[string]struct{}{}, ips: map[string]struct{}{}}
			groups[root] = g
		}
		g.subdomains[a.Domain] = struct{}{}
		if a.IP != "" {
			g.ips[a.IP] = struct{}{}
		}
		g.total++
	}
	if len(groups) == 0 {
		return nil
	}
	type row struct {
		root           string
		subs, ips, tot int
	}
	rs := make([]row, 0, len(groups))
	for k, v := range groups {
		rs = append(rs, row{k, len(v.subdomains), len(v.ips), v.total})
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].tot != rs[j].tot {
			return rs[i].tot > rs[j].tot
		}
		return rs[i].root < rs[j].root
	})
	rows := make([][]any, 0, len(rs))
	for _, r := range rs {
		rows = append(rows, []any{r.root, r.subs, r.ips, r.tot})
	}
	return &SheetSpec{
		Name:    "根域归集",
		Headers: []string{"root_domain", "子域数", "IP数", "资产数"},
		Rows:    rows,
	}
}

// buildPathSheet "路径明细"：同一 host 下不同 URL 路径
func buildPathSheet(assets []*models.Asset) *SheetSpec {
	type item struct {
		host, domain, path, url, title, server, products, tags, source string
	}
	hostPaths := map[string]map[string]bool{}
	items := []item{}
	for _, a := range assets {
		if a.URL == "" || !strings.Contains(a.URL, "://") {
			continue
		}
		path := extractPath(a.URL)
		if path == "" {
			continue
		}
		host := a.Host
		if host == "" {
			host = a.Domain
		}
		if host == "" {
			continue
		}
		key := host + "|" + path
		if hostPaths[host] == nil {
			hostPaths[host] = map[string]bool{}
		}
		if hostPaths[host][key] {
			continue
		}
		hostPaths[host][key] = true
		items = append(items, item{
			host: host, domain: a.Domain, path: path, url: a.URL, title: a.Title,
			server: a.Server, products: strings.Join(a.Products, ","),
			tags: strings.Join(a.Tags, ","), source: a.Source,
		})
	}
	if len(items) == 0 {
		return nil
	}
	hostCount := map[string]int{}
	for h, paths := range hostPaths {
		hostCount[h] = len(paths)
	}
	sort.Slice(items, func(i, j int) bool {
		if hostCount[items[i].host] != hostCount[items[j].host] {
			return hostCount[items[i].host] > hostCount[items[j].host]
		}
		if items[i].host != items[j].host {
			return items[i].host < items[j].host
		}
		return items[i].path < items[j].path
	})
	rows := make([][]any, 0, len(items))
	for _, it := range items {
		rows = append(rows, []any{
			hostCount[it.host], it.host, it.domain, it.path, it.url, it.title,
			it.server, it.products, it.tags, it.source,
		})
	}
	return &SheetSpec{
		Name: "路径明细",
		Headers: []string{
			"host_path_count", "host", "domain", "path", "url",
			"title", "server", "products", "tags", "source",
		},
		Rows: rows,
	}
}

func extractPath(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed == nil {
		return ""
	}
	p := parsed.Path
	if parsed.RawQuery != "" {
		p += "?" + parsed.RawQuery
	}
	if p == "" || p == "/" {
		return ""
	}
	return p
}

// buildEmailSheet "邮箱列表"
var emailSourceRE = regexp.MustCompile(`email|^hibp$|^psbdmp$|^intelx$|github_commits|hudsonrock|proxynova|breachdirectory`)
var emailTagRE = regexp.MustCompile(`\bemail\b|email泄露`)

func buildEmailSheet(assets []*models.Asset) *SheetSpec {
	type row struct {
		email, domain, sources, tags, org, title, updateTime string
	}
	rows := []row{}
	bySources := map[string]map[string]struct{}{} // email -> set of source
	for _, a := range assets {
		isEmail := strings.Contains(a.Host, "@")
		if !isEmail {
			if emailRE.MatchString(a.Title) {
				isEmail = true
			} else if a.Service == "email" {
				isEmail = true
			} else if tagstr := strings.Join(a.Tags, ","); emailTagRE.MatchString(tagstr) {
				isEmail = true
			} else if emailSourceRE.MatchString(a.Source) {
				isEmail = true
			}
		}
		if !isEmail {
			continue
		}
		em := ""
		if strings.Contains(a.Host, "@") {
			if m := emailRE.FindString(a.Host); m != "" {
				em = strings.ToLower(m)
			}
		}
		if em == "" {
			if m := emailRE.FindString(a.Title); m != "" {
				em = strings.ToLower(m)
			}
		}
		if em == "" {
			continue
		}
		if bySources[em] == nil {
			bySources[em] = map[string]struct{}{}
		}
		if a.Source != "" {
			bySources[em][a.Source] = struct{}{}
		}
		// 同邮箱保留第一条
		found := false
		for _, r := range rows {
			if r.email == em {
				found = true
				break
			}
		}
		if found {
			continue
		}
		domain := ""
		if at := strings.LastIndex(em, "@"); at >= 0 && at < len(em)-1 {
			domain = em[at+1:]
		}
		rows = append(rows, row{
			email: em, domain: domain, tags: strings.Join(a.Tags, ","),
			org: a.Org, title: a.Title, updateTime: a.UpdateTime,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	// fill sources
	for i := range rows {
		set := bySources[rows[i].email]
		ss := make([]string, 0, len(set))
		for s := range set {
			ss = append(ss, s)
		}
		sort.Strings(ss)
		rows[i].sources = strings.Join(ss, ", ")
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].domain != rows[j].domain {
			return rows[i].domain < rows[j].domain
		}
		return rows[i].email < rows[j].email
	})
	out := make([][]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, []any{r.email, r.domain, r.sources, r.tags, r.org, r.title, r.updateTime})
	}
	return &SheetSpec{
		Name:    "邮箱列表",
		Headers: []string{"邮箱", "域名", "命中源", "标签", "公司", "标题/上下文", "更新时间"},
		Rows:    out,
	}
}

// buildAppSheet "移动应用"
var appSourceRE = regexp.MustCompile(`zerozone-(?:app|apk)`)

func buildAppSheet(assets []*models.Asset) *SheetSpec {
	pickType := func(tags []string) string {
		kws := []string{"小程序", "公众号", "微信", "支付宝", "百度", "抖音", "APP", "H5", "iOS", "Android"}
		joined := strings.ToUpper(strings.Join(tags, ","))
		for _, k := range kws {
			if strings.Contains(joined, strings.ToUpper(k)) {
				return k
			}
		}
		return ""
	}
	rows := [][]any{}
	for _, a := range assets {
		isApp := a.Service == "app" || a.Service == "apk" || appSourceRE.MatchString(a.Source)
		if !isApp {
			continue
		}
		typ := pickType(a.Tags)
		rows = append(rows, []any{
			typ, a.Service, a.Title, a.URL, a.ICP, a.Org,
			strings.Join(a.Tags, ","), a.Source, a.UpdateTime,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := fmt.Sprintf("%v", rows[i][0]), fmt.Sprintf("%v", rows[j][0])
		if ai != aj {
			return ai < aj
		}
		bi, bj := fmt.Sprintf("%v", rows[i][5]), fmt.Sprintf("%v", rows[j][5])
		if bi != bj {
			return bi < bj
		}
		return fmt.Sprintf("%v", rows[i][2]) < fmt.Sprintf("%v", rows[j][2])
	})
	return &SheetSpec{
		Name:    "移动应用",
		Headers: []string{"类型", "服务", "名称", "链接", "ICP", "公司", "标签", "来源", "更新时间"},
		Rows:    rows,
	}
}

// buildSupplySheet "供应链关联"
var supplyRE = regexp.MustCompile(`fofa-supply|fofa-customer|github_org|zerozone-(?:org|member|branch|code)`)

func buildSupplySheet(assets []*models.Asset) *SheetSpec {
	bucket := func(src string) string {
		switch {
		case strings.Contains(src, "fofa-supply"):
			return "🔗 自动 pivot"
		case strings.Contains(src, "fofa-customer"):
			return "👥 vendor 客户"
		case strings.Contains(src, "github_org"):
			return "🐙 GitHub 组织"
		case strings.Contains(src, "zerozone-org"):
			return "🏢 公司"
		case strings.Contains(src, "zerozone-member"):
			return "👤 成员"
		case strings.Contains(src, "zerozone-branch"):
			return "🏢 分支"
		case strings.Contains(src, "zerozone-code"):
			return "💻 代码泄露"
		}
		return "其它"
	}
	rows := [][]any{}
	for _, a := range assets {
		if !supplyRE.MatchString(a.Source) {
			continue
		}
		rows = append(rows, []any{
			bucket(a.Source), a.Host, a.Domain, a.IP, portOrEmpty(a.Port), a.URL,
			a.Title, a.Org, a.ICP, strings.Join(a.Tags, ","), a.Source, a.UpdateTime,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := fmt.Sprintf("%v", rows[i][0]), fmt.Sprintf("%v", rows[j][0])
		if ai != aj {
			return ai < aj
		}
		return fmt.Sprintf("%v", rows[i][7]) < fmt.Sprintf("%v", rows[j][7])
	})
	return &SheetSpec{
		Name: "供应链关联",
		Headers: []string{
			"类别", "Host", "域名", "IP", "端口", "URL",
			"标题", "公司", "ICP", "标签", "来源", "更新时间",
		},
		Rows: rows,
	}
}

// buildLeakSheet "泄露记录"
var leakRE = regexp.MustCompile(`hibp|intelx_leak|intelx|psbdmp|leakix|hunter-verify`)

func buildLeakSheet(assets []*models.Asset) *SheetSpec {
	rows := [][]any{}
	for _, a := range assets {
		if !leakRE.MatchString(a.Source) {
			continue
		}
		rows = append(rows, []any{
			a.Source, a.Host, a.Domain, a.URL, a.Title,
			strings.Join(a.Tags, ","), a.Org, a.UpdateTime,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := fmt.Sprintf("%v", rows[i][0]), fmt.Sprintf("%v", rows[j][0])
		if ai != aj {
			return ai < aj
		}
		return fmt.Sprintf("%v", rows[i][1]) < fmt.Sprintf("%v", rows[j][1])
	})
	return &SheetSpec{
		Name:    "泄露记录",
		Headers: []string{"来源", "Host", "域名", "URL", "描述", "标签", "公司", "时间"},
		Rows:    rows,
	}
}

// buildPathPivotSheet "敏感路径命中"
var pathPivotCategories = map[string]struct{}{
	"secret": {}, "admin": {}, "cve_proned": {}, "api": {},
	"debug": {}, "auth": {}, "upload": {},
}

func buildPathPivotSheet(assets []*models.Asset) *SheetSpec {
	pickTpl := func(tags []string) string {
		for _, t := range tags {
			t = strings.TrimSpace(t)
			if strings.HasPrefix(t, "template:") {
				return t[len("template:"):]
			}
		}
		return ""
	}
	pickCat := func(tags []string) string {
		for _, t := range tags {
			t = strings.TrimSpace(t)
			if _, ok := pathPivotCategories[t]; ok {
				return t
			}
		}
		return ""
	}
	rows := [][]any{}
	for _, a := range assets {
		joined := strings.Join(a.Tags, ",")
		if !strings.Contains(joined, "high-value") && !strings.Contains(joined, "template:") {
			continue
		}
		rows = append(rows, []any{
			pickCat(a.Tags), pickTpl(a.Tags), a.Host, a.URL, a.Title,
			a.Server, strings.Join(a.Products, ","), joined, a.Source,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := fmt.Sprintf("%v", rows[i][0]), fmt.Sprintf("%v", rows[j][0])
		if ai != aj {
			return ai < aj
		}
		bi, bj := fmt.Sprintf("%v", rows[i][1]), fmt.Sprintf("%v", rows[j][1])
		if bi != bj {
			return bi < bj
		}
		return fmt.Sprintf("%v", rows[i][2]) < fmt.Sprintf("%v", rows[j][2])
	})
	return &SheetSpec{
		Name:    "敏感路径命中",
		Headers: []string{"类别", "模板", "Host", "URL", "标题", "Server", "组件", "标签", "来源"},
		Rows:    rows,
	}
}

// buildCertSheet "证书归集"
func buildCertSheet(assets []*models.Asset) *SheetSpec {
	type agg struct {
		count   int
		ips     map[string]struct{}
		domains map[string]struct{}
		issuers map[string]struct{}
		certDom map[string]struct{}
	}
	groups := map[string]*agg{}
	for _, a := range assets {
		if a.CertSubject == "" && a.CertIssuer == "" && len(a.CertDomains) == 0 {
			continue
		}
		key := a.CertSubject
		if key == "" {
			key = "(无主体)"
		}
		g, ok := groups[key]
		if !ok {
			g = &agg{
				ips: map[string]struct{}{}, domains: map[string]struct{}{},
				issuers: map[string]struct{}{}, certDom: map[string]struct{}{},
			}
			groups[key] = g
		}
		g.count++
		if a.IP != "" {
			g.ips[a.IP] = struct{}{}
		}
		if a.Domain != "" {
			g.domains[a.Domain] = struct{}{}
		}
		if a.CertIssuer != "" {
			g.issuers[a.CertIssuer] = struct{}{}
		}
		for _, d := range a.CertDomains {
			if d != "" {
				g.certDom[d] = struct{}{}
			}
		}
	}
	if len(groups) == 0 {
		return nil
	}
	type row struct {
		subject string
		count   int
		ips     int
		domains int
		issuers string
		certDom string
	}
	rs := make([]row, 0, len(groups))
	for k, v := range groups {
		issuers := setToString(v.issuers, 200)
		certDom := setToString(v.certDom, 300)
		rs = append(rs, row{k, v.count, len(v.ips), len(v.domains), issuers, certDom})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].count > rs[j].count })
	rows := make([][]any, 0, len(rs))
	for _, r := range rs {
		rows = append(rows, []any{r.subject, r.count, r.ips, r.domains, r.issuers, r.certDom})
	}
	return &SheetSpec{
		Name:    "证书归集",
		Headers: []string{"证书主体", "资产数", "IP数", "域名数", "签发者", "含域"},
		Rows:    rows,
	}
}

func setToString(set map[string]struct{}, maxLen int) string {
	ss := make([]string, 0, len(set))
	for s := range set {
		ss = append(ss, s)
	}
	sort.Strings(ss)
	out := strings.Join(ss, ", ")
	if len([]rune(out)) > maxLen {
		r := []rune(out)
		out = string(r[:maxLen])
	}
	return out
}

// buildCTSheet "CT log 子域"
var ctRE = regexp.MustCompile(`^(?:ctlog|certspotter|crt\.sh|chaos|rapiddns|dnsdumpster)`)

func buildCTSheet(assets []*models.Asset) *SheetSpec {
	rows := [][]any{}
	seen := map[string]bool{}
	for _, a := range assets {
		if !ctRE.MatchString(a.Source) {
			continue
		}
		key := a.Domain
		if key == "" {
			key = a.Host
		}
		if key == "" {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		rows = append(rows, []any{a.Domain, a.Host, a.IP, a.Source, a.UpdateTime})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := fmt.Sprintf("%v", rows[i][0]), fmt.Sprintf("%v", rows[j][0])
		if ai != "" && aj != "" {
			return ai < aj
		}
		return fmt.Sprintf("%v", rows[i][1]) < fmt.Sprintf("%v", rows[j][1])
	})
	return &SheetSpec{
		Name:    "CT log 子域",
		Headers: []string{"域名", "Host", "IP", "来源", "时间"},
		Rows:    rows,
	}
}

// buildWaybackSheet "Wayback 历史"
func buildWaybackSheet(assets []*models.Asset) *SheetSpec {
	rows := [][]any{}
	seen := map[string]bool{}
	for _, a := range assets {
		if !strings.HasPrefix(a.Source, "wayback") {
			continue
		}
		if a.URL == "" || seen[a.URL] {
			continue
		}
		seen[a.URL] = true
		rows = append(rows, []any{a.URL, a.Host, a.Domain, a.Title, a.UpdateTime, a.Source})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return fmt.Sprintf("%v", rows[i][1]) < fmt.Sprintf("%v", rows[j][1])
	})
	return &SheetSpec{
		Name:    "Wayback 历史",
		Headers: []string{"URL", "Host", "域名", "标题", "归档时间", "来源"},
		Rows:    rows,
	}
}

// buildCDNSheet "CDN-防护"
func buildCDNSheet(assets []*models.Asset) *SheetSpec {
	rows := [][]any{}
	for _, a := range assets {
		isCDN := false
		for _, t := range a.Tags {
			if t == "CDN" {
				isCDN = true
				break
			}
		}
		if !isCDN {
			continue
		}
		rows = append(rows, []any{
			a.Host, a.Domain, a.IP, a.Org, a.ISP, a.Server,
			strings.Join(a.Tags, ","), a.Source,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := fmt.Sprintf("%v", rows[i][3]), fmt.Sprintf("%v", rows[j][3])
		if ai != aj {
			return ai < aj
		}
		return fmt.Sprintf("%v", rows[i][0]) < fmt.Sprintf("%v", rows[j][0])
	})
	return &SheetSpec{
		Name:    "CDN-防护",
		Headers: []string{"Host", "域名", "IP", "组织", "ISP", "Server", "标签", "来源"},
		Rows:    rows,
	}
}

// buildCrossSourceSheet "高价值资产-跨源"：source 含 "+"
func buildCrossSourceSheet(assets []*models.Asset) *SheetSpec {
	rows := [][]any{}
	for _, a := range assets {
		if !strings.Contains(a.Source, "+") {
			continue
		}
		rows = append(rows, []any{
			a.Source, a.IP, portOrEmpty(a.Port), a.Protocol, a.Domain, a.Host, a.URL,
			a.Service, a.Title, a.Server, strings.Join(a.Products, ","),
			a.Country, a.City, a.Org, a.ICP, strings.Join(a.Tags, ","), a.UpdateTime,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	return &SheetSpec{
		Name: "高价值资产-跨源",
		Headers: []string{
			"source", "ip", "port", "protocol", "domain", "host", "url",
			"service", "title", "server", "products",
			"country", "city", "org", "icp", "tags", "update_time",
		},
		Rows: rows,
	}
}

// buildRiskySheet "重点关注"：tags 含 敏感端口/后台/登录
func buildRiskySheet(assets []*models.Asset) *SheetSpec {
	rows := [][]any{}
	for _, a := range assets {
		joined := strings.Join(a.Tags, ",")
		if !strings.Contains(joined, "敏感端口") &&
			!strings.Contains(joined, "后台") &&
			!strings.Contains(joined, "登录") {
			continue
		}
		rows = append(rows, []any{
			a.Source, a.IP, portOrEmpty(a.Port), a.Domain, a.Host, a.URL,
			a.Title, a.Server, strings.Join(a.Products, ","),
			a.Country, a.City, a.Org, joined, a.UpdateTime,
		})
	}
	if len(rows) == 0 {
		return nil
	}
	return &SheetSpec{
		Name: "重点关注",
		Headers: []string{
			"source", "ip", "port", "domain", "host", "url",
			"title", "server", "products", "country", "city", "org", "tags", "update_time",
		},
		Rows: rows,
	}
}
