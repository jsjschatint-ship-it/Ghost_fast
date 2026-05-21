package core

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/wgpsec/ENScan/pkg/models"
	"golang.org/x/net/publicsuffix"
)

// Columns 导出列顺序
var Columns = []string{
	"source", "ip", "port", "protocol", "domain", "host", "url",
	"service", "title", "server", "products", "os",
	"country", "province", "city", "asn", "org", "isp",
	"icp", "cert_subject", "cert_issuer", "cert_domains",
	"jarm", "ja3s", "favicon_hash", "tags", "update_time",
}

// ToDataFrame 转为 DataFrame（用 map slice 模拟）
func ToDataFrame(assets []*models.Asset) []map[string]any {
	var rows []map[string]any
	for _, a := range assets {
		rows = append(rows, a.ToDict())
	}
	// 确保列顺序
	var out []map[string]any
	for _, row := range rows {
		ordered := make(map[string]any)
		for _, col := range Columns {
			ordered[col] = row[col]
		}
		out = append(out, ordered)
	}
	return out
}

// ToXLSX 导出为多 sheet 的 XLSX 综合报告（22+ sheet，与 Python build_report 对齐）。
// 见 xlsx_report.go 的 BuildReportSheets。
func ToXLSX(assets []*models.Asset, path string) error {
	return ToXLSXReport(assets, path)
}

// ToCSV 导出为 CSV
func ToCSV(assets []*models.Asset, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv: %w", err)
	}
	defer f.Close()
	writer := csv.NewWriter(f)
	defer writer.Flush()
	if err := writer.Write(Columns); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	for _, a := range assets {
		row := a.ToDict()
		var record []string
		for _, col := range Columns {
			val := row[col]
			if val == nil {
				record = append(record, "")
			} else {
				record = append(record, fmt.Sprintf("%v", val))
			}
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write record: %w", err)
		}
	}
	return nil
}

// ToJSON 导出为 JSON
func ToJSON(assets []*models.Asset, path string) error {
	var rows []map[string]any
	for _, a := range assets {
		rows = append(rows, a.ToDict())
	}
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// BuildReport 生成各 sheet 的数据（简化为 map）
func BuildReport(assets []*models.Asset) map[string][]map[string]any {
	df := ToDataFrame(assets)
	report := map[string][]map[string]any{
		"资产明细": df,
	}
	if len(df) == 0 {
		return report
	}
	// 按域名分组
	domainMap := make(map[string][]map[string]any)
	for _, row := range df {
		domain := row["domain"].(string)
		if domain == "" {
			continue
		}
		domainMap[domain] = append(domainMap[domain], row)
	}
	for domain, rows := range domainMap {
		report["域名_"+domain] = rows
	}
	return report
}

// RootDomain 用 publicsuffix 提取 eTLD+1（注册域）。导出版本，便于其它包复用。
//
// 例：www.example.co.uk → example.co.uk; sub.qq.com → qq.com；非域名输入返回原值或空。
func RootDomain(d string) string { return rootDomain(d) }

// rootDomain 包内简写。
func rootDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	if d == "" || !strings.Contains(d, ".") {
		return d
	}
	// 去掉端口
	if i := strings.Index(d, ":"); i > 0 {
		d = d[:i]
	}
	etld, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil || etld == "" {
		parts := strings.Split(d, ".")
		if len(parts) < 2 {
			return d
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return etld
}

// ExportToFile 根据后缀导出
func ExportToFile(assets []*models.Asset, path string) error {
	switch {
	case strings.HasSuffix(strings.ToLower(path), ".csv"):
		return ToCSV(assets, path)
	case strings.HasSuffix(strings.ToLower(path), ".xlsx"):
		return ToXLSX(assets, path)
	case strings.HasSuffix(strings.ToLower(path), ".json"):
		return ToJSON(assets, path)
	default:
		return fmt.Errorf("unsupported output format")
	}
}
