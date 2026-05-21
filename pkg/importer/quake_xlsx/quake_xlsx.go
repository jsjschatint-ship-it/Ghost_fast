package quake_xlsx

import (
	"context"
	"fmt"
	"strconv"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// QuakeXlsx 实现 Quake Excel 导入器
type QuakeXlsx struct {
	*source.BaseSource
}

// NewQuakeXlsx 创建 QuakeXlsx
func NewQuakeXlsx() *QuakeXlsx {
	return &QuakeXlsx{
		BaseSource: source.NewBaseSource("quake_xlsx"),
	}
}

// Name 返回名称
func (q *QuakeXlsx) Name() string {
	return q.BaseSource.Name()
}

// Accepts 接受的输入类型
func (q *QuakeXlsx) Accepts() []string {
	return []string{"file"}
}

// NeedsKey 是否需要 API Key
func (q *QuakeXlsx) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (q *QuakeXlsx) SetConfig(cfg map[string]any) error {
	_ = q.BaseSource.SetConfig(cfg)
	return nil
}

// Search 执行搜索（从 Excel 导入）
func (q *QuakeXlsx) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 1000,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 模拟解析 Quake Excel（实际需用 excelize 库）
	// 假设 Excel 列：ip, port, service, hostname, title, country, city, org
	rows := [][]string{
		{"1.2.3.4", "80", "http", "example.com", "Example Site", "CN", "Beijing", "Tencent"},
		{"1.2.3.5", "443", "https", "example.org", "Example Org", "US", "San Francisco", "Cloudflare"},
	}
	var allAssets []*models.Asset
	for _, row := range rows {
		if len(row) < 7 {
			continue
		}
		ip := row[0]
		port, _ := strconv.Atoi(row[1])
		service := row[2]
		hostname := row[3]
		title := row[4]
		country := row[5]
		city := row[6]
		org := ""
		if len(row) > 7 {
			org = row[7]
		}
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[Quake XLSX] %s:%d (%s)", ip, port, title)).
			WithIP(ip).
			WithPort(port).
			WithService(service).
			WithHost(hostname).
			WithTitle(title).
			WithCountry(country).
			WithCity(city).
			WithOrg(org).
			WithSource(q.Name()).
			WithTags("quake", "xlsx", "import").
			WithRaw("import_file", target)
		allAssets = append(allAssets, asset)
	}
	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}
