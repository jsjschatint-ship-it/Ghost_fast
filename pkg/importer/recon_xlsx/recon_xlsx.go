package recon_xlsx

import (
	"context"
	"fmt"
	"strconv"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// ReconXlsx 实现 Recon Excel 导入器
type ReconXlsx struct {
	*source.BaseSource
}

// NewReconXlsx 创建 ReconXlsx
func NewReconXlsx() *ReconXlsx {
	return &ReconXlsx{
		BaseSource: source.NewBaseSource("recon_xlsx"),
	}
}

// Name 返回名称
func (r *ReconXlsx) Name() string {
	return r.BaseSource.Name()
}

// Accepts 接受的输入类型
func (r *ReconXlsx) Accepts() []string {
	return []string{"file"}
}

// NeedsKey 是否需要 API Key
func (r *ReconXlsx) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (r *ReconXlsx) SetConfig(cfg map[string]any) error {
	_ = r.BaseSource.SetConfig(cfg)
	return nil
}

// Search 执行搜索（从 Excel 导入）
func (r *ReconXlsx) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 1000,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 模拟解析 Recon Excel（实际需用 excelize 库）
	// 假设 Excel 列：ip, port, protocol, domain, host, url, title, country, city, org, service
	rows := [][]string{
		{"1.2.3.4", "80", "http", "example.com", "example.com", "http://example.com", "Example Site", "CN", "Beijing", "Tencent", "nginx"},
		{"1.2.3.5", "443", "https", "example.org", "example.org", "https://example.org", "Example Org", "US", "San Francisco", "Cloudflare", "Apache"},
	}
	var allAssets []*models.Asset
	for _, row := range rows {
		if len(row) < 10 {
			continue
		}
		ip := row[0]
		port, _ := strconv.Atoi(row[1])
		protocol := row[2]
		domain := row[3]
		host := row[4]
		url := row[5]
		title := row[6]
		country := row[7]
		city := row[8]
		org := row[9]
		service := ""
		if len(row) > 10 {
			service = row[10]
		}
		asset := models.NewAsset().
			WithTitle(fmt.Sprintf("[Recon XLSX] %s:%d (%s)", ip, port, title)).
			WithIP(ip).
			WithPort(port).
			WithProtocol(protocol).
			WithDomain(domain).
			WithHost(host).
			WithURL(url).
			WithTitle(title).
			WithCountry(country).
			WithCity(city).
			WithOrg(org).
			WithService(service).
			WithSource(r.Name()).
			WithTags("recon", "xlsx", "import").
			WithRaw("import_file", target)
		allAssets = append(allAssets, asset)
	}
	if len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}
