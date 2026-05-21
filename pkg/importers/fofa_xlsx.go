package importers

import (
	"regexp"
	"strings"

	"github.com/wgpsec/ENScan/pkg/models"
)

var reFOFAProduct = regexp.MustCompile(`\{[^{}]*?\s+([^{}\s][^{}]*?)\s*\}`)

// parseFOFAProducts 解析 "[{服务 NGINX } {其他企业应用 Google-站长平台 }]"
func parseFOFAProducts(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, m := range reFOFAProduct.FindAllStringSubmatch(raw, -1) {
		s := strings.TrimSpace(m[1])
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// parseCertDomains 解析 "['a.com', 'b.com']"
func parseCertDomains(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "[]")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.Trim(strings.TrimSpace(p), "'\"")
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ImportFOFAXLSX 导入 FOFA "导出全部" 生成的 xlsx
func ImportFOFAXLSX(path string) ([]*models.Asset, error) {
	rows, err := ReadXLSXRows(path)
	if err != nil {
		return nil, err
	}
	out := make([]*models.Asset, 0, len(rows))
	for _, r := range rows {
		a := models.NewAsset().
			WithIP(S(r, "IP")).
			WithPort(I(r, "端口")).
			WithProtocol(SOr(r, "协议", "基础协议")).
			WithDomain(S(r, "域名")).
			WithHost(S(r, "主机名")).
			WithURL(S(r, "链接")).
			WithService(S(r, "服务")).
			WithTitle(S(r, "标题")).
			WithOS(S(r, "操作系统")).
			WithCountry(SOr(r, "国家", "国家代码")).
			WithProvince(S(r, "区域")).
			WithCity(S(r, "城市")).
			WithASN(S(r, "ASN")).
			WithOrg(S(r, "组织")).
			WithCertSubject(SOr(r, "证书持有者CN", "证书持有者组织")).
			WithCertIssuer(SOr(r, "证书颁发者CN", "证书颁发者组织")).
			WithJARM(S(r, "JARM")).
			WithICP(S(r, "ICP备案号")).
			WithUpdateTime(S(r, "更新时间")).
			WithSource("fofa_xlsx")
		if products := parseFOFAProducts(S(r, "产品名")); len(products) > 0 {
			for _, p := range products {
				a.WithProduct(p)
			}
		}
		if cd := parseCertDomains(S(r, "证书域名")); len(cd) > 0 {
			a.WithCertDomains(cd...)
		}
		a.JA3S = S(r, "JA3S")
		// 把扩展字段塞进 raw
		for _, k := range []string{"HEADER", "BANNER", "CNAME", "证书"} {
			if v := S(r, k); v != "" {
				a.WithRaw(k, v)
			}
		}
		a.Normalize()
		if a.Key() != "" {
			out = append(out, a)
		}
	}
	return out, nil
}
