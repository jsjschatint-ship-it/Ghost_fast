package importers

import (
	"strings"

	"github.com/wgpsec/ENScan/pkg/core"
	"github.com/wgpsec/ENScan/pkg/models"
)

var listFields = map[string]bool{
	"products": true, "cert_domains": true, "tags": true,
}

func splitList(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	for _, sep := range []string{";", "|", "，", ","} {
		if strings.Contains(v, sep) {
			parts := strings.Split(v, sep)
			out := make([]string, 0, len(parts))
			for _, p := range parts {
				if s := strings.TrimSpace(p); s != "" {
					out = append(out, s)
				}
			}
			return out
		}
	}
	return []string{v}
}

// ImportReconXLSX 导入本工具自己导出的 recon_*.xlsx
// 嗅探：表头里至少 5 个 core.Columns 命中才认。
func ImportReconXLSX(path string) ([]*models.Asset, error) {
	rows, err := ReadXLSXRows(path)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	headers := map[string]bool{}
	for h := range rows[0] {
		headers[h] = true
	}
	hit := 0
	for _, c := range core.Columns {
		if headers[c] {
			hit++
		}
	}
	if hit < 5 {
		return nil, nil
	}

	out := make([]*models.Asset, 0, len(rows))
	for _, r := range rows {
		a := models.NewAsset()
		for _, col := range core.Columns {
			v, ok := r[col]
			if !ok {
				continue
			}
			val := strings.TrimSpace(v)
			if val == "" {
				continue
			}
			switch col {
			case "ip":
				a.WithIP(val)
			case "port":
				a.WithPort(I(r, "port"))
			case "protocol":
				a.WithProtocol(val)
			case "domain":
				a.WithDomain(val)
			case "host":
				a.WithHost(val)
			case "url":
				a.WithURL(val)
			case "service":
				a.WithService(val)
			case "title":
				a.WithTitle(val)
			case "server":
				a.WithServer(val)
			case "products":
				for _, p := range splitList(val) {
					a.WithProduct(p)
				}
			case "os":
				a.WithOS(val)
			case "country":
				a.WithCountry(val)
			case "province":
				a.WithProvince(val)
			case "city":
				a.WithCity(val)
			case "asn":
				a.WithASN(val)
			case "org":
				a.WithOrg(val)
			case "isp":
				a.WithISP(val)
			case "cert_subject":
				a.WithCertSubject(val)
			case "cert_issuer":
				a.WithCertIssuer(val)
			case "cert_domains":
				a.WithCertDomains(splitList(val)...)
			case "jarm":
				a.WithJARM(val)
			case "ja3s":
				a.JA3S = val
			case "favicon_hash":
				a.WithFaviconHash(val)
			case "icp":
				a.WithICP(val)
			case "source":
				a.WithSource(val)
			case "update_time":
				a.WithUpdateTime(val)
			case "tags":
				for _, t := range splitList(val) {
					a.WithTags(t)
				}
			}
		}
		if a.Source == "" {
			a.WithSource("recon_xlsx")
		}
		a.Normalize()
		if a.Key() != "" {
			out = append(out, a)
		}
	}
	return out, nil
}
