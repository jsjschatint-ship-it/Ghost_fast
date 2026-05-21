package importers

import (
	"strings"

	"github.com/wgpsec/ENScan/pkg/models"
)

func splitQuakeList(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "[]")
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "|", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ImportQuakeXLSX 导入 360 Quake "数据导出" 生成的 xlsx
func ImportQuakeXLSX(path string) ([]*models.Asset, error) {
	rows, err := ReadXLSXRows(path)
	if err != nil {
		return nil, err
	}
	out := make([]*models.Asset, 0, len(rows))
	for _, r := range rows {
		osStr := S(r, "操作系统")
		if v := S(r, "操作系统版本"); v != "" {
			osStr = strings.TrimSpace(osStr + " " + v)
		}
		certSubj := S(r, "证书")
		if len(certSubj) > 200 {
			certSubj = certSubj[:200]
		}
		a := models.NewAsset().
			WithIP(S(r, "IP")).
			WithPort(I(r, "端口")).
			WithProtocol(SOr(r, "传输协议", "服务")).
			WithDomain(S(r, "域名")).
			WithHost(S(r, "主机名")).
			WithURL(S(r, "链接")).
			WithService(S(r, "服务")).
			WithTitle(S(r, "网页标题")).
			WithServer(S(r, "服务器")).
			WithOS(osStr).
			WithCountry(SOr(r, "国家中文", "国家英文", "国家代码")).
			WithProvince(SOr(r, "省份中文", "省份英文")).
			WithCity(SOr(r, "城市中文", "城市英文")).
			WithASN(S(r, "自治域编号")).
			WithOrg(SOr(r, "自治域名称", "自治域")).
			WithISP(S(r, "运营商")).
			WithICP(S(r, "备案号")).
			WithCertSubject(certSubj).
			WithJARM(S(r, "JARM指纹")).
			WithFaviconHash(S(r, "FAVICON指纹")).
			WithUpdateTime(S(r, "更新时间")).
			WithSource("quake_xlsx")
		a.JA3S = S(r, "JA3S指纹")
		for _, p := range splitQuakeList(S(r, "组件")) {
			a.WithProduct(p)
		}
		for _, k := range []string{"响应头", "内容", "网站路径", "HTML指纹", "GPS坐标"} {
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
