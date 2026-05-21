package core

import (
	"strings"

	"github.com/wgpsec/ENScan/pkg/models"
)

// CDNKeywords CDN 关键字
var CDNKeywords = []string{
	"cloudflare", "cloudfront", "akamai", "fastly", "incapsula", "cdn",
	"qcloud-cdn", "alikunlun", "ksyuncdn", "wscloudcdn", "chinanetcenter",
	"wangsu", "baidubce", "azureedge", "edgecast", "stackpath", "sucuri",
}

// SensitivePorts 敏感端口映射
var SensitivePorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	110:   "POP3",
	135:   "RPC",
	139:   "NetBIOS",
	445:   "SMB",
	1433:  "MSSQL",
	1521:  "Oracle",
	2375:  "Docker-API",
	2379:  "etcd",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5601:  "Kibana",
	5900:  "VNC",
	6379:  "Redis",
	7001:  "WebLogic",
	8009:  "AJP",
	8080:  "HTTP-Alt",
	8161:  "ActiveMQ",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	9000:  "PHP-FPM",
	9090:  "Prom",
	9200:  "Elasticsearch",
	9300:  "ES-Cluster",
	11211: "Memcached",
	27017: "MongoDB",
	50070: "Hadoop",
}

// LoginKeywords 登录关键字
var LoginKeywords = []string{
	"login", "登录", "signin", "sign in", "管理后台", "后台管理", "admin", "console",
}

// AdminPaths 后台路径
var AdminPaths = []string{
	"/admin", "/manage", "/manager", "/console", "/dashboard",
}

// TagAsset 给资产打标（离线规则）
func TagAsset(a *models.Asset) {
	tags := make(map[string]bool)
	for _, t := range a.Tags {
		tags[t] = true
	}

	// CDN 识别：CNAME / org / ASN
	blob := strings.ToLower(a.Org + " " + a.ISP + " " + a.Raw["cname"] + " " + a.Server)
	for _, kw := range CDNKeywords {
		if strings.Contains(blob, kw) {
			tags["CDN"] = true
			break
		}
	}

	// 敏感端口
	if label, ok := SensitivePorts[a.Port]; ok {
		tags["敏感端口:"+label] = true
	}

	// 登录/后台
	titleLow := strings.ToLower(a.Title)
	urlLow := strings.ToLower(a.URL)
	for _, kw := range LoginKeywords {
		if strings.Contains(titleLow, kw) {
			tags["登录入口"] = true
			break
		}
	}
	for _, p := range AdminPaths {
		if strings.Contains(urlLow, p) {
			tags["后台路径"] = true
			break
		}
	}

	// ICP 备案 → 国内资产
	if a.ICP != "" {
		tags["有ICP备案"] = true
	}

	// 证书泛域名
	for _, d := range a.CertDomains {
		if strings.HasPrefix(d, "*.") {
			tags["泛域名证书"] = true
			break
		}
	}

	// 转为切片
	var out []string
	for t := range tags {
		out = append(out, t)
	}
	a.Tags = out
}

// TagAll 批量打标
func TagAll(assets []*models.Asset) {
	for _, a := range assets {
		TagAsset(a)
	}
}
