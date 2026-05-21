// Package path_pivot 高价值路径反查（零流量） — 蹭 FOFA/Quake 已爬好的全网索引
// 找目标的敏感路径快照。完全被动，不向目标资产发任何流量。
package path_pivot

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// Template 路径模板
type Template struct {
	ID    string
	Cat   string
	Desc  string
	FOFA  string
	Quake string
}

// PathTemplates 内置模板列表
var PathTemplates = []Template{
	// ---- secret ----
	{"git_expose", "secret", "暴露 .git 目录",
		`body=".git/HEAD" || body="[core]\n\trepositoryformatversion" || body="ref: refs/heads"`,
		`body:".git/HEAD" OR body:"[core]" OR body:"ref: refs/heads"`},
	{"env_expose", "secret", "暴露 .env 配置",
		`body="DB_PASSWORD=" || body="APP_KEY=" || body="SECRET_KEY="`,
		`body:"DB_PASSWORD=" OR body:"APP_KEY=" OR body:"SECRET_KEY="`},
	{"svn_expose", "secret", "暴露 .svn/DS_Store",
		`body="svn:entry" || (body="_Bud" && body=".DS_Store")`,
		`body:"svn:entry"`},
	{"wp_config_leak", "secret", "wp-config.php / application.properties 泄露",
		`body="DB_HOST" && body="DB_USER" && body="DB_PASSWORD"`,
		`body:"DB_HOST" AND body:"DB_PASSWORD"`},
	{"backup_file", "secret", "备份/SQL 打包文件",
		`title="Index of /" && (body=".sql" || body=".bak" || body=".zip" || body=".tar.gz")`,
		`title:"Index of /" AND (body:".sql" OR body:".bak" OR body:".zip")`},
	{"cloud_key_leak", "secret", "页面/JS 中泄露的云 AccessKey",
		`body="AKIA" || body="LTAI" || body="aliyun_access_key_id" || body="AKID" || body="AIza"`,
		`body:"AKIA" OR body:"LTAI" OR body:"aliyun_access_key_id" OR body:"AKID"`},
	{"private_key_expose", "secret", "页面泄露 PRIVATE KEY",
		`body="-----BEGIN RSA PRIVATE KEY-----" || body="-----BEGIN OPENSSH PRIVATE KEY-----"`,
		`body:"BEGIN RSA PRIVATE KEY" OR body:"BEGIN OPENSSH PRIVATE KEY"`},
	{"s3_listing", "secret", "公开 S3/OSS/COS Bucket Listing",
		`body="<ListBucketResult"`,
		`body:"<ListBucketResult" OR body:"ListBucketResult xmlns"`},
	{"sourcemap_leak", "secret", "前端 .js.map 源码映射泄露",
		`body="\"sources\":[" && body="\"sourcesContent\""`,
		`body:"sourcesContent" OR body:"webpack:///"`},
	{"kubeconfig_expose", "secret", "kubeconfig / K8s 凭证文件泄露",
		`body="apiVersion: v1" && body="kind: Config" && body="client-certificate-data"`,
		`body:"kind: Config" AND body:"client-certificate-data"`},
	{"dockercfg_expose", "secret", "docker config.json / .dockercfg 凭证泄露",
		`body="\"auths\"" && body="\"auth\"" && body="docker"`,
		`body:"auths" AND body:"auth" AND body:"docker.io"`},

	// ---- API ----
	{"graphql_introspection", "api", "GraphQL Playground / introspection",
		`body="GraphQL Playground" || body="__schema"`,
		`body:"GraphQL Playground" OR body:"__schema"`},
	{"openapi_json", "api", "OpenAPI/Swagger JSON 完整文档",
		`body="\"openapi\":" || body="\"swagger\":\"2.0\""`,
		`body:"openapi" AND body:"paths" AND body:"components"`},
	{"swagger_ui", "api", "Swagger UI",
		`title="Swagger UI" || body="swagger-ui-bundle.js"`,
		`title:"Swagger UI" OR body:"swagger-ui-bundle"`},

	// ---- admin ----
	{"k8s_dashboard", "admin", "K8s Dashboard / Rancher / Harbor",
		`title="Kubernetes Dashboard" || title="Rancher" || title="Harbor"`,
		`title:"Kubernetes Dashboard" OR title:"Rancher" OR title:"Harbor"`},
	{"metabase_superset", "admin", "Metabase / Superset / Redash",
		`title="Metabase" || title="Superset" || title="Redash"`,
		`title:"Metabase" OR title:"Superset" OR title:"Redash"`},
	{"minio_console", "admin", "MinIO Console / Browser",
		`title="MinIO Console" || title="MinIO Browser"`,
		`title:"MinIO Console" OR title:"MinIO Browser"`},
	{"nacos_console", "admin", "Nacos / Apollo 配置中心",
		`title="Nacos" || title="Apollo Config"`,
		`title:"Nacos" OR title:"Apollo"`},
	{"phpmyadmin", "admin", "phpMyAdmin",
		`body="pmahomme" || title="phpMyAdmin"`,
		`body:"pmahomme" OR title:"phpMyAdmin"`},
	{"jenkins", "admin", "Jenkins",
		`header="X-Jenkins" || body="Dashboard [Jenkins]"`,
		`header:"X-Jenkins" OR title:"Dashboard [Jenkins]"`},
	{"grafana", "admin", "Grafana",
		`title="Grafana" || header="grafana"`,
		`title:"Grafana" OR header:"grafana"`},
	{"wp_admin", "admin", "WordPress 后台",
		`body="wp-login.php" && body="WordPress"`,
		`body:"wp-login.php"`},
	{"kibana", "admin", "Kibana",
		`title="Kibana"`,
		`title:"Kibana"`},
	{"portainer", "admin", "Portainer",
		`title="portainer.io" || body="portainer-wrapper"`,
		`title:"portainer.io"`},

	// ---- cve_proned ----
	{"elasticsearch_open", "cve_proned", "ElasticSearch 未授权",
		`body="\"cluster_name\"" && body="\"lucene_version\""`,
		`body:"cluster_name" AND body:"lucene_version"`},
	{"couchdb_open", "cve_proned", "CouchDB 未授权",
		`body="\"couchdb\":\"Welcome\""`,
		`body:"couchdb" AND body:"Welcome"`},
	{"rabbitmq_mgmt", "cve_proned", "RabbitMQ Management",
		`title="RabbitMQ Management"`,
		`title:"RabbitMQ Management"`},
	{"consul_ui", "cve_proned", "Consul UI",
		`title="Consul by HashiCorp"`,
		`title:"Consul by HashiCorp"`},
	{"spring_actuator", "cve_proned", "Spring Actuator",
		`body="/actuator/env"`,
		`body:"/actuator/env" OR body:"actuator/health"`},
	{"druid_monitor", "cve_proned", "阿里 Druid 监控",
		`title="Druid Stat Index"`,
		`title:"Druid Stat Index"`},
	{"solr_admin", "cve_proned", "Solr 管理",
		`title="Solr Admin"`,
		`title:"Solr Admin"`},

	// ---- debug ----
	{"phpinfo", "debug", "phpinfo() 信息泄露",
		`body="PHP Version" && body="phpinfo()"`,
		`body:"phpinfo()" AND body:"PHP Version"`},
	{"apache_server_status", "debug", "Apache mod_status",
		`title="Apache Status"`,
		`title:"Apache Status"`},
	{"nginx_status", "debug", "Nginx stub_status",
		`body="Active connections:" && body="server accepts"`,
		`body:"Active connections:" AND body:"server accepts"`},

	// ---- auth ----
	{"oauth_endpoint", "auth", "OAuth/OIDC 端点",
		`body="\"authorization_endpoint\""`,
		`body:"authorization_endpoint" OR body:"token_endpoint"`},

	// ---- upload ----
	{"dir_listing", "upload", "开放目录列表",
		`title="Index of /"`,
		`title:"Index of /"`},
}

// PathPivot 数据源
type PathPivot struct {
	*source.BaseSource
	client         *req.Client
	fofaKey        string
	quakeKey       string
	maxPerTemplate int
	templateIDs    []string
	categories     []string
}

// New 创建
func New() *PathPivot {
	return &PathPivot{
		BaseSource:     source.NewBaseSource("path_pivot"),
		client:         req.C().SetTimeout(30 * time.Second).SetUserAgent("Mozilla/5.0 (compatible; PassiveRecon/1.0)"),
		maxPerTemplate: 30,
	}
}

// Accepts 接受的输入类型
func (p *PathPivot) Accepts() []string { return []string{"domain"} }

// NeedsKey 是否需要 API Key
func (p *PathPivot) NeedsKey() bool { return true }

// SetConfig 配置
func (p *PathPivot) SetConfig(cfg map[string]any) error {
	_ = p.BaseSource.SetConfig(cfg)
	if v, ok := cfg["fofa_key"].(string); ok {
		p.fofaKey = v
	}
	if v, ok := cfg["quake_key"].(string); ok {
		p.quakeKey = v
	}
	if v, ok := cfg["proxy"].(string); ok && v != "" {
		p.client.SetProxyURL(v)
	}
	if v, ok := cfg["timeout"].(int); ok && v > 0 {
		p.client.SetTimeout(time.Duration(v) * time.Second)
	}
	if v, ok := cfg["max_per_template"].(int); ok && v > 0 {
		p.maxPerTemplate = v
	}
	if v, ok := cfg["template_ids"].([]string); ok {
		p.templateIDs = v
	}
	if v, ok := cfg["categories"].([]string); ok {
		p.categories = v
	}
	return nil
}

// Search 执行搜索
func (p *PathPivot) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	domain := strings.TrimSpace(target)
	if domain == "" {
		return nil, nil
	}
	if p.fofaKey == "" && p.quakeKey == "" {
		return nil, fmt.Errorf("path_pivot needs fofa_key or quake_key")
	}

	type seenKey struct {
		host, url string
		port      int
	}
	seen := map[seenKey]bool{}
	var out []*models.Asset

	for _, t := range PathTemplates {
		if !p.match(t) {
			continue
		}
		// FOFA
		if p.fofaKey != "" {
			q := wrapScopeFOFA(t.FOFA, domain)
			rs := p.fetchFOFA(ctx, q, p.maxPerTemplate)
			for _, a := range rs {
				k := seenKey{a.Host, a.URL, a.Port}
				if seen[k] {
					continue
				}
				seen[k] = true
				a.Tags = append(a.Tags, "high-value", t.Cat, "template:"+t.ID)
				out = append(out, a)
			}
		}
		// Quake
		if p.quakeKey != "" {
			q := wrapScopeQuake(t.Quake, domain)
			rs := p.fetchQuake(ctx, q, p.maxPerTemplate)
			for _, a := range rs {
				k := seenKey{a.Host, a.URL, a.Port}
				if seen[k] {
					continue
				}
				seen[k] = true
				a.Tags = append(a.Tags, "high-value", t.Cat, "template:"+t.ID)
				out = append(out, a)
			}
		}
	}
	return out, nil
}

func (p *PathPivot) match(t Template) bool {
	if len(p.templateIDs) > 0 {
		ok := false
		for _, id := range p.templateIDs {
			if id == t.ID {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(p.categories) > 0 {
		ok := false
		for _, c := range p.categories {
			if c == t.Cat {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// wrapScopeFOFA 把模板片段 + 目标域合成完整 query
func wrapScopeFOFA(frag, domain string) string {
	d := strings.TrimPrefix(strings.TrimSpace(strings.ToLower(domain)), ".")
	scope := fmt.Sprintf(`(domain="%s" || host="%s" || cert="%s")`, d, d, d)
	return fmt.Sprintf("(%s) && %s", frag, scope)
}

func wrapScopeQuake(frag, domain string) string {
	d := strings.TrimPrefix(strings.TrimSpace(strings.ToLower(domain)), ".")
	scope := fmt.Sprintf(`(domain:"%s" OR host:"%s")`, d, d)
	return fmt.Sprintf("(%s) AND %s", frag, scope)
}

// fetchFOFA 走 FOFA API 拉条目
func (p *PathPivot) fetchFOFA(ctx context.Context, query string, maxTotal int) []*models.Asset {
	qb64 := base64.StdEncoding.EncodeToString([]byte(query))
	resp, err := p.client.R().SetContext(ctx).
		SetQueryParam("key", p.fofaKey).
		SetQueryParam("qbase64", qb64).
		SetQueryParam("size", strconv.Itoa(maxTotal)).
		SetQueryParam("page", "1").
		SetQueryParam("fields", "host,ip,port,title,domain,link").
		Get("https://fofa.info/api/v1/search/all")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	body := resp.String()
	if gjson.Get(body, "error").Bool() {
		return nil
	}
	var out []*models.Asset
	for _, row := range gjson.Get(body, "results").Array() {
		arr := row.Array()
		get := func(i int) string {
			if i < len(arr) {
				return arr[i].String()
			}
			return ""
		}
		port, _ := strconv.Atoi(get(2))
		a := models.NewAsset().
			WithHost(get(0)).WithIP(get(1)).WithPort(port).
			WithTitle(get(3)).WithDomain(get(4)).WithURL(get(5)).
			WithSource("fofa-pivot")
		a.Normalize()
		out = append(out, a)
	}
	return out
}

// fetchQuake 走 Quake v3 search API
func (p *PathPivot) fetchQuake(ctx context.Context, query string, maxTotal int) []*models.Asset {
	body := map[string]any{
		"query":   query,
		"start":   0,
		"size":    maxTotal,
		"include": []string{"ip", "port", "domain", "service", "components"},
		"latest":  true,
	}
	resp, err := p.client.R().SetContext(ctx).
		SetHeader("X-QuakeToken", p.quakeKey).
		SetHeader("Content-Type", "application/json").
		SetBodyJsonMarshal(body).
		Post("https://quake.360.net/api/v3/search/quake_service")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	raw := resp.String()
	if gjson.Get(raw, "code").String() != "0" {
		return nil
	}
	var out []*models.Asset
	for _, item := range gjson.Get(raw, "data").Array() {
		ip := item.Get("ip").String()
		port := int(item.Get("port").Int())
		title := item.Get("service.http.title").String()
		domain := item.Get("domain").String()
		host := domain
		if host == "" {
			host = ip
		}
		a := models.NewAsset().
			WithHost(host).WithIP(ip).WithPort(port).
			WithDomain(domain).WithTitle(title).
			WithSource("quake-pivot")
		a.Normalize()
		out = append(out, a)
	}
	return out
}
