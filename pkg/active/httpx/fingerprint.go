package httpx

import (
	"net/http"
	"sort"
	"strings"
)

// rule matches one of: header, body, cookie, favicon-hash. All comparisons are
// case-insensitive and use substring containment unless prefixed with "=".
type rule struct {
	// product is the label emitted when the rule matches.
	product string
	// header matches `Name: ValueSubstring`. Empty `name:`+value means any header value.
	header string
	// body is a substring searched in the response body (lower-cased).
	body string
	// cookie is a substring searched in the Set-Cookie header.
	cookie string
	// favicon is an exact favicon mmh3 hash (signed int32 as decimal string).
	favicon string
}

// fingerprintRules is intentionally small and curated. Keep it ordered by
// specificity (most specific first) so the dedup logic preserves intent.
var fingerprintRules = []rule{
	// --- Web servers ---
	{product: "nginx", header: "Server: nginx"},
	{product: "Apache", header: "Server: Apache"},
	{product: "Microsoft-IIS", header: "Server: Microsoft-IIS"},
	{product: "OpenResty", header: "Server: openresty"},
	{product: "Caddy", header: "Server: Caddy"},
	{product: "LiteSpeed", header: "Server: LiteSpeed"},
	{product: "Tengine", header: "Server: Tengine"},
	{product: "Tomcat", header: "Server: Apache-Coyote"},
	{product: "Jetty", header: "Server: Jetty"},
	{product: "Gunicorn", header: "Server: gunicorn"},
	{product: "uvicorn", header: "Server: uvicorn"},
	{product: "Node.js", header: "X-Powered-By: Express"},
	{product: "PHP", header: "X-Powered-By: PHP"},
	{product: "ASP.NET", header: "X-Powered-By: ASP.NET"},
	{product: "Servlet", header: "X-Powered-By: Servlet"},

	// --- CDN / WAF ---
	{product: "Cloudflare", header: "Server: cloudflare"},
	{product: "Cloudflare", header: "CF-RAY:"},
	{product: "Akamai", header: "Server: AkamaiGHost"},
	{product: "Akamai", header: "X-Akamai-Transformed:"},
	{product: "Fastly", header: "X-Fastly-Request-ID:"},
	{product: "CloudFront", header: "Via: CloudFront"},
	{product: "CloudFront", header: "X-Amz-Cf-Id:"},
	{product: "Aliyun-WAF", header: "Server: Tengine/Aserver"},
	{product: "Aliyun-CDN", header: "Server: Tengine"},
	{product: "Tencent-CDN", header: "X-Cache-Lookup: Hit From"},
	{product: "Tencent-CDN", header: "Server: cdn"},
	{product: "Sucuri", header: "X-Sucuri-ID:"},
	{product: "Imperva", header: "X-Iinfo:"},
	{product: "ModSecurity", header: "Server: Mod_Security"},

	// --- CMS / blog / forum ---
	{product: "WordPress", body: "/wp-content/"},
	{product: "WordPress", header: "X-Pingback:"},
	{product: "Drupal", header: "X-Drupal-Cache:"},
	{product: "Drupal", header: "X-Generator: Drupal"},
	{product: "Joomla", body: "content=\"Joomla"},
	{product: "Discuz!", body: "content=\"Discuz!"},
	{product: "phpBB", body: "content=\"phpBB"},
	{product: "MediaWiki", body: "content=\"MediaWiki"},
	{product: "Ghost", body: "content=\"Ghost "},
	{product: "Typecho", body: "content=\"Typecho"},
	{product: "DedeCMS", body: "content=\"DedeCMS"},
	{product: "MetInfo", body: "content=\"MetInfo"},
	{product: "ThinkCMF", body: "thinkcmf"},

	// --- App frameworks ---
	{product: "Laravel", cookie: "laravel_session="},
	{product: "Laravel", cookie: "XSRF-TOKEN="},
	{product: "Django", cookie: "csrftoken="},
	{product: "Django", cookie: "sessionid="},
	{product: "Flask", cookie: "session=ey"},
	{product: "Rails", cookie: "_rails_session"},
	{product: "Spring", header: "X-Application-Context:"},
	{product: "Spring-Boot", body: "/error\"><pre>"},
	{product: "Spring-Boot", body: "Whitelabel Error Page"},
	{product: "Struts2", body: "struts"},
	{product: "ThinkPHP", body: "ThinkPHP"},
	{product: "FastAPI", body: "<title>FastAPI"},
	{product: "Nuxt", body: "id=\"__nuxt"},
	{product: "Next.js", body: "id=\"__next"},
	{product: "Next.js", header: "X-Powered-By: Next.js"},

	// --- JS libs / frontend ---
	{product: "React", body: "data-reactroot"},
	{product: "React", body: "data-reactid"},
	{product: "Vue.js", body: "id=\"app\" data-v-"},
	{product: "Vue.js", body: "data-server-rendered=\"true\""},
	{product: "Angular", body: "ng-version="},
	{product: "Element-UI", body: "el-button"},
	{product: "Ant-Design", body: "ant-btn"},

	// --- Dev / API tooling ---
	{product: "Swagger-UI", body: "swagger-ui"},
	{product: "Swagger-UI", body: "/swagger-resources"},
	{product: "GraphiQL", body: "GraphiQL"},
	{product: "Actuator", body: "\"_links\":{\"self\""},

	// --- Specific products (PoC magnets) ---
	{product: "Jenkins", header: "X-Jenkins:"},
	{product: "Jira", header: "X-AREQUESTID:"},
	{product: "Jira", cookie: "JSESSIONID="},
	{product: "Confluence", header: "X-Confluence-Request-Time:"},
	{product: "GitLab", body: "GitLab.com"},
	{product: "Gitea", header: "Set-Cookie: i_like_gitea"},
	{product: "Harbor", header: "Set-Cookie: harbor_session"},
	{product: "Nacos", body: "Nacos"},
	{product: "Apollo", body: "apollo-portal"},
	{product: "Kibana", body: "kbn-version"},
	{product: "Grafana", body: "grafana"},
	{product: "Zabbix", body: "Zabbix SIA"},
	{product: "Prometheus", body: "Prometheus Time Series Collection"},
	{product: "WeblogicAdmin", body: "Welcome to Weblogic Application"},
	{product: "phpMyAdmin", body: "phpmyadmin.css.php"},
	{product: "Adminer", body: "Adminer - Database management"},

	// --- Cloud / object storage exposure ---
	{product: "AliyunOSS", body: "<HostId>oss-"},
	{product: "AWS-S3", body: "<ListBucketResult"},
	{product: "MinIO", header: "Server: MinIO"},

	// --- Favicons (most common, copied from public dataset) ---
	{product: "Jenkins", favicon: "81586312"},
	{product: "Spring-Boot", favicon: "116323821"},
	{product: "GitLab", favicon: "-1684273927"},
	{product: "Grafana", favicon: "-1140212333"},
	{product: "Kibana", favicon: "-1085141318"},
	{product: "Nacos", favicon: "13750606"},
	{product: "Harbor", favicon: "657337228"},
	{product: "Gitea", favicon: "-1929969042"},
	{product: "Apache", favicon: "-1664299192"},
}

// productAliases maps known-variant product labels to a single canonical name
// so different databases don't produce duplicate entries like "Next.js" + "nextjs".
// Lookup is keyed on the lower-cased label.
var productAliases = map[string]string{
	"nextjs":       "Next.js",
	"next.js":      "Next.js",
	"swagger":      "Swagger UI",
	"swagger-ui":   "Swagger UI",
	"swagger ui":   "Swagger UI",
	"wordpress":    "WordPress",
	"nginx":        "Nginx",
	"apache":       "Apache",
	"apache httpd": "Apache",
	"openresty":    "OpenResty",
	"tomcat":       "Tomcat",
	"jetty":        "Jetty",
	"gunicorn":     "Gunicorn",
	"php":          "PHP",
	"node.js":      "Node.js",
	"nodejs":       "Node.js",
	"vue":          "Vue.js",
	"vue.js":       "Vue.js",
	"react":        "React",
	"angular":      "Angular",
	"laravel":      "Laravel",
	"django":       "Django",
	"flask":        "Flask",
	"spring":       "Spring",
	"spring boot":  "Spring Boot",
	"spring-boot":  "Spring Boot",
	"cloudflare":   "Cloudflare",
	"akamai":       "Akamai",
	"fastly":       "Fastly",
	"cloudfront":   "CloudFront",
	"jenkins":      "Jenkins",
	"gitlab":       "GitLab",
	"gitea":        "Gitea",
	"jquery":       "jQuery",
}

// canonicaliseProduct returns the canonical display label for a product name
// according to productAliases. Unknown names are returned unchanged.
func canonicaliseProduct(p string) string {
	if c, ok := productAliases[strings.ToLower(p)]; ok {
		return c
	}
	return p
}

// matchFingerprints inspects response metadata + body + favicon hash and returns
// a deduplicated, alphabetised list of matched product labels. It combines the
// embedded fingerprint databases (Wappalyzer + FingerprintHub + EHole, ~9k rules)
// with the small built-in rule set below.
func matchFingerprints(headers http.Header, body []byte, faviconHash, title string) []string {
	// Case-insensitive product set: key=lower(canonical), value=canonical label.
	caseSeen := map[string]string{}
	addProduct := func(p string) {
		c := canonicaliseProduct(p)
		k := strings.ToLower(c)
		if _, ok := caseSeen[k]; !ok {
			caseSeen[k] = c
		}
	}
	for _, p := range dbMatch(headers, body, faviconHash, title) {
		addProduct(p)
	}
	bodyLow := strings.ToLower(string(body))
	cookies := strings.ToLower(strings.Join(headers.Values("Set-Cookie"), "; "))
	// Flatten headers as "name: value" lines for substring scan.
	var flat strings.Builder
	for k, vs := range headers {
		for _, v := range vs {
			flat.WriteString(k)
			flat.WriteString(": ")
			flat.WriteString(v)
			flat.WriteByte('\n')
		}
	}
	flatLow := strings.ToLower(flat.String())

	for _, r := range fingerprintRules {
		hit := false
		switch {
		case r.header != "":
			hit = strings.Contains(flatLow, strings.ToLower(r.header))
		case r.body != "":
			hit = strings.Contains(bodyLow, strings.ToLower(r.body))
		case r.cookie != "":
			hit = strings.Contains(cookies, strings.ToLower(r.cookie))
		case r.favicon != "":
			hit = faviconHash != "" && r.favicon == faviconHash
		}
		if hit {
			addProduct(r.product)
		}
	}
	if len(caseSeen) == 0 {
		return nil
	}
	out := make([]string, 0, len(caseSeen))
	for _, p := range caseSeen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
