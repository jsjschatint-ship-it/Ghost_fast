// Package core URL 高价值路径分类器。
// 对一个完整 URL 返回它命中的高价值标签列表，给 Wayback / JS 端点抽取 / 测绘平台原始 URL 等场景共用。
package core

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

// URL 分类规则
var (
	secretPatterns = []*regexp.Regexp{
		// 凭据 / 源码
		regexp.MustCompile(`/\.git(?:/|$)`),
		regexp.MustCompile(`/\.svn(?:/|$)`),
		regexp.MustCompile(`/\.hg(?:/|$)`),
		regexp.MustCompile(`/\.bzr(?:/|$)`),
		regexp.MustCompile(`/\.env(?:\.|/|$)`),
		regexp.MustCompile(`/\.DS_Store$`),
		regexp.MustCompile(`/wp-config\.php(?:\.bak)?`),
		regexp.MustCompile(`/web\.config`),
		regexp.MustCompile(`/config\.php(?:\.bak)?`),
		regexp.MustCompile(`/configuration\.php`),
		regexp.MustCompile(`/database\.yml`),
		regexp.MustCompile(`/secrets\.yml`),
		regexp.MustCompile(`/id_rsa(?:\.pub)?$`),
		regexp.MustCompile(`/\.htpasswd`),
		regexp.MustCompile(`/\.htaccess`),
		regexp.MustCompile(`\.bak$`),
		regexp.MustCompile(`\.sql(?:\.gz|\.bz2|\.zip)?$`),
		regexp.MustCompile(`\.tar(?:\.gz|\.bz2)?$`),
		regexp.MustCompile(`\.zip$`),
		regexp.MustCompile(`\.rar$`),
		regexp.MustCompile(`\.7z$`),
	}
	adminPatterns = []*regexp.Regexp{
		regexp.MustCompile(`/admin(?:/|$)`),
		regexp.MustCompile(`/manager(?:/|$)`),
		regexp.MustCompile(`/manage(?:/|$)`),
		regexp.MustCompile(`/console(?:/|$)`),
		regexp.MustCompile(`/dashboard(?:/|$)`),
		regexp.MustCompile(`/jenkins(?:/|$)`),
		regexp.MustCompile(`/grafana(?:/|$)`),
		regexp.MustCompile(`/phpmyadmin(?:/|$)`),
		regexp.MustCompile(`/kibana(?:/|$)`),
		regexp.MustCompile(`/zabbix(?:/|$)`),
	}
	apiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`/api(?:/|$)`),
		regexp.MustCompile(`/v\d+(?:/|$)`),
		regexp.MustCompile(`/graphql(?:/|$)`),
		regexp.MustCompile(`/swagger`),
		regexp.MustCompile(`/openapi`),
		regexp.MustCompile(`/rest(?:/|$)`),
	}
	uploadPatterns = []*regexp.Regexp{
		regexp.MustCompile(`/upload(?:/|$)`),
		regexp.MustCompile(`/file(?:/|$)`),
		regexp.MustCompile(`/download(?:/|$)`),
		regexp.MustCompile(`/attachment(?:/|$)`),
	}
	debugPatterns = []*regexp.Regexp{
		regexp.MustCompile(`/test(?:/|$)`),
		regexp.MustCompile(`/debug(?:/|$)`),
		regexp.MustCompile(`/phpinfo`),
		regexp.MustCompile(`/server-status`),
		regexp.MustCompile(`/server-info`),
		regexp.MustCompile(`/info\.php`),
	}
	authPatterns = []*regexp.Regexp{
		regexp.MustCompile(`/oauth(?:/|$)`),
		regexp.MustCompile(`/sso(?:/|$)`),
		regexp.MustCompile(`/saml(?:/|$)`),
		regexp.MustCompile(`/\.well-known(?:/|$)`),
		regexp.MustCompile(`/login(?:/|$)`),
		regexp.MustCompile(`/signin(?:/|$)`),
	}
	cveProneonPatterns = []*regexp.Regexp{
		regexp.MustCompile(`/struts(?:/|$)`),
		regexp.MustCompile(`/actuator(?:/|$)`),
		regexp.MustCompile(`/druid(?:/|$)`),
		regexp.MustCompile(`/elasticsearch(?:/|$)`),
		regexp.MustCompile(`/solr(?:/|$)`),
		regexp.MustCompile(`/redis(?:/|$)`),
		regexp.MustCompile(`/zookeeper(?:/|$)`),
	}
)

// Classify 返回 URL 命中的高价值标签列表
func Classify(rawURL string) []string {
	if rawURL == "" {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	p := strings.ToLower(u.Path)
	var tags []string
	check := func(patterns []*regexp.Regexp, label string) bool {
		for _, re := range patterns {
			if re.MatchString(p) {
				tags = append(tags, "high-value", label)
				return true
			}
		}
		return false
	}
	// 按优先级，命中即停
	if check(secretPatterns, "secret") {
		ext := strings.ToLower(path.Ext(p))
		if ext != "" {
			tags = append(tags, "ext:"+ext)
		}
		return tags
	}
	if check(adminPatterns, "admin") {
		return tags
	}
	if check(apiPatterns, "api") {
		return tags
	}
	if check(uploadPatterns, "upload") {
		return tags
	}
	if check(debugPatterns, "debug") {
		return tags
	}
	if check(authPatterns, "auth") {
		return tags
	}
	if check(cveProneonPatterns, "cve_prone") {
		return tags
	}
	return tags
}
