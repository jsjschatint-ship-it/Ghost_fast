package sensifile

import "strings"

// rule defines one sensitive-path probe.
type rule struct {
	Path        string
	Category    string
	Severity    string // info|low|medium|high|critical
	Description string
	// Confirm is called with the response body. If non-nil, returning false
	// means "looked like a 200 but doesn't shape-match → ignore" (common on
	// SPA sites that return their index.html for every unknown path).
	Confirm func(body string) bool
}

// defaultRules is the curated list of paths we probe. Severity guidelines:
//
//	info     — public-by-design but useful (robots.txt, sitemap.xml)
//	low      — informational leak (server-status, /actuator)
//	medium   — non-trivial leak (.DS_Store, swagger.json)
//	high     — direct source/config leak (.git, .env, web.config)
//	critical — direct credential leak (id_rsa, .aws/credentials)
var defaultRules = []rule{
	// ---- VCS / source ----
	{Path: "/.git/HEAD", Category: "git", Severity: "high",
		Description: "Exposed .git directory — full source recovery possible",
		Confirm:     func(b string) bool { return strings.Contains(b, "ref: refs/") }},
	{Path: "/.git/config", Category: "git", Severity: "high",
		Description: ".git/config — repo metadata + remote URL",
		Confirm:     func(b string) bool { return strings.Contains(b, "[core]") || strings.Contains(b, "[remote") }},
	{Path: "/.gitignore", Category: "git", Severity: "info",
		Description: ".gitignore (informational)"},
	{Path: "/.svn/entries", Category: "svn", Severity: "high",
		Description: "Exposed Subversion repo"},
	{Path: "/.hg/store/00manifest.i", Category: "hg", Severity: "high",
		Description: "Exposed Mercurial repo"},
	{Path: "/.bzr/branch-format", Category: "bzr", Severity: "high",
		Description: "Exposed Bazaar repo"},

	// ---- Env / config ----
	{Path: "/.env", Category: "env", Severity: "critical",
		Description: ".env file — typically contains DB / API credentials",
		Confirm:     confirmEnvFile},
	{Path: "/.env.local", Category: "env", Severity: "critical",
		Description: ".env.local", Confirm: confirmEnvFile},
	{Path: "/.env.production", Category: "env", Severity: "critical",
		Description: ".env.production", Confirm: confirmEnvFile},
	{Path: "/config.json", Category: "config", Severity: "medium",
		Description: "config.json (may contain secrets)",
		Confirm:     confirmJSONy},
	{Path: "/config.yaml", Category: "config", Severity: "medium",
		Description: "config.yaml"},
	{Path: "/config.yml", Category: "config", Severity: "medium",
		Description: "config.yml"},
	{Path: "/web.config", Category: "config", Severity: "high",
		Description: "IIS web.config — connection strings often inside"},
	{Path: "/appsettings.json", Category: "config", Severity: "high",
		Description: ".NET appsettings.json — connection strings + secrets",
		Confirm:     confirmJSONy},

	// ---- OS / editor metadata ----
	{Path: "/.DS_Store", Category: "macos", Severity: "medium",
		Description: ".DS_Store — leaks file listing of the directory"},
	{Path: "/Thumbs.db", Category: "windows", Severity: "low",
		Description: "Thumbs.db — leaks image filenames"},

	// ---- Backups / archives ----
	{Path: "/backup.zip", Category: "backup", Severity: "high",
		Description: "Exposed backup.zip"},
	{Path: "/backup.tar.gz", Category: "backup", Severity: "high",
		Description: "Exposed backup.tar.gz"},
	{Path: "/backup.sql", Category: "backup", Severity: "critical",
		Description: "Exposed SQL dump"},
	{Path: "/db.sql", Category: "backup", Severity: "critical",
		Description: "Exposed db.sql"},
	{Path: "/database.sql", Category: "backup", Severity: "critical",
		Description: "Exposed database.sql"},
	{Path: "/dump.sql", Category: "backup", Severity: "critical",
		Description: "Exposed dump.sql"},
	{Path: "/wp-config.php.bak", Category: "backup", Severity: "critical",
		Description: "WordPress config backup with DB credentials"},
	{Path: "/wp-config.php~", Category: "backup", Severity: "critical",
		Description: "WordPress config backup (editor tilde)"},

	// ---- SSH / cloud creds ----
	{Path: "/.ssh/id_rsa", Category: "ssh", Severity: "critical",
		Description: "Exposed private SSH key",
		Confirm:     func(b string) bool { return strings.Contains(b, "BEGIN") && strings.Contains(b, "PRIVATE KEY") }},
	{Path: "/.aws/credentials", Category: "aws", Severity: "critical",
		Description: "Exposed AWS credentials file",
		Confirm: func(b string) bool {
			return strings.Contains(b, "aws_access_key_id") || strings.Contains(b, "[default]")
		}},
	{Path: "/.aws/config", Category: "aws", Severity: "high",
		Description: "Exposed AWS config file"},

	// ---- Discovery / sitemaps ----
	{Path: "/robots.txt", Category: "discovery", Severity: "info",
		Description: "robots.txt (informational, reveals disallowed paths)",
		Confirm: func(b string) bool {
			return strings.Contains(strings.ToLower(b), "user-agent") || strings.Contains(strings.ToLower(b), "disallow")
		}},
	{Path: "/sitemap.xml", Category: "discovery", Severity: "info",
		Description: "sitemap.xml (informational, reveals URL space)",
		Confirm:     func(b string) bool { return strings.Contains(b, "<urlset") || strings.Contains(b, "<sitemapindex") }},
	{Path: "/sitemap_index.xml", Category: "discovery", Severity: "info",
		Description: "sitemap_index.xml"},
	{Path: "/security.txt", Category: "discovery", Severity: "info",
		Description: "security.txt"},
	{Path: "/.well-known/security.txt", Category: "discovery", Severity: "info",
		Description: ".well-known/security.txt"},
	{Path: "/crossdomain.xml", Category: "discovery", Severity: "low",
		Description: "Flash crossdomain.xml — may be over-permissive"},
	{Path: "/clientaccesspolicy.xml", Category: "discovery", Severity: "low",
		Description: "Silverlight clientaccesspolicy.xml"},

	// ---- API / docs ----
	{Path: "/swagger.json", Category: "api", Severity: "medium",
		Description: "Swagger spec — full API surface", Confirm: confirmJSONy},
	{Path: "/swagger/v1/swagger.json", Category: "api", Severity: "medium",
		Description: "Swagger v1 spec", Confirm: confirmJSONy},
	{Path: "/swagger-ui.html", Category: "api", Severity: "medium",
		Description: "Swagger UI"},
	{Path: "/v2/api-docs", Category: "api", Severity: "medium",
		Description: "Swagger v2 api-docs"},
	{Path: "/v3/api-docs", Category: "api", Severity: "medium",
		Description: "Swagger v3 api-docs"},
	{Path: "/openapi.json", Category: "api", Severity: "medium",
		Description: "OpenAPI 3 spec", Confirm: confirmJSONy},
	{Path: "/graphql", Category: "api", Severity: "low",
		Description: "GraphQL endpoint"},

	// ---- Server-status / monitoring ----
	{Path: "/server-status", Category: "monitoring", Severity: "low",
		Description: "Apache mod_status"},
	{Path: "/server-info", Category: "monitoring", Severity: "low",
		Description: "Apache mod_info"},
	{Path: "/nginx_status", Category: "monitoring", Severity: "low",
		Description: "Nginx stub_status"},
	{Path: "/phpinfo.php", Category: "monitoring", Severity: "medium",
		Description: "phpinfo() dump — leaks PHP config + env"},
	{Path: "/info.php", Category: "monitoring", Severity: "medium",
		Description: "info.php"},
	{Path: "/test.php", Category: "monitoring", Severity: "low",
		Description: "test.php"},

	// ---- Spring Boot Actuator ----
	{Path: "/actuator", Category: "actuator", Severity: "low",
		Description: "Spring Boot actuator root"},
	{Path: "/actuator/health", Category: "actuator", Severity: "info",
		Description: "Spring Boot actuator health"},
	{Path: "/actuator/env", Category: "actuator", Severity: "high",
		Description: "Spring Boot /actuator/env — leaks application properties + secrets"},
	{Path: "/actuator/heapdump", Category: "actuator", Severity: "critical",
		Description: "Spring Boot heap dump — credentials in memory"},
	{Path: "/actuator/mappings", Category: "actuator", Severity: "low",
		Description: "Spring Boot /actuator/mappings — full route list"},
	{Path: "/actuator/loggers", Category: "actuator", Severity: "low",
		Description: "Spring Boot /actuator/loggers"},
	{Path: "/env", Category: "actuator", Severity: "high",
		Description: "Spring /env (pre-actuator)"},
	{Path: "/dump", Category: "actuator", Severity: "high",
		Description: "Spring /dump"},
	{Path: "/trace", Category: "actuator", Severity: "low",
		Description: "Spring /trace"},

	// ---- Admin / panel ----
	{Path: "/phpmyadmin/", Category: "admin", Severity: "low",
		Description: "phpMyAdmin"},
	{Path: "/admin/", Category: "admin", Severity: "info",
		Description: "/admin/ landing"},
	{Path: "/console/", Category: "admin", Severity: "low",
		Description: "/console/ landing (Weblogic / Druid / etc.)"},
	{Path: "/druid/index.html", Category: "admin", Severity: "medium",
		Description: "Druid monitor"},
	{Path: "/jolokia/list", Category: "admin", Severity: "medium",
		Description: "Jolokia JMX bridge"},
	{Path: "/_cat", Category: "admin", Severity: "medium",
		Description: "Elasticsearch _cat endpoint"},

	// ---- Project meta ----
	{Path: "/package.json", Category: "project", Severity: "info",
		Description: "package.json", Confirm: confirmJSONy},
	{Path: "/composer.json", Category: "project", Severity: "info",
		Description: "composer.json"},
	{Path: "/composer.lock", Category: "project", Severity: "info",
		Description: "composer.lock"},
	{Path: "/Gemfile.lock", Category: "project", Severity: "info",
		Description: "Gemfile.lock"},
	{Path: "/yarn.lock", Category: "project", Severity: "info",
		Description: "yarn.lock"},
}

// confirmEnvFile heuristically matches a dotenv body: at least one KEY=VAL
// line that doesn't look like HTML.
func confirmEnvFile(b string) bool {
	if strings.Contains(strings.ToLower(b), "<html") || strings.Contains(strings.ToLower(b), "<!doctype") {
		return false
	}
	for _, line := range strings.Split(b, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if eq := strings.IndexByte(line, '='); eq > 0 && eq < len(line)-1 {
			return true
		}
	}
	return false
}

// confirmJSONy checks the body looks like JSON (after stripping leading
// whitespace) — avoids false positives from SPA fallback HTML.
func confirmJSONy(b string) bool {
	t := strings.TrimLeft(b, " \t\r\n")
	if t == "" {
		return false
	}
	c := t[0]
	return c == '{' || c == '['
}
