package dnsrecord

import (
	"regexp"
	"strings"
)

// tokenRule recognises a TXT-record verification fingerprint.
type tokenRule struct {
	Provider string
	Type     string
	// Match is a substring (case-insensitive) — fast path. If Re is non-nil,
	// it must also match (and supplies the captured token via group 1).
	Match string
	Re    *regexp.Regexp
}

// tokenRules covers the highest-value SaaS verification beacons. Each TXT
// record from the domain is tested against the full list.
var tokenRules = []tokenRule{
	// ---------- Source-control / dev ----------
	{Provider: "github", Type: "site_verification",
		Match: "github-verification-",
		Re:    regexp.MustCompile(`(?i)github-verification[-=]([A-Za-z0-9_\-]+)`)},
	{Provider: "github", Type: "pages_verification",
		Match: "_github-challenge-",
		Re:    regexp.MustCompile(`(?i)_github-challenge-([A-Za-z0-9_\-]+)`)},
	{Provider: "gitlab", Type: "verification",
		Match: "gitlab-verification=",
		Re:    regexp.MustCompile(`(?i)gitlab-verification=([A-Za-z0-9_\-]+)`)},

	// ---------- Google / Microsoft / Apple ----------
	{Provider: "google_workspace", Type: "site_verification",
		Match: "google-site-verification=",
		Re:    regexp.MustCompile(`(?i)google-site-verification=([A-Za-z0-9_\-]+)`)},
	{Provider: "google_workspace", Type: "spf_include",
		Match: "_spf.google.com"},
	{Provider: "microsoft_365", Type: "domain_verification",
		Match: "ms=ms",
		Re:    regexp.MustCompile(`(?i)\bms=ms(\d+)\b`)},
	{Provider: "microsoft_365", Type: "spf_include",
		Match: "spf.protection.outlook.com"},
	{Provider: "apple", Type: "domain_verification",
		Match: "apple-domain-verification=",
		Re:    regexp.MustCompile(`(?i)apple-domain-verification=([A-Za-z0-9_\-]+)`)},

	// ---------- AWS ----------
	{Provider: "aws_ses", Type: "amazonses_dkim_or_verification",
		Match: "amazonses:",
		Re:    regexp.MustCompile(`(?i)amazonses:([A-Za-z0-9+/=]+)`)},
	{Provider: "aws_ses", Type: "spf_include",
		Match: "amazonses.com"},
	{Provider: "aws_acm", Type: "validation",
		Match: "_acme-challenge"}, // ACM/Let's Encrypt; provider context follows from CNAME

	// ---------- Atlassian / Slack / Zoom / Notion ----------
	{Provider: "atlassian", Type: "site_verification",
		Match: "atlassian-domain-verification=",
		Re:    regexp.MustCompile(`(?i)atlassian-domain-verification=([A-Za-z0-9_\-]+)`)},
	{Provider: "slack", Type: "site_verification",
		Match: "slack-domain-verification=",
		Re:    regexp.MustCompile(`(?i)slack-domain-verification=([A-Za-z0-9_\-]+)`)},
	{Provider: "zoom", Type: "verification",
		Match: "zoomverify=",
		Re:    regexp.MustCompile(`(?i)zoomverify=([A-Za-z0-9_\-]+)`)},
	{Provider: "notion", Type: "verification",
		Match: "notion-domain-verification=",
		Re:    regexp.MustCompile(`(?i)notion-domain-verification=([A-Za-z0-9_\-]+)`)},
	{Provider: "miro", Type: "verification",
		Match: "miro-verification="},
	{Provider: "figma", Type: "verification",
		Match: "figma-domain-verification="},

	// ---------- Marketing / analytics ----------
	{Provider: "hubspot", Type: "site_verification",
		Match: "hubspot-developer-verification="},
	{Provider: "mailchimp", Type: "spf_include",
		Match: "servers.mcsv.net"},
	{Provider: "sendgrid", Type: "spf_include",
		Match: "sendgrid.net"},
	{Provider: "mailgun", Type: "spf_include",
		Match: "mailgun.org"},
	{Provider: "stripe", Type: "verification",
		Match: "stripe-verification="},
	{Provider: "intercom", Type: "verification",
		Match: "intercom-verification-"},
	{Provider: "facebook", Type: "domain_verification",
		Match: "facebook-domain-verification=",
		Re:    regexp.MustCompile(`(?i)facebook-domain-verification=([A-Za-z0-9_\-]+)`)},
	{Provider: "linkedin", Type: "verification",
		Match: "linkedin-verification="},

	// ---------- 国内常用 SaaS ----------
	{Provider: "dingtalk", Type: "domain_verification",
		Match: "dingtalk-site-verification=",
		Re:    regexp.MustCompile(`(?i)dingtalk-site-verification=([A-Za-z0-9_\-]+)`)},
	{Provider: "feishu", Type: "domain_verification",
		Match: "lark-domain-verification=",
		Re:    regexp.MustCompile(`(?i)lark-domain-verification=([A-Za-z0-9_\-]+)`)},
	{Provider: "feishu_alt", Type: "domain_verification",
		Match: "feishu-domain-verification="},
	{Provider: "wechat_work", Type: "domain_verification",
		Match: "wxwork-site-verification="},
	{Provider: "aliyun", Type: "domain_verification",
		Match: "aliyun-site-verification="},
	{Provider: "aliyun_directmail", Type: "spf_include",
		Match: "spf1.dm.aliyun.com"},
	{Provider: "tencent_cloud", Type: "domain_verification",
		Match: "qcloud-site-verification="},
	{Provider: "tencent_exmail", Type: "spf_include",
		Match: "spf.mail.qq.com"},
	{Provider: "163_qiyemail", Type: "spf_include",
		Match: "qiye.163.com"},
	{Provider: "baidu", Type: "site_verification",
		Match: "baidu-site-verification="},

	// ---------- DNS / CDN / sec ----------
	{Provider: "cloudflare", Type: "domain_verification",
		Match: "cloudflare-verify."},
	{Provider: "fastly", Type: "tls_validation",
		Match: "fastly"},
	{Provider: "akamai", Type: "validation",
		Match: "akamai"},
	{Provider: "letsencrypt", Type: "validation",
		Match: "_acme-challenge"},
}

// classifyTXT runs every rule against a TXT body and yields all matches.
// A single record can yield multiple hits (e.g. an SPF record that includes
// google + sendgrid + aws). Output is deduped by provider+type.
func classifyTXT(txt string) []*TokenMatch {
	low := strings.ToLower(txt)
	seen := map[string]struct{}{}
	var out []*TokenMatch
	for _, ru := range tokenRules {
		if !strings.Contains(low, strings.ToLower(ru.Match)) {
			continue
		}
		key := ru.Provider + "|" + ru.Type
		if _, ok := seen[key]; ok {
			continue
		}
		m := &TokenMatch{Provider: ru.Provider, Type: ru.Type, Raw: txt}
		if ru.Re != nil {
			if g := ru.Re.FindStringSubmatch(txt); len(g) >= 2 {
				m.Value = g[1]
			}
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}
