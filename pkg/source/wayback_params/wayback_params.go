// Package wayback_params 从 Wayback Machine 历史 URL 中抽取 query string 参数，
// 分类标注高危参数（sqli/ssrf/lfi/rce/xss/auth/ssti/xxe/openredir），
// 生成 fuzz 输入清单。完全被动，不接触目标。
package wayback_params

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const cdxURL = "http://web.archive.org/cdx/search/cdx"

// 高危参数分类（按 OWASP Top10 攻击面分组）
var riskPatterns = []struct {
	Kind string
	Re   *regexp.Regexp
}{
	{"sqli", regexp.MustCompile(`(?i)^(id|user|uid|pid|product|item|cat|category|type|order|sort|page|num|limit|count)$`)},
	{"ssrf", regexp.MustCompile(`(?i)^(url|uri|link|src|callback|target|return|redirect|next|continue|dest|destination|host|domain|fetch|proxy|via|origin)$`)},
	{"lfi", regexp.MustCompile(`(?i)^(file|filename|path|dir|folder|template|page|include|require|load|read|view|doc|document|attachment)$`)},
	{"rce", regexp.MustCompile(`(?i)^(cmd|exec|command|run|action|do|shell|code|eval|func|method|operation|task|process)$`)},
	{"xss", regexp.MustCompile(`(?i)^(q|search|query|keyword|kw|s|term|text|content|message|msg|comment|name|title|description|desc)$`)},
	{"auth", regexp.MustCompile(`(?i)^(token|jwt|session|sid|sess|auth|key|api_key|apikey|access_token|secret|password|pwd|hash|sign|signature)$`)},
	{"ssti", regexp.MustCompile(`(?i)^(template|view|tpl|theme|layout|render|format)$`)},
	{"xxe", regexp.MustCompile(`(?i)^(xml|data|payload|input|body)$`)},
	{"openredir", regexp.MustCompile(`(?i)^(redirect|redir|url|next|return|returnto|return_to|continue|forward|goto|to|target)$`)},
}

func classifyParam(name string) []string {
	var kinds []string
	for _, p := range riskPatterns {
		if p.Re.MatchString(name) {
			kinds = append(kinds, p.Kind)
		}
	}
	return kinds
}

// WaybackParams 数据源
type WaybackParams struct {
	*source.BaseSource
	client     *req.Client
	maxURLs    int
	outDir     string
	writeFiles bool
}

func NewWaybackParams() *WaybackParams {
	return &WaybackParams{
		BaseSource: source.NewBaseSource("wayback_params"),
		client:     req.C().SetTimeout(180 * time.Second).SetUserAgent("PassiveRecon/1.0"),
		maxURLs:    5000,
		outDir:     "data/wayback_params",
		writeFiles: true,
	}
}

func (s *WaybackParams) Accepts() []string { return []string{"domain"} }
func (s *WaybackParams) NeedsKey() bool    { return false }

func (s *WaybackParams) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	if v, ok := cfg["max_urls"].(int); ok && v > 0 {
		s.maxURLs = v
	}
	if v, ok := cfg["out_dir"].(string); ok && v != "" {
		s.outDir = v
	}
	if v, ok := cfg["write_files"].(bool); ok {
		s.writeFiles = v
	}
	if v, ok := cfg["proxy"].(string); ok && v != "" {
		s.client.SetProxyURL(v)
	}
	if v, ok := cfg["timeout"].(int); ok && v > 0 {
		s.client.SetTimeout(time.Duration(v) * time.Second)
	}
	return nil
}

type paramStat struct {
	Count       int
	Risks       map[string]bool
	SampleURL   string
	SampleValue string
	FirstTS     string
	LastTS      string
}

func (s *WaybackParams) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(target)), ".")
	if domain == "" {
		return nil, nil
	}

	// CDX 查询：原 Python 通过重复 filter= 参数表达多个 filter
	req := s.client.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"url":      "*." + domain + "/*",
			"output":   "json",
			"fl":       "original,timestamp",
			"collapse": "urlkey",
			"limit":    fmt.Sprintf("%d", s.maxURLs),
		}).
		AddQueryParam("filter", "statuscode:200").
		AddQueryParam("filter", "original:.*\\?.+")
	resp, err := req.Get(cdxURL)
	if err != nil {
		// 透传 err 由 smoke/runner 正确分类为 timeout/dial，而不是伪造 "ok" asset
		return nil, fmt.Errorf("wayback CDX: %w", err)
	}
	if resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
		return nil, nil // Wayback CDX 偶发可用性问题，视为空
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback CDX status %d", resp.StatusCode)
	}

	body := resp.String()
	rows := gjson.Parse(body).Array()
	if len(rows) <= 1 {
		return nil, nil
	}

	stats := map[string]*paramStat{}
	var seenURLs []string

	for _, r := range rows[1:] {
		arr := r.Array()
		if len(arr) < 2 {
			continue
		}
		urlStr := arr[0].String()
		ts := arr[1].String()
		if !strings.Contains(urlStr, "?") {
			continue
		}
		u, err := url.Parse(urlStr)
		if err != nil || u.RawQuery == "" {
			continue
		}
		seenURLs = append(seenURLs, urlStr)
		values, _ := url.ParseQuery(u.RawQuery)
		for k, vs := range values {
			if k == "" || len(k) > 60 {
				continue
			}
			low := strings.ToLower(k)
			st, ok := stats[low]
			if !ok {
				st = &paramStat{Risks: map[string]bool{}}
				stats[low] = st
			}
			st.Count++
			for _, risk := range classifyParam(k) {
				st.Risks[risk] = true
			}
			if st.SampleURL == "" {
				st.SampleURL = urlStr
				sv := ""
				if len(vs) > 0 {
					sv = vs[0]
				}
				if len(sv) > 80 {
					sv = sv[:80]
				}
				st.SampleValue = sv
				st.FirstTS = ts
			}
			st.LastTS = ts
		}
	}

	// 写产物
	var filesWritten []string
	if s.writeFiles && len(stats) > 0 {
		if err := os.MkdirAll(s.outDir, 0755); err == nil {
			paramFile := filepath.Join(s.outDir, domain+".txt")
			urlsFile := filepath.Join(s.outDir, domain+".urls")
			riskyFile := filepath.Join(s.outDir, domain+".risky.urls")

			var names []string
			for n := range stats {
				names = append(names, n)
			}
			sort.Strings(names)
			_ = os.WriteFile(paramFile, []byte(strings.Join(names, "\n")+"\n"), 0644)

			// 去重 URL
			uniq := map[string]bool{}
			var urlsList []string
			for _, u := range seenURLs {
				if !uniq[u] {
					uniq[u] = true
					urlsList = append(urlsList, u)
				}
			}
			sort.Strings(urlsList)
			_ = os.WriteFile(urlsFile, []byte(strings.Join(urlsList, "\n")+"\n"), 0644)

			// 仅含高危参数的 URL（喂 sqlmap）
			var risky []string
			for _, u := range seenURLs {
				pu, err := url.Parse(u)
				if err != nil {
					continue
				}
				vals, _ := url.ParseQuery(pu.RawQuery)
				risk := false
				for k := range vals {
					if len(classifyParam(k)) > 0 {
						risk = true
						break
					}
				}
				if risk {
					risky = append(risky, u)
				}
			}
			_ = os.WriteFile(riskyFile, []byte(strings.Join(risky, "\n")+"\n"), 0644)

			filesWritten = []string{paramFile, urlsFile, riskyFile}
		}
	}

	// 转 Asset，按 count 倒序
	type kv struct {
		name string
		st   *paramStat
	}
	list := make([]kv, 0, len(stats))
	for k, v := range stats {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].st.Count > list[j].st.Count })

	var out []*models.Asset
	for _, p := range list {
		risks := make([]string, 0, len(p.st.Risks))
		for r := range p.st.Risks {
			risks = append(risks, r)
		}
		sort.Strings(risks)
		tags := []string{"wayback-param", "param:" + p.name, fmt.Sprintf("count:%d", p.st.Count)}
		for _, r := range risks {
			tags = append(tags, "risk:"+r)
		}
		if len(risks) > 0 {
			tags = append(tags, "high-value")
		}
		risksStr := strings.Join(risks, ",")
		if risksStr == "" {
			risksStr = "-"
		}
		sv := p.st.SampleValue
		if len(sv) > 30 {
			sv = sv[:30]
		}
		ts := p.st.LastTS
		if len(ts) > 8 {
			ts = ts[:8]
		}
		a := models.NewAsset().
			WithTitle(fmt.Sprintf("[wb-param] %s=%s  ×%d  %s", p.name, sv, p.st.Count, risksStr)).
			WithURL(p.st.SampleURL).
			WithDomain(domain).
			WithSource("wayback_params").
			WithUpdateTime(ts).
			WithTags(tags...)
		a.WithRaw("param", p.name).
			WithRaw("count", fmt.Sprintf("%d", p.st.Count)).
			WithRaw("risks", strings.Join(risks, ",")).
			WithRaw("sample_url", p.st.SampleURL).
			WithRaw("first_ts", p.st.FirstTS).
			WithRaw("last_ts", p.st.LastTS)
		a.Normalize()
		out = append(out, a)
	}

	// 一条 summary
	if len(filesWritten) > 0 {
		sum := models.NewAsset().
			WithTitle(fmt.Sprintf("[wb-param] 📁 已写出 %d 参数 / %d URL → %s",
				len(stats), len(seenURLs), s.outDir)).
			WithSource("wayback_params").
			WithTags("wayback-param", "summary").
			WithRaw("param_count", fmt.Sprintf("%d", len(stats))).
			WithRaw("url_count", fmt.Sprintf("%d", len(seenURLs))).
			WithRaw("files", strings.Join(filesWritten, ";"))
		out = append(out, sum)
	}
	return out, nil
}
