package whois_reverse

// Reverse WHOIS - 按 registrant 反查所有关联域。
// 两条路径：
//   1) viewdns.info/reversewhois HTML 解析（免 key 但限速）
//   2) whoisxmlapi.com Reverse WHOIS API（需 key，500 次/月免费 trial）
//
// 输入：完整 owner 字符串（公司英文名 / 邮箱 / 手机）。
// 若传入像域名的 target，会先走 RDAP 拿 registrant 再反查。
//
import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

var domainRowRe = regexp.MustCompile(`<tr><td>([\w.\-]+\.[a-zA-Z]{2,})</td>`)

type WhoisReverse struct {
	*source.BaseSource
	client *req.Client
}

func NewWhoisReverse() *WhoisReverse {
	return &WhoisReverse{
		BaseSource: source.NewBaseSource("whois_reverse"),
		client:     req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0"),
	}
}

func (s *WhoisReverse) Name() string      { return s.BaseSource.Name() }
func (s *WhoisReverse) Accepts() []string { return []string{"domain", "email", "company"} }
func (s *WhoisReverse) NeedsKey() bool    { return false } // viewdns 路径免 key

// configString helper
func (s *WhoisReverse) configString(k string) string {
	c := s.BaseSource.Config()
	if c == nil {
		return ""
	}
	if v, ok := c[k].(string); ok {
		return v
	}
	return ""
}

func (s *WhoisReverse) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{MaxAssets: 1000}
	for _, opt := range opts {
		opt(cfg)
	}
	owner := s.configString("owner")
	if owner == "" {
		owner = target
	}
	if owner == "" {
		return nil, nil
	}
	// 如果看着像域名，先走 RDAP 拿 registrant
	if strings.Contains(owner, ".") && !strings.Contains(owner, " ") && !strings.Contains(owner, "@") {
		if name := s.lookupRegistrant(ctx, owner); name != "" {
			owner = name
		}
	}

	key := s.BaseSource.Key()
	var domains []string
	if key != "" {
		domains = s.queryWhoisXML(ctx, owner, key)
	}
	if len(domains) == 0 {
		domains = s.queryViewDNS(ctx, owner)
	}

	out := make([]*models.Asset, 0, len(domains))
	seen := map[string]struct{}{}
	ownerTag := owner
	if len(ownerTag) > 60 {
		ownerTag = ownerTag[:60]
	}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		a := models.NewAsset().
			WithDomain(d).WithHost(d).WithOrg(owner).
			WithSource(s.Name()).
			WithTags("reverse-whois", "owner:"+ownerTag)
		out = append(out, a)
		if cfg.MaxAssets > 0 && len(out) >= cfg.MaxAssets {
			break
		}
	}
	return out, nil
}

// lookupRegistrant 用 rdap.org 查找 registrant fn
func (s *WhoisReverse) lookupRegistrant(ctx context.Context, domain string) string {
	resp, err := s.client.R().
		SetContext(ctx).
		Get("https://rdap.org/domain/" + domain)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	entities := gjson.Parse(resp.String()).Get("entities").Array()
	for _, ent := range entities {
		vcard := ent.Get("vcardArray").Array()
		if len(vcard) < 2 {
			continue
		}
		fields := vcard[1].Array()
		for _, f := range fields {
			arr := f.Array()
			if len(arr) >= 4 && arr[0].String() == "fn" {
				name := arr[len(arr)-1].String()
				if len(name) > 2 {
					return name
				}
			}
		}
	}
	return ""
}

// queryWhoisXML 调用 whoisxmlapi 的反查 API
func (s *WhoisReverse) queryWhoisXML(ctx context.Context, owner, key string) []string {
	resp, err := s.client.R().
		SetContext(ctx).
		SetQueryParams(map[string]string{
			"apiKey":           key,
			"searchType":       "current",
			"mode":             "purchase",
			"punycode":         "true",
			"basicSearchTerms": owner,
		}).
		Get("https://reverse-whois.whoisxmlapi.com/api/v2")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	out := []string{}
	for _, d := range gjson.Parse(resp.String()).Get("domainsList").Array() {
		out = append(out, d.String())
	}
	return out
}

// queryViewDNS 解析 viewdns.info/reversewhois HTML
func (s *WhoisReverse) queryViewDNS(ctx context.Context, owner string) []string {
	resp, err := s.client.R().
		SetContext(ctx).
		SetQueryParam("q", owner).
		Get("https://viewdns.info/reversewhois/")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	matches := domainRowRe.FindAllStringSubmatch(resp.String(), -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			out = append(out, m[1])
		}
	}
	return out
}

// 占位，避免 unused import 警告
var _ = fmt.Sprintf
var _ = time.Second
