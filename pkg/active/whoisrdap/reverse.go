package whoisrdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var reverseWhoisDomainRe = regexp.MustCompile(`(?i)<tr><td>([a-z0-9][a-z0-9_.-]*\.[a-z]{2,})</td>`)

func reverseWhoisSiblings(ctx context.Context, client *http.Client, pivot string, cfg *Config) []*SiblingDomain {
	pivot = strings.TrimSpace(strings.ToLower(pivot))
	if pivot == "" || cfg.MaxSiblingDomains <= 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []*SiblingDomain
	add := func(domain, source string) {
		domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), ".")
		if domain == "" || !strings.Contains(domain, ".") || strings.Contains(domain, "@") {
			return
		}
		if _, ok := seen[domain]; ok {
			return
		}
		seen[domain] = struct{}{}
		out = append(out, &SiblingDomain{Domain: domain, Source: source, Pivot: pivot})
	}
	if cfg.ReverseWhoisKey != "" {
		for _, d := range queryWhoisXMLReverse(ctx, client, pivot, cfg.ReverseWhoisKey, cfg.MaxSiblingDomains) {
			add(d, "whoisxmlapi")
			if len(out) >= cfg.MaxSiblingDomains {
				return out
			}
		}
	}
	for _, d := range queryViewDNSReverse(ctx, client, pivot, cfg.MaxSiblingDomains-len(out)) {
		add(d, "viewdns")
		if len(out) >= cfg.MaxSiblingDomains {
			return out
		}
	}
	return out
}

func queryWhoisXMLReverse(ctx context.Context, client *http.Client, pivot, key string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	q := url.Values{}
	q.Set("apiKey", key)
	q.Set("searchType", "current")
	q.Set("mode", "purchase")
	q.Set("punycode", "true")
	q.Set("basicSearchTerms", pivot)
	u := "https://reverse-whois.whoisxmlapi.com/api/v2?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil
	}
	return parseWhoisXMLDomains(data, limit)
}

func parseWhoisXMLDomains(data []byte, limit int) []string {
	var payload struct {
		DomainsList []string `json:"domainsList"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	out := make([]string, 0, len(payload.DomainsList))
	for _, d := range payload.DomainsList {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		out = append(out, d)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func queryViewDNSReverse(ctx context.Context, client *http.Client, pivot string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	u := fmt.Sprintf("https://viewdns.info/reversewhois/?q=%s", url.QueryEscape(pivot))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil
	}
	return parseViewDNSDomains(string(data), limit)
}

func parseViewDNSDomains(body string, limit int) []string {
	matches := reverseWhoisDomainRe.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		d := strings.Trim(strings.ToLower(m[1]), ".")
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
		if len(out) >= limit {
			break
		}
	}
	return out
}
