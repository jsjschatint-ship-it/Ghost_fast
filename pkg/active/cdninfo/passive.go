package cdninfo

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	securityTrailsBase = "https://api.securitytrails.com/v1"
	virusTotalBase     = "https://www.virustotal.com/api/v3"
	hackerTargetBase   = "https://api.hackertarget.com"
	threatMinerBase    = "https://api.threatminer.org/v2"
)

func passiveOriginCandidates(ctx context.Context, client *http.Client, root string, frontIPs []string, cfg *Config) []*OriginCandidate {
	front := make(map[string]struct{}, len(frontIPs))
	for _, ip := range frontIPs {
		front[ip] = struct{}{}
	}
	seen := map[string]struct{}{}
	var out []*OriginCandidate
	add := func(source, label, note string, ips []string) {
		label = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(label)), ".")
		if label == "" {
			label = root
		}
		fresh := make([]string, 0, len(ips))
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if net.ParseIP(ip) == nil {
				continue
			}
			if _, ok := front[ip]; !ok {
				fresh = appendUniqueString(fresh, ip)
			}
		}
		if len(fresh) == 0 {
			return
		}
		key := source + "|" + label + "|" + strings.Join(fresh, ",")
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, &OriginCandidate{Source: source, Label: label, IPs: fresh, Note: note})
	}

	for _, src := range normalizedPassiveSources(cfg.PassiveSources) {
		if len(out) >= cfg.MaxPassiveRecords {
			break
		}
		switch src {
		case "securitytrails":
			if cfg.SecurityTrailsKey == "" {
				continue
			}
			for _, c := range querySecurityTrailsPassive(ctx, client, root, cfg.SecurityTrailsKey, cfg.UserAgent, cfg.MaxPassiveRecords-len(out)) {
				add(c.Source, c.Label, c.Note, c.IPs)
			}
		case "virustotal":
			if cfg.VirusTotalKey == "" {
				continue
			}
			for _, c := range queryVirusTotalPassive(ctx, client, root, cfg.VirusTotalKey, cfg.UserAgent, cfg.MaxPassiveRecords-len(out)) {
				add(c.Source, c.Label, c.Note, c.IPs)
			}
		case "threatminer":
			for _, c := range queryThreatMinerPassive(ctx, client, root, cfg.UserAgent, cfg.MaxPassiveRecords-len(out)) {
				add(c.Source, c.Label, c.Note, c.IPs)
			}
		case "hackertarget":
			for _, c := range queryHackerTargetPassive(ctx, client, root, cfg.UserAgent, cfg.MaxPassiveRecords-len(out)) {
				add(c.Source, c.Label, c.Note, c.IPs)
			}
		}
	}
	return out
}

func normalizedPassiveSources(in []string) []string {
	if len(in) == 0 {
		return []string{"securitytrails", "virustotal", "threatminer", "hackertarget"}
	}
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.ReplaceAll(s, "_", "")
		s = strings.ReplaceAll(s, "-", "")
		switch s {
		case "securitytrails", "st":
			s = "securitytrails"
		case "virustotal", "vt":
			s = "virustotal"
		case "threatminer", "tm":
			s = "threatminer"
		case "hackertarget", "ht":
			s = "hackertarget"
		default:
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func querySecurityTrailsPassive(ctx context.Context, client *http.Client, root, key, userAgent string, limit int) []*OriginCandidate {
	if limit <= 0 {
		return nil
	}
	var out []*OriginCandidate
	currentURL := fmt.Sprintf("%s/domain/%s", securityTrailsBase, url.PathEscape(root))
	if body, ok := fetchJSON(ctx, client, currentURL, map[string]string{"APIKEY": key, "User-Agent": userAgent}); ok {
		for _, rec := range gjson.GetBytes(body, "current_dns.a.values").Array() {
			ip := rec.Get("ip").String()
			if ip != "" {
				out = append(out, &OriginCandidate{Source: "securitytrails_current", Label: root, IPs: []string{ip}, Note: "SecurityTrails current A"})
			}
			if len(out) >= limit {
				return out
			}
		}
	}
	historyURL := fmt.Sprintf("%s/history/%s/dns/a", securityTrailsBase, url.PathEscape(root))
	if body, ok := fetchJSON(ctx, client, historyURL, map[string]string{"APIKEY": key, "User-Agent": userAgent}); ok {
		for _, rec := range gjson.GetBytes(body, "records").Array() {
			first := rec.Get("first_seen").String()
			last := rec.Get("last_seen").String()
			note := "SecurityTrails historical A"
			if first != "" || last != "" {
				note = strings.TrimSpace(note + " " + first + ".." + last)
			}
			for _, v := range rec.Get("values").Array() {
				ip := v.Get("ip").String()
				if ip == "" {
					continue
				}
				out = append(out, &OriginCandidate{Source: "securitytrails_history", Label: root, IPs: []string{ip}, Note: note})
				if len(out) >= limit {
					return out
				}
			}
		}
	}
	return out
}

func queryVirusTotalPassive(ctx context.Context, client *http.Client, root, key, userAgent string, limit int) []*OriginCandidate {
	if limit <= 0 {
		return nil
	}
	u := fmt.Sprintf("%s/domains/%s/resolutions?limit=%d", virusTotalBase, url.PathEscape(root), limit)
	body, ok := fetchJSON(ctx, client, u, map[string]string{"x-apikey": key, "User-Agent": userAgent})
	if !ok {
		return nil
	}
	var out []*OriginCandidate
	for _, item := range gjson.GetBytes(body, "data").Array() {
		attr := item.Get("attributes")
		ip := attr.Get("ip_address").String()
		host := attr.Get("host_name").String()
		date := attr.Get("date").String()
		if ip == "" {
			continue
		}
		note := "VirusTotal domain resolution"
		if date != "" {
			note += " " + date
		}
		if host == "" {
			host = root
		}
		out = append(out, &OriginCandidate{Source: "virustotal_history", Label: host, IPs: []string{ip}, Note: note})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func queryThreatMinerPassive(ctx context.Context, client *http.Client, root, userAgent string, limit int) []*OriginCandidate {
	if limit <= 0 {
		return nil
	}
	u := fmt.Sprintf("%s/domain.php?q=%s&rt=2", threatMinerBase, url.QueryEscape(root))
	body, ok := fetchJSON(ctx, client, u, map[string]string{"User-Agent": userAgent})
	if !ok {
		return nil
	}
	return threatMinerCandidates(root, string(body), limit)
}

func threatMinerCandidates(root, body string, limit int) []*OriginCandidate {
	var out []*OriginCandidate
	for _, item := range gjson.Get(body, "results").Array() {
		var host, ip string
		if item.IsObject() {
			host = firstNonEmpty(item.Get("domain").String(), item.Get("host").String(), item.Get("hostname").String(), root)
			ip = firstNonEmpty(item.Get("ip").String(), item.Get("ip_address").String(), item.Get("address").String())
		} else {
			v := strings.TrimSpace(item.String())
			if net.ParseIP(v) != nil {
				ip = v
				host = root
			}
		}
		if ip == "" {
			continue
		}
		out = append(out, &OriginCandidate{Source: "threatminer_pdns", Label: host, IPs: []string{ip}, Note: "ThreatMiner passive DNS"})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func queryHackerTargetPassive(ctx context.Context, client *http.Client, root, userAgent string, limit int) []*OriginCandidate {
	if limit <= 0 {
		return nil
	}
	u := fmt.Sprintf("%s/hostsearch/?q=%s", hackerTargetBase, url.QueryEscape(root))
	body, ok := fetchPlain(ctx, client, u, map[string]string{"User-Agent": userAgent})
	if !ok {
		return nil
	}
	return hackerTargetCandidates(string(body), limit)
}

func hackerTargetCandidates(body string, limit int) []*OriginCandidate {
	var out []*OriginCandidate
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "error") || strings.HasPrefix(strings.ToLower(line), "api count exceeded") {
			continue
		}
		host, ip, ok := strings.Cut(line, ",")
		if !ok {
			continue
		}
		host = strings.TrimSpace(host)
		ip = strings.TrimSpace(ip)
		if host == "" || net.ParseIP(ip) == nil {
			continue
		}
		out = append(out, &OriginCandidate{Source: "hackertarget_hostsearch", Label: host, IPs: []string{ip}, Note: "HackerTarget hostsearch"})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func fetchJSON(ctx context.Context, client *http.Client, u string, headers map[string]string) ([]byte, bool) {
	body, ok := fetchPlain(ctx, client, u, headers)
	if !ok || !gjson.ValidBytes(body) {
		return nil, false
	}
	return body, true
}

func fetchPlain(ctx context.Context, client *http.Client, u string, headers map[string]string) ([]byte, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, false
	}
	for k, v := range headers {
		if strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, false
	}
	return body, true
}

func appendUniqueString(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
