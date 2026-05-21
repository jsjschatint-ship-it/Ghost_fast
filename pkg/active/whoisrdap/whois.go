package whoisrdap

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// tldWhois lists the canonical whois server for popular TLDs. Many TLD
// registries publish their own; we delegate everything else to IANA's
// whois.iana.org for the referral.
var tldWhois = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.publicinterestregistry.org",
	"io":   "whois.nic.io",
	"co":   "whois.nic.co",
	"ai":   "whois.nic.ai",
	"app":  "whois.nic.google",
	"dev":  "whois.nic.google",
	"xyz":  "whois.nic.xyz",
	"cn":   "whois.cnnic.cn",
	"jp":   "whois.jprs.jp",
	"uk":   "whois.nic.uk",
	"de":   "whois.denic.de",
	"fr":   "whois.nic.fr",
	"ru":   "whois.tcinet.ru",
	"info": "whois.afilias.net",
	"biz":  "whois.biz",
	"us":   "whois.nic.us",
	"top":  "whois.nic.top",
	"site": "whois.nic.site",
	"club": "whois.nic.club",
	"shop": "whois.nic.shop",
}

// whoisFor returns the WHOIS plaintext for `domain` (or IP). For IPs we go
// through whois.arin.net which transparently refers to the right RIR.
// For domains we use the per-TLD map with whois.iana.org fallback.
func whoisFor(ctx context.Context, query string, timeout time.Duration) (string, string, error) {
	server := pickWhoisServer(query)
	body, err := whoisQuery(ctx, server, query, timeout)
	if err != nil {
		return server, "", err
	}
	// Some servers respond with a referral ("Registrar WHOIS Server:
	// whois.markmonitor.com") — chase one level.
	if ref := extractReferral(body); ref != "" && ref != server {
		body2, err2 := whoisQuery(ctx, ref, query, timeout)
		if err2 == nil && len(body2) > 50 {
			return ref, body2, nil
		}
	}
	return server, body, nil
}

func pickWhoisServer(query string) string {
	if net.ParseIP(query) != nil {
		return "whois.arin.net"
	}
	// Multi-level TLDs first (e.g. com.cn → cnnic).
	low := strings.ToLower(strings.Trim(query, "."))
	if strings.HasSuffix(low, ".com.cn") || strings.HasSuffix(low, ".net.cn") || strings.HasSuffix(low, ".org.cn") {
		return "whois.cnnic.cn"
	}
	if strings.HasSuffix(low, ".co.uk") || strings.HasSuffix(low, ".org.uk") {
		return "whois.nic.uk"
	}
	if i := strings.LastIndexByte(low, '.'); i >= 0 {
		tld := low[i+1:]
		if s, ok := tldWhois[tld]; ok {
			return s
		}
	}
	return "whois.iana.org"
}

// whoisQuery opens a TCP/43 connection, sends `query\r\n`, and reads until
// EOF. Most public whois servers honour this exact protocol.
func whoisQuery(ctx context.Context, server, query string, timeout time.Duration) (string, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", server+":43")
	if err != nil {
		return "", fmt.Errorf("whois dial %s: %w", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	br := bufio.NewReader(conn)
	body, err := io.ReadAll(br)
	if err != nil && len(body) == 0 {
		return "", err
	}
	return string(body), nil
}

var referralRe = regexp.MustCompile(`(?i)(?:Registrar WHOIS Server|whois server|refer)\s*:\s*([A-Za-z0-9.\-]+)`)

// extractReferral pulls the registrar's WHOIS server out of a referral body.
func extractReferral(body string) string {
	m := referralRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(strings.ToLower(m[1]))
}

// parseWhoisFields runs a small set of field extractors on a WHOIS body.
// Output is whatever's confidently parseable — never returns an error;
// missing fields are simply absent from the Record.
func parseWhoisFields(body string) parsed {
	p := parsed{}
	lines := strings.Split(body, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		colon := strings.IndexByte(line, ':')
		if colon < 1 || colon == len(line)-1 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		if val == "" {
			continue
		}
		switch {
		case key == "registrar" || key == "sponsoring registrar" || strings.HasPrefix(key, "registrar:"):
			if p.Registrar == "" {
				p.Registrar = val
			}
		case key == "registrar url":
			if p.RegistrarURL == "" {
				p.RegistrarURL = val
			}
		case key == "creation date" || key == "created" || key == "registered" || key == "registered on":
			if p.Created == "" {
				p.Created = val
			}
		case key == "updated date" || key == "last updated" || key == "last modified":
			if p.Updated == "" {
				p.Updated = val
			}
		case key == "registry expiry date" || key == "registrar registration expiration date" ||
			key == "expiry date" || key == "expiration date" || key == "expires":
			if p.Expires == "" {
				p.Expires = val
			}
		case key == "name server" || key == "nserver":
			p.Nameservers = appendUnique(p.Nameservers, strings.ToLower(val))
		case key == "domain status":
			p.Status = appendUnique(p.Status, val)
		case key == "registrant email" || key == "registrant contact email":
			p.RegistrantEmail = strings.ToLower(val)
		case key == "registrant name":
			p.RegistrantName = val
		case key == "registrant organization" || key == "registrant org" || key == "registrant":
			if p.RegistrantOrg == "" {
				p.RegistrantOrg = val
			}
		case key == "registrant country":
			p.RegistrantCountry = val
		case key == "admin email":
			p.AdminEmail = strings.ToLower(val)
		case key == "tech email":
			p.TechEmail = strings.ToLower(val)
		}
	}
	return p
}

type parsed struct {
	Registrar         string
	RegistrarURL      string
	Created           string
	Updated           string
	Expires           string
	Status            []string
	Nameservers       []string
	RegistrantName    string
	RegistrantOrg     string
	RegistrantEmail   string
	RegistrantCountry string
	AdminEmail        string
	TechEmail         string
}

func appendUnique(in []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return in
	}
	for _, x := range in {
		if strings.EqualFold(x, v) {
			return in
		}
	}
	return append(in, v)
}
