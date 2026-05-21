package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Prober is the concurrent HTTP/HTTPS prober. It is safe for reuse across calls
// to Run; each call creates its own HTTP client according to Config.
type Prober struct {
	cfg    Config
	client *http.Client
}

// New constructs a Prober with the given config. The config is normalised in
// place: callers may inspect prober.Config() to see the effective settings.
func New(cfg Config) *Prober {
	cfg.Normalize()
	p := &Prober{cfg: cfg}
	p.client = p.buildClient()
	return p
}

// Config returns the effective (normalised) configuration.
func (p *Prober) Config() Config { return p.cfg }

// buildClient creates the http.Client used for probes. Redirects are handled
// manually so we can record the redirect chain.
func (p *Prober) buildClient() *http.Client {
	tr := &http.Transport{
		Proxy:           p.proxyFunc(),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: p.cfg.SkipTLSVerify}, // intentional: callers ask for raw recon
		DialContext: (&net.Dialer{
			Timeout: p.cfg.Timeout,
		}).DialContext,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   p.cfg.Timeout,
		ResponseHeaderTimeout: p.cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   p.cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !p.cfg.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= p.cfg.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// proxyFunc returns a Transport-compatible proxy resolver honouring Config.Proxy.
func (p *Prober) proxyFunc() func(*http.Request) (*url.URL, error) {
	if p.cfg.Proxy == "" {
		return http.ProxyFromEnvironment
	}
	u, err := url.Parse(p.cfg.Proxy)
	if err != nil {
		return http.ProxyFromEnvironment
	}
	return http.ProxyURL(u)
}

// ProgressFunc is invoked once per completed input. It MUST be safe for
// concurrent invocation. done/total are 1-indexed final counts.
type ProgressFunc func(done, total int, last *Result)

// Run probes every input concurrently and returns the collected Results in the
// same order as the inputs. Empty / invalid inputs yield Results with Err set.
func (p *Prober) Run(ctx context.Context, inputs []string, progress ProgressFunc) []*Result {
	if len(inputs) == 0 {
		return nil
	}
	expanded := make([]string, 0, len(inputs))
	originIndex := make([]int, 0, len(inputs))
	for i, raw := range inputs {
		for _, u := range p.expandTarget(raw) {
			expanded = append(expanded, u)
			originIndex = append(originIndex, i)
		}
	}
	results := make([]*Result, len(expanded))
	sem := make(chan struct{}, p.cfg.Concurrency)
	var wg sync.WaitGroup
	var done int
	var doneMu sync.Mutex
	total := len(expanded)
	for i, target := range expanded {
		select {
		case <-ctx.Done():
			results[i] = &Result{Input: inputs[originIndex[i]], URL: target, Err: ctx.Err().Error()}
			continue
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, target string, originalInput string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := p.probeOne(ctx, target)
			r.Input = originalInput
			results[idx] = r
			if progress != nil {
				doneMu.Lock()
				done++
				cur := done
				doneMu.Unlock()
				progress(cur, total, r)
			}
		}(i, target, inputs[originIndex[i]])
	}
	wg.Wait()
	return results
}

// expandTarget turns one input string into one or more probe URLs.
//
// Rules:
//   - A scheme-prefixed URL (http:// or https://) is used as-is.
//   - "host:port" picks https for 443/8443/9443/.../*443 patterns, otherwise http.
//   - A bare host with SchemesAuto true expands to http://host and https://host.
//   - A bare host with SchemesAuto false defaults to http://host.
func (p *Prober) expandTarget(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	low := strings.ToLower(raw)
	if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
		return []string{raw}
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		scheme := "http"
		if isLikelyTLSPort(port) {
			scheme = "https"
		}
		return []string{fmt.Sprintf("%s://%s:%s", scheme, host, port)}
	}
	if p.cfg.SchemesAuto {
		out := make([]string, 0, len(p.cfg.Ports))
		for _, port := range p.cfg.Ports {
			scheme := "http"
			if port == 443 || isLikelyTLSPort(strconv.Itoa(port)) {
				scheme = "https"
			}
			if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
				out = append(out, fmt.Sprintf("%s://%s", scheme, raw))
			} else {
				out = append(out, fmt.Sprintf("%s://%s:%d", scheme, raw, port))
			}
		}
		return out
	}
	return []string{"http://" + raw}
}

// isLikelyTLSPort returns true for ports commonly serving TLS (443, *443, 8443, 9443).
func isLikelyTLSPort(port string) bool {
	switch port {
	case "443", "8443", "9443", "10443":
		return true
	}
	return strings.HasSuffix(port, "443")
}

// probeOne executes a single probe against the supplied URL. It never panics
// and always returns a non-nil *Result; transport errors are stored in r.Err.
func (p *Prober) probeOne(ctx context.Context, target string) *Result {
	start := time.Now()
	r := &Result{URL: target}
	u, err := url.Parse(target)
	if err != nil {
		r.Err = "invalid url: " + err.Error()
		r.Duration = time.Since(start)
		return r
	}
	r.Scheme = u.Scheme
	r.Host = u.Hostname()
	if portStr := u.Port(); portStr != "" {
		if pn, err := strconv.Atoi(portStr); err == nil {
			r.Port = pn
		}
	} else if u.Scheme == "https" {
		r.Port = 443
	} else {
		r.Port = 80
	}
	// DNS first (best-effort; failures don't abort the probe).
	if p.cfg.ResolveDNS && r.Host != "" {
		r.IPs, r.CNAME = resolveHost(ctx, r.Host)
	}
	// Request.
	reqCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		r.Err = err.Error()
		r.Duration = time.Since(start)
		return r
	}
	req.Header.Set("User-Agent", p.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	for k, v := range p.cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}
	// Track redirect chain via a trace cookie.
	resp, err := p.client.Do(req)
	if err != nil {
		// Distinguish: redirect-blocked errors yield a response we can still inspect.
		if resp == nil {
			r.Err = err.Error()
			r.Duration = time.Since(start)
			return r
		}
	}
	defer resp.Body.Close()
	r.Status = resp.StatusCode
	r.ContentType = resp.Header.Get("Content-Type")
	r.Server = resp.Header.Get("Server")
	if resp.Request != nil && resp.Request.URL != nil {
		r.FinalURL = resp.Request.URL.String()
	} else {
		r.FinalURL = target
	}
	if r.FinalURL != "" && r.FinalURL != target {
		r.Chain = []string{target, r.FinalURL}
	}
	// TLS cert details.
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		c := resp.TLS.PeerCertificates[0]
		r.Cert = &CertInfo{
			Subject:   c.Subject.String(),
			Issuer:    c.Issuer.String(),
			SANs:      append([]string(nil), c.DNSNames...),
			NotBefore: c.NotBefore,
			NotAfter:  c.NotAfter,
			SelfSign:  c.Subject.String() == c.Issuer.String(),
		}
	}
	// Body read capped by MaxBodyBytes.
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.cfg.MaxBodyBytes))
	if err != nil && !errors.Is(err, io.EOF) {
		r.Err = "body read: " + err.Error()
	}
	r.ContentLength = int64(len(body))
	r.Title = extractTitle(body)
	// Favicon (best-effort, separate request).
	if p.cfg.FetchFavicon && resp.Request != nil {
		r.FaviconHash = p.fetchFaviconHash(ctx, resp.Request.URL)
	}
	r.Tech = matchFingerprints(resp.Header, body, r.FaviconHash, r.Title)
	r.Duration = time.Since(start)
	return r
}

// fetchFaviconHash downloads /favicon.ico relative to base and computes its
// favicon mmh3 hash. Network/parse errors silently yield "".
func (p *Prober) fetchFaviconHash(ctx context.Context, base *url.URL) string {
	if base == nil {
		return ""
	}
	favURL := *base
	favURL.Path = "/favicon.ico"
	favURL.RawQuery = ""
	favURL.Fragment = ""
	reqCtx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, favURL.String(), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", p.cfg.UserAgent)
	resp, err := p.client.Do(req)
	if err != nil || resp == nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil || len(body) == 0 {
		return ""
	}
	return Mmh3FaviconHash(body)
}

// resolveHost looks up A/AAAA + CNAME for host using the default resolver. Any
// individual lookup failure is silently absorbed.
func resolveHost(ctx context.Context, host string) (ips []string, cname string) {
	resolver := net.DefaultResolver
	if addrs, err := resolver.LookupHost(ctx, host); err == nil {
		seen := map[string]struct{}{}
		for _, a := range addrs {
			if _, ok := seen[a]; ok {
				continue
			}
			seen[a] = struct{}{}
			ips = append(ips, a)
		}
	}
	if name, err := resolver.LookupCNAME(ctx, host); err == nil {
		name = strings.TrimSuffix(name, ".")
		if !strings.EqualFold(name, host) {
			cname = name
		}
	}
	return ips, cname
}

// titleRe matches the contents of the first <title>...</title> tag,
// case-insensitively across newlines.
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle returns a cleaned-up <title> string or "".
func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	t = strings.ReplaceAll(t, "\n", " ")
	t = strings.ReplaceAll(t, "\r", " ")
	// Collapse runs of whitespace.
	for strings.Contains(t, "  ") {
		t = strings.ReplaceAll(t, "  ", " ")
	}
	if len(t) > 256 {
		t = t[:256]
	}
	return t
}
