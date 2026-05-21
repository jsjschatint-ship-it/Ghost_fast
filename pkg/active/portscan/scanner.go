package portscan

import (
	"bufio"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

// defaultTop100 is the embedded nmap top-100 TCP ports list, sorted by port
// number. Source: https://github.com/nmap/nmap/blob/master/nmap-services
//
//go:embed data/top100.txt
var defaultTop100 []byte

// defaultTop1000 is the embedded nmap top-1000 TCP ports list, sorted by port
// number.
//
//go:embed data/top1000.txt
var defaultTop1000 []byte

// Scanner drives a port-scan run. Construct via New; safe to reuse.
type Scanner struct {
	cfg Config
}

// New constructs a Scanner with the given config. Config is normalised in
// place; effective values can be inspected via Config().
func New(cfg Config) *Scanner {
	cfg.Normalize()
	return &Scanner{cfg: cfg}
}

// Config returns the effective (normalised) configuration.
func (s *Scanner) Config() Config { return s.cfg }

// ProgressFunc is invoked on every completed (port,target) attempt.
//   - done/total are 1-indexed counters across the whole run
//   - lastResult is non-nil only when the attempt produced an open port
type ProgressFunc func(done, total int, last *Result)

// Run executes the scan. Targets may be hostnames or IP literals; if the input
// has a trailing ":port", that single port supplements the configured port
// list FOR THAT TARGET ONLY (useful when callers already know about a few
// custom ports per host).
func (s *Scanner) Run(ctx context.Context, targets []string, progress ProgressFunc) ([]*Result, error) {
	ports, err := s.resolvePorts()
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, errors.New("portscan: empty port list after resolution")
	}
	cleanedTargets := dedupTargets(targets)
	if len(cleanedTargets) == 0 {
		return nil, errors.New("portscan: no targets")
	}

	type job struct {
		input string // original target string
		host  string // resolution input ("ip" or "host" without port)
		port  int
	}

	// Pre-resolve hostnames to (a) avoid DNS hammering during the scan and
	// (b) populate IP fields in results. Hostnames that fail to resolve are
	// still kept (we'll attempt the dial which will surface a clearer error).
	resolved := make(map[string]string, len(cleanedTargets))
	for _, t := range cleanedTargets {
		host, _ := splitHostExtraPort(t)
		if _, ok := resolved[host]; ok {
			continue
		}
		if !s.cfg.SkipResolve {
			ips, _ := net.DefaultResolver.LookupHost(ctx, host)
			if len(ips) > 0 {
				resolved[host] = ips[0]
			} else {
				resolved[host] = host
			}
		} else {
			resolved[host] = host
		}
	}

	// Build the full job set.
	var jobs []job
	for _, t := range cleanedTargets {
		host, extraPort := splitHostExtraPort(t)
		seen := map[int]struct{}{}
		for _, p := range ports {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			jobs = append(jobs, job{input: t, host: host, port: p})
		}
		if extraPort > 0 {
			if _, ok := seen[extraPort]; !ok {
				jobs = append(jobs, job{input: t, host: host, port: extraPort})
			}
		}
	}
	total := len(jobs)

	// Per-host gates: bounded semaphore per resolved host name. We allocate
	// upfront so workers never need to mutate the map.
	hostGates := make(map[string]chan struct{}, len(resolved))
	for h := range resolved {
		hostGates[h] = make(chan struct{}, s.cfg.PerHostConcurrency)
	}

	globalGate := make(chan struct{}, s.cfg.Concurrency)
	resultsCh := make(chan *Result, 64)

	var wg sync.WaitGroup
	var done int64
	dispatch := func(j job) {
		defer wg.Done()
		// Honour both per-host and global concurrency caps.
		hostGates[j.host] <- struct{}{}
		globalGate <- struct{}{}
		defer func() {
			<-globalGate
			<-hostGates[j.host]
		}()
		select {
		case <-ctx.Done():
			return
		default:
		}
		ip := resolved[j.host]
		res := s.probe(ctx, j.input, j.host, ip, j.port)
		n := atomic.AddInt64(&done, 1)
		if progress != nil {
			progress(int(n), total, res)
		}
		if res != nil {
			resultsCh <- res
		}
	}

	for _, j := range jobs {
		wg.Add(1)
		go dispatch(j)
	}
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	out := make([]*Result, 0, 32)
	for r := range resultsCh {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Port < out[j].Port
	})
	return out, nil
}

// probe attempts to connect to (ip:port). It returns a *Result only on success.
// Behaviour:
//   - first attempt uses cfg.Timeout
//   - on transient failure, up to cfg.RetryPerPort retries use cfg.RetryTimeout
//   - cancellation via ctx propagates immediately
//   - banner is grabbed if cfg.GrabBanner is true and the service speaks first
func (s *Scanner) probe(ctx context.Context, input, host, ip string, port int) *Result {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	maxAttempts := s.cfg.RetryPerPort + 1
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		timeout := s.cfg.Timeout
		if attempt > 1 {
			timeout = s.cfg.RetryTimeout
		}
		t0 := time.Now()
		conn, err := dialWithCtx(ctx, addr, timeout)
		if err != nil {
			if !shouldRetry(err) || attempt == maxAttempts {
				return nil
			}
			continue
		}
		latency := time.Since(t0).Milliseconds()
		banner := ""
		if s.cfg.GrabBanner {
			banner = grabBanner(conn, s.cfg.BannerTimeout, s.cfg.BannerMaxBytes)
		}
		_ = conn.Close()
		return &Result{
			Target:    input,
			IP:        ip,
			Port:      port,
			Service:   wellKnownService(port),
			Banner:    banner,
			LatencyMS: latency,
			Attempts:  attempt,
		}
	}
	return nil
}

// dialWithCtx wraps net.Dialer.DialContext with the requested timeout.
func dialWithCtx(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.DialContext(dctx, "tcp", addr)
}

// shouldRetry returns true for errors that may be transient: timeout, reset by
// peer, EOF mid-handshake. Refused / unreachable responses are deterministic
// "closed" signals and are not retried.
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "reset") || strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "broken pipe") || strings.Contains(msg, "forcibly closed") {
		return true
	}
	return false
}

// grabBanner reads up to maxBytes from conn within timeout; returns the
// printable-cleaned string. A silent service returns "".
func grabBanner(conn net.Conn, timeout time.Duration, maxBytes int) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)
	buf := make([]byte, maxBytes)
	n, err := br.Read(buf)
	if n <= 0 {
		_ = err // ignore — no banner is fine
		return ""
	}
	return cleanPrintable(buf[:n])
}

// cleanPrintable replaces non-printable bytes with '.' and trims surrounding
// whitespace, returning a single-line string suitable for logging.
func cleanPrintable(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			sb.WriteByte(' ')
		case c >= 32 && c < 127:
			sb.WriteByte(c)
		default:
			// Keep multi-byte UTF-8 only when we can decode safely; otherwise '.'
			if unicode.IsPrint(rune(c)) {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(sb.String()), " "))
}

// resolvePorts merges Config.Ports / PortPreset / PortRange into a single
// deduped, sorted []int.
func (s *Scanner) resolvePorts() ([]int, error) {
	seen := map[int]struct{}{}
	add := func(p int) {
		if p >= 1 && p <= 65535 {
			seen[p] = struct{}{}
		}
	}
	for _, p := range s.cfg.Ports {
		add(p)
	}
	if s.cfg.PortRange != "" {
		ps, err := ParseRange(s.cfg.PortRange)
		if err != nil {
			return nil, fmt.Errorf("portscan: invalid port range %q: %w", s.cfg.PortRange, err)
		}
		for _, p := range ps {
			add(p)
		}
	}
	if len(seen) == 0 {
		switch strings.ToLower(strings.TrimSpace(s.cfg.PortPreset)) {
		case "", "top100":
			for _, p := range parsePortFile(defaultTop100) {
				add(p)
			}
		case "top1000":
			for _, p := range parsePortFile(defaultTop1000) {
				add(p)
			}
		case "all":
			for p := 1; p <= 65535; p++ {
				add(p)
			}
		default:
			return nil, fmt.Errorf("portscan: unknown port preset %q (want top100|top1000|all)", s.cfg.PortPreset)
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// ParseRange parses a textual port spec like "80,443,8000-8100,9200" into
// a deduped, sorted []int. Empty parts are ignored. Public so callers can
// validate user input before constructing a Config.
func ParseRange(spec string) ([]int, error) {
	seen := map[int]struct{}{}
	for _, raw := range strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	}) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if i := strings.Index(raw, "-"); i >= 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(raw[:i]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(raw[i+1:]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid range %q", raw)
			}
			for p := lo; p <= hi; p++ {
				seen[p] = struct{}{}
			}
		} else {
			p, err := strconv.Atoi(raw)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", raw)
			}
			seen[p] = struct{}{}
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// parsePortFile reads a "one port per line" embedded file into a slice.
// Comment lines starting with '#' and blanks are skipped.
func parsePortFile(raw []byte) []int {
	out := make([]int, 0, 1024)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

// splitHostExtraPort interprets "host" or "host:port" or "ip:port".
// Returns (hostOnly, optionalPort). Brackets around IPv6 are handled.
func splitHostExtraPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return s, 0
	}
	// Strip URL scheme and trailing path if user pasted a URL.
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return strings.Trim(s, "[]"), 0
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return host, 0
	}
	return host, p
}

// dedupTargets returns a lower-cased, trimmed, order-preserving deduped copy.
func dedupTargets(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		k := strings.ToLower(t)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, t)
	}
	return out
}
