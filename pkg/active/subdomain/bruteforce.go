package subdomain

import (
	"bufio"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// defaultWordlistTop5k is the embedded SecLists subdomains-top1million-5000.txt.
//
//go:embed data/top5000.txt
var defaultWordlistTop5k []byte

// defaultWordlistTop20k is the embedded SecLists subdomains-top1million-20000.txt,
// available via Config.WordlistPath="builtin:top20000".
//
//go:embed data/top20000.txt
var defaultWordlistTop20k []byte

// BruteForcer drives a single brute-force run. Construct via New; safe to
// reuse across runs but each Run creates its own per-run state.
type BruteForcer struct {
	cfg Config
}

// New constructs a BruteForcer with the given config. The config is normalised
// in place; callers may inspect Config() for effective settings.
func New(cfg Config) *BruteForcer {
	cfg.Normalize()
	return &BruteForcer{cfg: cfg}
}

// Config returns the effective (normalised) configuration.
func (b *BruteForcer) Config() Config { return b.cfg }

// ProgressFunc is called once per completed lookup. done/total are 1-indexed;
// hit reflects whether the query produced a kept (non-wildcard) result.
type ProgressFunc func(done, total int, last *Result, hit bool)

// Run executes the brute force against the given root domain and returns
// kept (non-wildcard, alive) Results.
//
// Behaviour:
//   - Wildcard detection runs first unless Config.SkipWildcard is set.
//   - If wildcard is detected, any subdomain whose A-set is contained in the
//     wildcard A-set AND whose CNAME (if any) matches the wildcard CNAME is
//     dropped from the returned slice.
//   - The returned slice is alphabetically sorted by Name.
func (b *BruteForcer) Run(ctx context.Context, root string, progress ProgressFunc) ([]*Result, error) {
	root = normaliseRoot(root)
	if root == "" {
		return nil, errors.New("subdomain: empty root domain")
	}

	wordlist, err := b.loadWordlist()
	if err != nil {
		return nil, err
	}
	if b.cfg.IncludeRoot {
		// Probing the bare root is harmless and lets callers see if the apex
		// resolves through the same code path.
		wordlist = append([]string{""}, wordlist...)
	}

	// Wildcard pre-flight.
	wildcardSet := map[string]struct{}{}
	wildcardCNAME := ""
	wildcardDetected := false
	if !b.cfg.SkipWildcard {
		wildcardSet, wildcardCNAME, wildcardDetected = b.detectWildcard(ctx, root)
	}

	resolvers := append([]string(nil), b.cfg.Resolvers...)
	var rrIdx uint64
	pickResolver := func() string {
		i := atomic.AddUint64(&rrIdx, 1)
		return resolvers[int(i-1)%len(resolvers)]
	}

	type job struct {
		fqdn  string
		label string
	}
	jobs := make(chan job)
	results := make(chan *Result)

	var wg sync.WaitGroup
	for i := 0; i < b.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				res := b.queryOnce(ctx, j.fqdn, pickResolver())
				if res == nil {
					continue
				}
				// Apply wildcard filter.
				if wildcardDetected && b.looksLikeWildcard(res, wildcardSet, wildcardCNAME) {
					res.Wildcard = true
				}
				results <- res
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		defer close(jobs)
		for _, w := range wordlist {
			var fqdn string
			if w == "" {
				fqdn = root
			} else {
				fqdn = w + "." + root
			}
			select {
			case <-ctx.Done():
				return
			case jobs <- job{fqdn: fqdn, label: w}:
			}
		}
	}()

	kept := make([]*Result, 0, 64)
	total := len(wordlist)
	var done int
	for r := range results {
		done++
		hit := !r.Wildcard
		if progress != nil {
			progress(done, total, r, hit)
		}
		if hit {
			kept = append(kept, r)
		}
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i].Name < kept[j].Name })
	return kept, nil
}

// queryOnce performs one DNS lookup of fqdn using the given resolver address.
// It returns nil on NXDOMAIN, transport timeout, or empty answer.
func (b *BruteForcer) queryOnce(ctx context.Context, fqdn, server string) *Result {
	resolver := makeResolver(server, b.cfg.Timeout)
	attempts := b.cfg.RetryPerQuery + 1
	for attempt := 0; attempt < attempts; attempt++ {
		qctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
		ips, err := resolver.LookupHost(qctx, fqdn)
		cancel()
		if err != nil {
			// Treat NXDOMAIN as "no result" without retry; only retry on
			// timeout/transport errors.
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				return nil
			}
			if attempt+1 < attempts {
				continue
			}
			return nil
		}
		if len(ips) == 0 {
			return nil
		}
		seen := map[string]struct{}{}
		uniq := make([]string, 0, len(ips))
		for _, ip := range ips {
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			uniq = append(uniq, ip)
		}
		sort.Strings(uniq)
		res := &Result{Name: strings.TrimSuffix(fqdn, "."), IPs: uniq, Resolver: server}
		// CNAME lookup is best-effort; we don't fail the whole result on error.
		cctx, ccancel := context.WithTimeout(ctx, b.cfg.Timeout)
		if cn, err := resolver.LookupCNAME(cctx, fqdn); err == nil {
			cn = strings.TrimSuffix(cn, ".")
			if cn != "" && !strings.EqualFold(cn, res.Name) {
				res.CNAME = cn
			}
		}
		ccancel()
		return res
	}
	return nil
}

// detectWildcard issues N random subdomain queries against the root and
// returns the (possibly empty) wildcard A-set, CNAME, and a detected flag.
func (b *BruteForcer) detectWildcard(ctx context.Context, root string) (map[string]struct{}, string, bool) {
	probes := b.cfg.WildcardProbes
	resolver := b.cfg.Resolvers[0]
	type ans struct {
		ips   []string
		cname string
	}
	var answers []ans
	for i := 0; i < probes; i++ {
		label := randomLabel(12)
		fqdn := label + "." + root
		r := b.queryOnce(ctx, fqdn, resolver)
		if r == nil {
			continue
		}
		answers = append(answers, ans{ips: r.IPs, cname: r.CNAME})
	}
	if len(answers) == 0 {
		return nil, "", false
	}
	// Heuristic: wildcard if at least 2 of the probes returned the same A set
	// (and ideally same CNAME).
	if len(answers) < 2 {
		// Single positive answer is suspicious but not conclusive; treat as wildcard.
		set := toSet(answers[0].ips)
		return set, answers[0].cname, true
	}
	// Compare first two answers; if identical IP sets, lock in.
	if equalIPSets(answers[0].ips, answers[1].ips) {
		set := toSet(answers[0].ips)
		return set, answers[0].cname, true
	}
	// Otherwise, take the union as a conservative wildcard set (any subdomain
	// resolving entirely within the union is suspect).
	union := map[string]struct{}{}
	for _, a := range answers {
		for _, ip := range a.ips {
			union[ip] = struct{}{}
		}
	}
	return union, answers[0].cname, true
}

// looksLikeWildcard returns true when the result's IPs are a non-empty subset
// of the wildcard set; CNAME is also compared if the wildcard had one.
func (b *BruteForcer) looksLikeWildcard(r *Result, wildcardSet map[string]struct{}, wildcardCNAME string) bool {
	if len(wildcardSet) == 0 {
		return false
	}
	if len(r.IPs) == 0 {
		return false
	}
	for _, ip := range r.IPs {
		if _, ok := wildcardSet[ip]; !ok {
			return false
		}
	}
	if wildcardCNAME != "" && r.CNAME != "" && !strings.EqualFold(wildcardCNAME, r.CNAME) {
		return false
	}
	return true
}

// loadWordlist resolves Config.WordlistPath / Config.Wordlist into a deduped
// label slice. Supports two special path tokens:
//
//	"builtin:top5000"   - embedded 5k SecLists list (default if unset)
//	"builtin:top20000"  - embedded 20k SecLists list
func (b *BruteForcer) loadWordlist() ([]string, error) {
	if len(b.cfg.Wordlist) > 0 {
		return dedupLabels(b.cfg.Wordlist), nil
	}
	var raw []byte
	switch b.cfg.WordlistPath {
	case "", "builtin:top5000":
		raw = defaultWordlistTop5k
	case "builtin:top20000":
		raw = defaultWordlistTop20k
	default:
		data, err := os.ReadFile(b.cfg.WordlistPath)
		if err != nil {
			return nil, err
		}
		raw = data
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []string
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return dedupLabels(out), nil
}

// dedupLabels returns a lowercased, trimmed, deduped, order-preserving copy.
func dedupLabels(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, w := range in {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" {
			continue
		}
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	return out
}

// normaliseRoot strips a trailing dot, lower-cases, and removes a leading
// scheme if the caller accidentally passed a URL.
func normaliseRoot(root string) string {
	root = strings.TrimSpace(root)
	root = strings.ToLower(root)
	root = strings.TrimSuffix(root, ".")
	if i := strings.Index(root, "://"); i >= 0 {
		root = root[i+3:]
	}
	if i := strings.IndexAny(root, "/?#"); i >= 0 {
		root = root[:i]
	}
	if h, _, err := net.SplitHostPort(root); err == nil {
		root = h
	}
	return root
}

// randomLabel returns a length-n lowercase hex string.
func randomLabel(n int) string {
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		// Fallback to time-based pseudo-random; collisions are fine for our purpose.
		t := time.Now().UnixNano()
		for i := range buf {
			buf[i] = byte(t >> (i * 8))
		}
	}
	return hex.EncodeToString(buf)[:n]
}

// makeResolver constructs a net.Resolver that forces UDP DNS queries to the
// supplied server address.
func makeResolver(server string, timeout time.Duration) *net.Resolver {
	d := &net.Dialer{Timeout: timeout}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Force UDP first; net.Resolver will fall back to TCP automatically
			// when truncation is detected.
			return d.DialContext(ctx, "udp", server)
		},
	}
}

// toSet converts a slice to a map[string]struct{}.
func toSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[s] = struct{}{}
	}
	return out
}

// equalIPSets reports whether the two slices contain the same string set.
func equalIPSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := toSet(a)
	for _, x := range b {
		if _, ok := sa[x]; !ok {
			return false
		}
	}
	return true
}
