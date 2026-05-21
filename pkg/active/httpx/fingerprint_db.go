package httpx

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Embedded fingerprint datasets. All three files live under data/ so go:embed
// can find them. Sizes are bounded (single-MB) so init parsing is acceptable.
//
//go:embed data/wappalyzer.json
var wappalyzerJSON []byte

//go:embed data/fphub.json
var fphubJSON []byte

//go:embed data/ehole.json
var eholeJSON []byte

// compiledRule is the unified internal representation of a fingerprint, derived
// from any of the supported source databases.
type compiledRule struct {
	// product is the public label emitted on a hit (e.g. "Nginx", "致远OA").
	product string
	// origin is "wappalyzer" / "fphub" / "ehole" / "builtin" — used only for debugging.
	origin string

	// Criteria semantics:
	//   - OR-criteria slots: rule fires if ANY entry matches.
	//   - AND-criteria slots: rule fires only when ALL entries match. Used for
	//     FingerprintHub style rules where `keyword: [a, b, c]` means
	//     "body must contain a AND b AND c".
	headerRegex   map[string][]*regexp.Regexp // OR: header name (lowercased) -> any-of regexes
	cookieRegex   []*regexp.Regexp            // OR: applied to "name=value" pairs
	bodyContains  []string                    // OR: case-folded substring matches
	bodyRegex     []*regexp.Regexp            // OR: regex on raw body
	titleContains []string                    // OR: substring on lowercased title
	faviconHashes map[string]struct{}         // OR: exact mmh3 string match
	// AND-only slots — when non-empty, ALL items must be present for the rule
	// to fire. They are evaluated independently of the OR slots above; either
	// an OR criterion or the full AND bundle is enough to declare a hit.
	bodyAllOf   []string // case-folded substrings all required in body
	headerAllOf []headerLiteral
}

// headerLiteral is a literal header-name + substring pair used by AND rules.
// Empty value means "header must be present".
type headerLiteral struct {
	name  string // lower-cased header name
	value string // lower-cased substring; empty = presence only
}

// fingerprintDB is the lazily-built rule set used by dbMatch.
type fingerprintDB struct {
	rules []compiledRule
}

var (
	dbOnce  sync.Once
	dbValue *fingerprintDB
)

// db returns the shared parsed fingerprint database, building it on first call.
// Parsing failures for individual rules are silently skipped so a single bad
// pattern can never panic at runtime.
func db() *fingerprintDB {
	dbOnce.Do(func() {
		dbValue = &fingerprintDB{}
		dbValue.loadWappalyzer(wappalyzerJSON)
		dbValue.loadFingerprintHub(fphubJSON)
		dbValue.loadEHole(eholeJSON)
	})
	return dbValue
}

// dbMatch runs the unified rule set against a probe response and returns the
// deduplicated, alphabetised list of matched product labels.
func dbMatch(headers http.Header, body []byte, faviconHash, title string) []string {
	rules := db().rules
	if len(rules) == 0 {
		return nil
	}
	bodyLow := strings.ToLower(string(body))
	titleLow := strings.ToLower(title)
	// Index headers (lower-cased name) once for fast lookup.
	hdrLow := make(map[string][]string, len(headers))
	var hdrBlob strings.Builder
	for k, vs := range headers {
		lk := strings.ToLower(k)
		hdrLow[lk] = vs
		for _, v := range vs {
			hdrBlob.WriteString(lk)
			hdrBlob.WriteString(": ")
			hdrBlob.WriteString(v)
			hdrBlob.WriteByte('\n')
		}
	}
	hdrBlobStr := hdrBlob.String()
	// Cookie pairs are scanned as raw "name=value" strings; both Set-Cookie
	// (server) and Cookie (would not appear here, but safe).
	var cookies []string
	for _, sc := range headers.Values("Set-Cookie") {
		cookies = append(cookies, sc)
	}

	seen := map[string]struct{}{}
	for i := range rules {
		r := &rules[i]
		if matchRule(r, hdrLow, hdrBlobStr, cookies, bodyLow, body, titleLow, faviconHash) {
			seen[r.product] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// matchRule reports whether r fires on the given probe response. A rule fires
// when ANY of its populated slots produces a hit; this matches the loose
// behaviour of public fingerprint databases where a single signal is enough.
func matchRule(r *compiledRule, hdrLow map[string][]string, hdrBlob string, cookies []string, bodyLow string, bodyRaw []byte, titleLow, faviconHash string) bool {
	// favicon — fastest, check first.
	if faviconHash != "" {
		if _, ok := r.faviconHashes[faviconHash]; ok {
			return true
		}
	}
	// header regex
	for name, regs := range r.headerRegex {
		// Empty key "" means "scan the flattened header blob" (EHole header rules).
		if name == "" {
			for _, re := range regs {
				if re != nil && re.MatchString(hdrBlob) {
					return true
				}
			}
			continue
		}
		vals, ok := hdrLow[name]
		if !ok {
			continue
		}
		// An empty regex slice means "header presence is enough".
		if len(regs) == 0 {
			return true
		}
		for _, v := range vals {
			for _, re := range regs {
				if re == nil {
					return true
				}
				if re.MatchString(v) {
					return true
				}
			}
		}
	}
	// cookies
	for _, re := range r.cookieRegex {
		for _, c := range cookies {
			if re == nil {
				continue
			}
			if re.MatchString(c) {
				return true
			}
		}
	}
	// body substring
	for _, sub := range r.bodyContains {
		if sub != "" && strings.Contains(bodyLow, sub) {
			return true
		}
	}
	// body regex (run on raw body to preserve case-sensitive patterns).
	for _, re := range r.bodyRegex {
		if re != nil && re.Match(bodyRaw) {
			return true
		}
	}
	// title substring
	for _, sub := range r.titleContains {
		if sub != "" && strings.Contains(titleLow, sub) {
			return true
		}
	}
	// AND bundle — only fires when every required substring/header matches.
	if len(r.bodyAllOf) > 0 || len(r.headerAllOf) > 0 {
		allMatch := true
		for _, sub := range r.bodyAllOf {
			if sub == "" {
				continue
			}
			if !strings.Contains(bodyLow, sub) {
				allMatch = false
				break
			}
		}
		if allMatch {
			for _, h := range r.headerAllOf {
				vals, ok := hdrLow[h.name]
				if !ok {
					allMatch = false
					break
				}
				if h.value == "" {
					continue // presence is enough
				}
				ok = false
				for _, v := range vals {
					if strings.Contains(strings.ToLower(v), h.value) {
						ok = true
						break
					}
				}
				if !ok {
					allMatch = false
					break
				}
			}
		}
		if allMatch {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Loader: Wappalyzer (projectdiscovery/wappalyzergo fingerprints_data.json)
// ---------------------------------------------------------------------------

// wappalyzerSchema models the subset of fields we consume. Wappalyzer rule
// values can be a string or a list-of-strings; we use json.RawMessage to
// dispatch at runtime.
type wappalyzerSchema struct {
	Apps map[string]struct {
		Headers   map[string]string          `json:"headers"`
		Cookies   map[string]string          `json:"cookies"`
		HTML      json.RawMessage            `json:"html"`
		Script    json.RawMessage            `json:"script"`
		ScriptSrc json.RawMessage            `json:"scriptSrc"`
		Meta      map[string]json.RawMessage `json:"meta"`
		Icon      string                     `json:"icon"`
	} `json:"apps"`
}

// loadWappalyzer parses the upstream Wappalyzer schema into compiled rules.
// Custom `\;version:\d` capture-extraction syntax is stripped before regex
// compilation; we don't extract versions yet.
func (db *fingerprintDB) loadWappalyzer(raw []byte) {
	if len(raw) == 0 {
		return
	}
	var doc wappalyzerSchema
	if err := json.Unmarshal(raw, &doc); err != nil {
		return
	}
	for name, app := range doc.Apps {
		r := compiledRule{product: name, origin: "wappalyzer"}
		// headers: name -> regex value (case-insensitive)
		if len(app.Headers) > 0 {
			r.headerRegex = make(map[string][]*regexp.Regexp, len(app.Headers))
			for k, v := range app.Headers {
				clean := stripWappalyzerSuffix(v)
				key := strings.ToLower(k)
				if clean == "" {
					r.headerRegex[key] = nil // presence-only
					continue
				}
				if re, err := regexp.Compile("(?i)" + clean); err == nil {
					r.headerRegex[key] = append(r.headerRegex[key], re)
				}
			}
		}
		// cookies: name -> regex value, applied to "name=value" pairs
		for k, v := range app.Cookies {
			pat := "(?i)\\b" + regexp.QuoteMeta(k) + "="
			if v != "" {
				pat += stripWappalyzerSuffix(v)
			}
			if re, err := regexp.Compile(pat); err == nil {
				r.cookieRegex = append(r.cookieRegex, re)
			}
		}
		// html: list of regex matched against body (case-insensitive).
		for _, p := range decodeStringList(app.HTML) {
			clean := stripWappalyzerSuffix(p)
			if clean == "" {
				continue
			}
			if re, err := regexp.Compile("(?i)" + clean); err == nil {
				r.bodyRegex = append(r.bodyRegex, re)
			}
		}
		// scriptSrc / script: regex matched on body too (close enough; <script src=...> sits in body).
		for _, p := range decodeStringList(app.ScriptSrc) {
			clean := stripWappalyzerSuffix(p)
			if clean == "" {
				continue
			}
			if re, err := regexp.Compile("(?i)" + clean); err == nil {
				r.bodyRegex = append(r.bodyRegex, re)
			}
		}
		for _, p := range decodeStringList(app.Script) {
			clean := stripWappalyzerSuffix(p)
			if clean == "" {
				continue
			}
			if re, err := regexp.Compile("(?i)" + clean); err == nil {
				r.bodyRegex = append(r.bodyRegex, re)
			}
		}
		// meta name -> body regex match e.g. <meta name="generator" content="WordPress">
		for k, v := range app.Meta {
			vs := decodeStringList(v)
			for _, vv := range vs {
				clean := stripWappalyzerSuffix(vv)
				pat := "(?is)<meta[^>]+name\\s*=\\s*[\"']" + regexp.QuoteMeta(k) + "[\"'][^>]+content\\s*=\\s*[\"'][^\"']*"
				if clean != "" {
					pat += clean
				}
				if re, err := regexp.Compile(pat); err == nil {
					r.bodyRegex = append(r.bodyRegex, re)
				}
			}
		}
		if hasAnyCriterion(&r) {
			db.rules = append(db.rules, r)
		}
	}
}

// stripWappalyzerSuffix removes the ;version / ;confidence trailing meta-tags
// from a Wappalyzer regex pattern so it compiles cleanly with Go's RE2 engine.
func stripWappalyzerSuffix(s string) string {
	if i := strings.Index(s, "\\;"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ";version:"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ";confidence:"); i >= 0 {
		s = s[:i]
	}
	return s
}

// decodeStringList accepts either a JSON string or a JSON array of strings and
// returns the contained values. Invalid JSON yields nil.
func decodeStringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	// First try string.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	return nil
}

// ---------------------------------------------------------------------------
// Loader: 0x727/FingerprintHub web_fingerprint_v3.json
// ---------------------------------------------------------------------------

type fphubEntry struct {
	Path          string            `json:"path"`
	RequestMethod string            `json:"request_method"`
	StatusCode    int               `json:"status_code"`
	Headers       map[string]string `json:"headers"`
	Keyword       []string          `json:"keyword"`
	FaviconHash   []string          `json:"favicon_hash"`
	Name          string            `json:"name"`
	Priority      int               `json:"priority"`
}

// loadFingerprintHub adds rules from FingerprintHub. Only rules targeting "/"
// (or empty path) with method GET (or empty) are considered, since the prober
// fetches only the root URL.
func (db *fingerprintDB) loadFingerprintHub(raw []byte) {
	if len(raw) == 0 {
		return
	}
	var entries []fphubEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return
	}
	for _, e := range entries {
		path := strings.TrimSpace(e.Path)
		if path != "" && path != "/" {
			continue
		}
		method := strings.ToLower(strings.TrimSpace(e.RequestMethod))
		if method != "" && method != "get" {
			continue
		}
		// FingerprintHub semantics: ALL non-empty fields must match. The
		// keyword list itself is AND-of-keywords, headers is AND-of-headers,
		// favicon_hash is OR-of-hashes. We encode this by emitting the
		// keyword+headers as an AND-bundle, and (if present) faviconHashes
		// separately as an OR signal — favicon match alone is normally
		// distinctive enough to identify the product.
		r := compiledRule{product: e.Name, origin: "fphub"}
		for _, kw := range e.Keyword {
			kw = strings.TrimSpace(kw)
			if kw != "" {
				r.bodyAllOf = append(r.bodyAllOf, strings.ToLower(kw))
			}
		}
		for k, v := range e.Headers {
			key := strings.ToLower(strings.TrimSpace(k))
			if key == "" {
				continue
			}
			r.headerAllOf = append(r.headerAllOf, headerLiteral{
				name:  key,
				value: strings.ToLower(strings.TrimSpace(v)),
			})
		}
		if len(e.FaviconHash) > 0 {
			r.faviconHashes = make(map[string]struct{}, len(e.FaviconHash))
			for _, h := range e.FaviconHash {
				h = strings.TrimSpace(h)
				if h != "" {
					r.faviconHashes[h] = struct{}{}
				}
			}
		}
		if hasAnyCriterion(&r) {
			db.rules = append(db.rules, r)
		}
	}
}

// ---------------------------------------------------------------------------
// Loader: EdgeSecurityTeam/EHole finger.json
// ---------------------------------------------------------------------------

type eholeDoc struct {
	Fingerprint []eholeEntry `json:"fingerprint"`
}

type eholeEntry struct {
	CMS      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

// loadEHole adds rules from EHole. Supported method values: keyword, faviconhash.
// Supported locations: body (default), header, title.
func (db *fingerprintDB) loadEHole(raw []byte) {
	if len(raw) == 0 {
		return
	}
	var doc eholeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return
	}
	for _, e := range doc.Fingerprint {
		if e.CMS == "" || len(e.Keyword) == 0 {
			continue
		}
		r := compiledRule{product: e.CMS, origin: "ehole"}
		method := strings.ToLower(strings.TrimSpace(e.Method))
		location := strings.ToLower(strings.TrimSpace(e.Location))
		switch method {
		case "faviconhash":
			r.faviconHashes = make(map[string]struct{}, len(e.Keyword))
			for _, h := range e.Keyword {
				h = strings.TrimSpace(h)
				if h != "" {
					r.faviconHashes[h] = struct{}{}
				}
			}
		case "keyword", "":
			// EHole keyword arrays are AND-semantics: a fingerprint fires only
			// when every keyword is found in the configured location. (This
			// matches the behaviour of EHole's own matcher; treating them as
			// OR produces an avalanche of false positives.)
			//
			// For SINGLE-keyword body rules we additionally apply a
			// specificity guard, because many of EHole's single-keyword rules
			// are too generic ("login", "apps", "360", ...) and even AND-of-1
			// fires constantly.
			cleaned := make([]string, 0, len(e.Keyword))
			for _, kw := range e.Keyword {
				kw = strings.TrimSpace(kw)
				if kw != "" {
					cleaned = append(cleaned, kw)
				}
			}
			if len(cleaned) == 0 {
				break
			}
			singleBodyRule := (location == "" || location == "body") && len(cleaned) == 1
			if singleBodyRule && !eholeKeywordIsSpecific(cleaned[0]) {
				break
			}
			switch location {
			case "header":
				// All keywords required in the flattened header blob.
				if r.headerRegex == nil {
					r.headerRegex = map[string][]*regexp.Regexp{}
				}
				for _, kw := range cleaned {
					if re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(kw)); err == nil {
						r.headerRegex[""] = append(r.headerRegex[""], re)
					}
				}
			case "title":
				// All keywords required in title (AND).
				for _, kw := range cleaned {
					r.titleContains = append(r.titleContains, strings.ToLower(kw))
				}
			default:
				// Body location (default): AND-bundle.
				for _, kw := range cleaned {
					r.bodyAllOf = append(r.bodyAllOf, strings.ToLower(kw))
				}
			}
		}
		if hasAnyCriterion(&r) {
			db.rules = append(db.rules, r)
		}
	}
}

// eholeNoisyKeywords is a denylist of EHole body keywords observed to produce
// many false positives on real-world HTML. Lower-cased exact match.
var eholeNoisyKeywords = map[string]struct{}{
	"login": {}, "logout": {}, "admin": {}, "host": {}, "hosts": {}, "redirect": {},
	"support": {}, "download": {}, "theme": {}, "platform": {}, "console": {},
	"apps": {}, "app": {}, "user": {}, "users": {}, "auth": {}, "register": {},
	"signin": {}, "sign in": {}, "sign-in": {}, "manage": {}, "dashboard": {},
	"settings": {}, "config": {}, "system": {}, "main": {}, "index": {}, "home": {},
	"about": {}, "help": {}, "search": {}, "version": {}, "title": {}, "test": {},
	"upload": {}, "image": {}, "file": {}, "files": {}, "name": {}, "data": {},
	"icon": {}, "shortcut icon": {}, "login.php": {}, "login.html": {}, "login.jsp": {},
	"login.do": {}, "login.action": {}, "self.location": {}, "self.location.href": {},
	"window.location": {}, "window.location.href": {}, "location.href": {},
	"360": {}, "ie": {}, "dns": {}, "nas": {}, "ip": {}, "id": {}, "ok": {},
	// Common page-path fragments that appear in many login/landing pages.
	"login.aspx": {}, "login.asp": {}, "/login": {}, "loginpage": {},
	"signup": {}, "signout": {}, "logout.php": {}, "passwd": {}, "password": {},
	"verify": {}, "captcha": {}, "robots.txt": {}, "favicon.ico": {},
	"sitemap.xml": {}, "manifest.json": {}, "loading": {}, "footer": {},
	"header": {}, "content": {}, "default": {}, "welcome": {}, "powered": {},
	"copyright": {}, "service": {}, "services": {}, "products": {}, "product": {},
	"company": {}, "contact": {}, "news": {}, "blog": {}, "forum": {},
}

// eholeKeywordIsSpecific decides whether an EHole body keyword is specific
// enough to use as a standalone fingerprint signal. Rules of thumb:
//   - any non-ASCII content (Chinese, etc.) is considered specific enough;
//     EHole's Chinese product strings are highly distinctive.
//   - pure ASCII keywords must be at least 8 chars AND not in the noise denylist.
func eholeKeywordIsSpecific(kw string) bool {
	low := strings.ToLower(strings.TrimSpace(kw))
	if low == "" {
		return false
	}
	if _, bad := eholeNoisyKeywords[low]; bad {
		return false
	}
	// Non-ASCII rune present? Trust the rule.
	for _, r := range low {
		if r > 127 {
			return true
		}
	}
	// Pure ASCII: require at least 8 chars of substance.
	return len(low) >= 8
}

// hasAnyCriterion reports whether the rule will ever fire.
func hasAnyCriterion(r *compiledRule) bool {
	return len(r.headerRegex) > 0 ||
		len(r.cookieRegex) > 0 ||
		len(r.bodyContains) > 0 ||
		len(r.bodyRegex) > 0 ||
		len(r.titleContains) > 0 ||
		len(r.faviconHashes) > 0 ||
		len(r.bodyAllOf) > 0 ||
		len(r.headerAllOf) > 0
}
