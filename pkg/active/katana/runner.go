// Package katana shells out to the upstream `katana` binary
// (github.com/projectdiscovery/katana) when the user opts in. It's strictly
// optional -- detection is graceful and callers fall back to the in-process
// jscrawl crawler when katana isn't on PATH.
//
// Why an external binary instead of importing the library?
//   - The katana library transitively pulls in chromedp + a sizeable headless
//     stack (~50+MB of code, plus a Chrome runtime requirement).
//   - Most users don't need headless rendering; bundling it would bloat the
//     binary and fail at runtime without Chrome installed.
//   - Power users who DO want headless can `go install
//     github.com/projectdiscovery/katana/cmd/katana@latest` and we'll detect
//     and use it. Best of both worlds.
package katana

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Info reports detection state. OK=true means the binary was found at Path
// and (best-effort) Version contains its reported version string.
type Info struct {
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// Detect locates a usable katana binary. override (when non-empty) wins over
// PATH lookup. We swallow "not found" silently (it's the common case) but
// surface "found-but-fails-to-run" via Info.Error so the dashboard can warn.
func Detect(override string) Info {
	bin := strings.TrimSpace(override)
	if bin == "" {
		bin = "katana"
	}
	p, err := exec.LookPath(bin)
	if err != nil {
		return Info{Error: ""} // Silent: not found is the common case.
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, p, "-version").CombinedOutput()
	if err != nil {
		// Binary exists but won't run -- surface as an error string so the
		// UI can show "katana found but broken" rather than silently
		// falling back.
		return Info{Path: p, OK: false, Error: err.Error()}
	}
	return Info{Path: p, Version: parseVersion(string(out)), OK: true}
}

// Config drives one Run(). It's deliberately a separate type from
// jscrawl.Config so katana-specific knobs (Headless, ExtraArgs) don't leak
// into the broader crawler API and vice-versa.
type Config struct {
	// Bin is an explicit path override; "" means use PATH lookup.
	Bin string

	// Seeds is the list of starting URLs.
	Seeds []string
	// MaxDepth maps to katana's -d flag.
	MaxDepth int
	// Concurrency maps to -c.
	Concurrency int
	// Timeout maps to -timeout (seconds).
	Timeout time.Duration
	// CrawlDuration maps to -ct (seconds, total crawl wall time).
	CrawlDuration time.Duration

	// UserAgent / Cookie / Headers all become -H header injections.
	UserAgent string
	Cookie    string
	Headers   map[string]string

	// Proxy maps to -proxy.
	Proxy string
	// RatePerSecond maps to -rl (per-host rate limit).
	RatePerSecond int
	// MaxRetries maps to -retry.
	MaxRetries int

	// JSCrawl maps to -jc (parse endpoints from JS, on by default).
	JSCrawl bool
	// KnownFiles maps to -kf all (robots.txt + sitemap discovery).
	KnownFiles bool
	// ExtractForms maps to -fx (capture <form> elements in output).
	ExtractForms bool

	// Headless maps to -hl (Chrome headless mode -- requires Chrome on the
	// host). Without this flag SPA targets typically yield zero endpoints.
	Headless bool
	// NoSandbox maps to -no-sandbox (needed inside Docker without privileges).
	NoSandbox bool

	// FieldScope maps to -fs (rdn / fqdn / dn).
	FieldScope string
	// ExcludePatterns map to -cos (out-of-scope regex blocklist).
	ExcludePatterns []string
	// MatchRegex maps to -cs (in-scope regex allowlist). Empty = no scope
	// restriction beyond seed hosts.
	MatchRegex []string
	// ExtensionMatch / ExtensionFilter map to -em / -ef.
	ExtensionMatch  []string
	ExtensionFilter []string
	// IgnoreQueryParams maps to -iqp.
	IgnoreQueryParams bool

	// ExtraArgs is an escape hatch: anything here is appended verbatim to the
	// argv. Useful for experimental flags we haven't surfaced yet.
	ExtraArgs []string
}

// Output is one parsed JSONL line from katana. We map to the upstream schema
// best-effort; fields we don't parse are still in RawJSON for downstream
// inspection.
type Output struct {
	Timestamp string `json:"timestamp,omitempty"`
	Request   struct {
		Method   string `json:"method,omitempty"`
		Endpoint string `json:"endpoint,omitempty"`
		// Tag is where katana found this URL: "body" / "script" / "form" /
		// "header" / "robots" / "sitemap" / etc. Useful for downstream
		// classification.
		Tag       string `json:"tag,omitempty"`
		Source    string `json:"source,omitempty"`
		Attribute string `json:"attribute,omitempty"`
	} `json:"request"`
	Response struct {
		StatusCode  int               `json:"status_code,omitempty"`
		ContentType string            `json:"content_type,omitempty"`
		Headers     map[string]string `json:"headers,omitempty"`
	} `json:"response,omitempty"`
	// Forms is populated when -fx was passed AND the page contained a <form>.
	Forms []struct {
		Action  string            `json:"action,omitempty"`
		Method  string            `json:"method,omitempty"`
		EncType string            `json:"enctype,omitempty"`
		Inputs  map[string]string `json:"inputs,omitempty"`
	} `json:"forms,omitempty"`

	// RawJSON keeps the original line for callers that want to do their own
	// parsing (e.g. extract a field we don't know about yet).
	RawJSON []byte `json:"-"`
}

// Run spawns katana, streams its JSONL stdout, and returns the parsed
// outputs. ctx cancellation kills the child process. Stderr is captured and
// surfaced via the returned error if the run failed AND we got nothing
// useful from stdout.
func Run(ctx context.Context, cfg Config) ([]*Output, error) {
	info := Detect(cfg.Bin)
	if !info.OK {
		if info.Error != "" {
			return nil, fmt.Errorf("katana detected but broken: %s", info.Error)
		}
		return nil, errors.New("katana binary not found in PATH (install with: go install github.com/projectdiscovery/katana/cmd/katana@latest)")
	}
	if len(cfg.Seeds) == 0 {
		return nil, errors.New("no seeds")
	}

	args := buildArgs(cfg)
	cmd := exec.CommandContext(ctx, info.Path, args...)
	// Pass seeds via stdin (one per line) -- bypasses argv length limits and
	// avoids issues with weird URL characters on Windows.
	cmd.Stdin = strings.NewReader(strings.Join(cfg.Seeds, "\n"))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start katana: %w", err)
	}

	// Read stdout JSONL in a goroutine; collect stderr in another for error
	// surfacing. wait for both before returning.
	var (
		mu        sync.Mutex
		outputs   []*Output
		stderrBuf strings.Builder
		wg        sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		// Some endpoints produce very long JSON lines (response headers,
		// inline forms). Bump the buffer well beyond the default 64KB.
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...) // copy: scanner reuses buffer
			var o Output
			if err := json.Unmarshal(line, &o); err != nil {
				continue // skip malformed line, keep going
			}
			o.RawJSON = line
			mu.Lock()
			outputs = append(outputs, &o)
			mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		// Cap stderr buffering at 64KB; katana's silent mode means usually 0
		// bytes here, but be defensive against runaway error output.
		_, _ = io.CopyN(&stderrBuf, stderr, 64*1024)
		_, _ = io.Copy(io.Discard, stderr) // drain rest
	}()
	wg.Wait()

	if err := cmd.Wait(); err != nil {
		// If we still got outputs, treat the run as partial-success rather
		// than a hard failure. Callers can decide whether to log.
		if len(outputs) == 0 {
			msg := strings.TrimSpace(stderrBuf.String())
			if msg == "" {
				msg = err.Error()
			}
			return nil, fmt.Errorf("katana run failed: %s", msg)
		}
	}
	return outputs, nil
}

// buildArgs translates Config into katana CLI args. Always includes
// -jsonl/-silent/-no-color so we can cleanly parse stdout. The seeds
// themselves are streamed via stdin (-list -).
func buildArgs(cfg Config) []string {
	args := []string{
		"-jsonl",
		"-silent",
		"-no-color",
		"-list", "-", // read seeds from stdin
	}
	addInt := func(flag string, v int) {
		if v > 0 {
			args = append(args, flag, strconv.Itoa(v))
		}
	}
	addInt("-d", cfg.MaxDepth)
	addInt("-c", cfg.Concurrency)
	if cfg.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(int(cfg.Timeout.Seconds())))
	}
	if cfg.CrawlDuration > 0 {
		args = append(args, "-ct", strconv.Itoa(int(cfg.CrawlDuration.Seconds())))
	}
	addInt("-rl", cfg.RatePerSecond)
	addInt("-retry", cfg.MaxRetries)

	if cfg.UserAgent != "" {
		args = append(args, "-H", "User-Agent: "+cfg.UserAgent)
	}
	if cfg.Cookie != "" {
		args = append(args, "-H", "Cookie: "+cfg.Cookie)
	}
	for k, v := range cfg.Headers {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		args = append(args, "-H", k+": "+v)
	}
	if cfg.Proxy != "" {
		args = append(args, "-proxy", cfg.Proxy)
	}

	if cfg.JSCrawl {
		args = append(args, "-jc")
	}
	if cfg.KnownFiles {
		args = append(args, "-kf", "all")
	}
	if cfg.ExtractForms {
		args = append(args, "-fx")
	}
	if cfg.Headless {
		args = append(args, "-hl")
		if cfg.NoSandbox {
			args = append(args, "-no-sandbox")
		}
	}
	if cfg.IgnoreQueryParams {
		args = append(args, "-iqp")
	}
	if cfg.FieldScope != "" {
		args = append(args, "-fs", cfg.FieldScope)
	}
	for _, p := range cfg.ExcludePatterns {
		args = append(args, "-cos", p)
	}
	for _, p := range cfg.MatchRegex {
		args = append(args, "-cs", p)
	}
	if len(cfg.ExtensionMatch) > 0 {
		args = append(args, "-em", strings.Join(cfg.ExtensionMatch, ","))
	}
	if len(cfg.ExtensionFilter) > 0 {
		args = append(args, "-ef", strings.Join(cfg.ExtensionFilter, ","))
	}
	args = append(args, cfg.ExtraArgs...)
	return args
}

// parseVersion pulls a version string out of `katana -version` stdout. We
// accept any of these shapes (katana has changed it across releases):
//
//	"Current Version: v1.2.3"
//	"katana v1.2.3"
//	"v1.2.3"
//
// Returns "" when nothing parseable is found; callers should treat that as
// "version unknown but binary works".
func parseVersion(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, tok := range strings.Fields(line) {
			t := strings.TrimSpace(tok)
			t = strings.TrimSuffix(t, ",")
			if t == "" {
				continue
			}
			// Accept "vN.N.N" or bare "N.N.N".
			head := t
			if strings.HasPrefix(head, "v") || strings.HasPrefix(head, "V") {
				head = head[1:]
			}
			if len(head) == 0 || (head[0] < '0' || head[0] > '9') {
				continue
			}
			// Quick sanity: must contain at least one dot to be a version.
			if !strings.Contains(head, ".") {
				continue
			}
			return strings.TrimPrefix(strings.TrimPrefix(t, "v"), "V")
		}
	}
	return ""
}
