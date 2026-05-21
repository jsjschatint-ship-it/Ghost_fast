package katana

import (
	"strings"
	"testing"
	"time"
)

// TestDetectMissing exercises the "binary not found" path. We use a
// definitely-not-installed name so PATH lookup fails. The function should
// quietly return Info{OK: false} (no error spam, no panic).
func TestDetectMissing(t *testing.T) {
	info := Detect("definitely-not-katana-zzz-" + time.Now().Format("20060102150405"))
	if info.OK {
		t.Errorf("expected OK=false for missing binary, got %+v", info)
	}
	if info.Path != "" {
		t.Errorf("expected empty path for missing binary, got %q", info.Path)
	}
}

// TestParseVersion covers the version-string parser for the three shapes
// katana has emitted across releases.
func TestParseVersion(t *testing.T) {
	cases := map[string]string{
		"Current Version: v1.2.3":            "1.2.3",
		"v0.0.7":                             "0.0.7",
		"katana v1.0.0":                      "1.0.0",
		"Project Discovery katana v1.2.10\n": "1.2.10",
		"":                                   "",
		"some random output":                 "",
		// Defensive: must require a dot to count as version.
		"v1": "",
	}
	for input, want := range cases {
		got := parseVersion(input)
		if got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestBuildArgsFlags spot-checks the CLI argv translation: each Config
// knob should produce the expected katana flag.
func TestBuildArgsFlags(t *testing.T) {
	cfg := Config{
		Seeds:             []string{"https://example.com"},
		MaxDepth:          3,
		Concurrency:       8,
		Timeout:           12 * time.Second,
		CrawlDuration:     60 * time.Second,
		UserAgent:         "ghost/1.0",
		Cookie:            "sid=abc",
		Headers:           map[string]string{"X-Test": "yes"},
		Proxy:             "http://127.0.0.1:8080",
		RatePerSecond:     5,
		MaxRetries:        2,
		JSCrawl:           true,
		KnownFiles:        true,
		ExtractForms:      true,
		Headless:          true,
		NoSandbox:         true,
		IgnoreQueryParams: true,
		FieldScope:        "rdn",
		ExcludePatterns:   []string{"/logout"},
		MatchRegex:        []string{"/api/"},
		ExtensionMatch:    []string{"js", "json"},
		ExtensionFilter:   []string{"png", "css"},
		ExtraArgs:         []string{"-debug"},
	}
	args := buildArgs(cfg)
	joined := strings.Join(args, " ")

	mustContain := []string{
		"-jsonl",
		"-silent",
		"-no-color",
		"-list -",
		"-d 3",
		"-c 8",
		"-timeout 12",
		"-ct 60",
		"-rl 5",
		"-retry 2",
		"User-Agent: ghost/1.0",
		"Cookie: sid=abc",
		"X-Test: yes",
		"-proxy http://127.0.0.1:8080",
		"-jc",
		"-kf all",
		"-fx",
		"-hl",
		"-no-sandbox",
		"-iqp",
		"-fs rdn",
		"-cos /logout",
		"-cs /api/",
		"-em js,json",
		"-ef png,css",
		"-debug",
	}
	for _, want := range mustContain {
		if !strings.Contains(joined, want) {
			t.Errorf("buildArgs missing %q in: %s", want, joined)
		}
	}
}

// TestBuildArgsMinimal: empty config produces only the always-on flags.
func TestBuildArgsMinimal(t *testing.T) {
	args := buildArgs(Config{Seeds: []string{"https://x"}})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-jsonl") || !strings.Contains(joined, "-list -") {
		t.Errorf("minimal args missing baseline: %s", joined)
	}
	for _, mustNot := range []string{"-jc", "-kf", "-fx", "-hl", "-iqp", "-d "} {
		if strings.Contains(joined, mustNot) {
			t.Errorf("minimal args should NOT contain %q, got: %s", mustNot, joined)
		}
	}
}
