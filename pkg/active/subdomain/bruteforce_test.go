package subdomain

import (
	"strings"
	"testing"
)

// TestEmbeddedWordlists ensures both default wordlists embed cleanly with the
// expected approximate sizes.
func TestEmbeddedWordlists(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      []byte
		minLines int
	}{
		{"top5000", defaultWordlistTop5k, 4500},
		{"top20000", defaultWordlistTop20k, 18000},
	} {
		lines := strings.Count(string(tc.raw), "\n")
		if lines < tc.minLines {
			t.Errorf("%s: expected >=%d lines, got %d", tc.name, tc.minLines, lines)
		}
		t.Logf("%s: %d lines (%d bytes)", tc.name, lines, len(tc.raw))
	}
}

// TestNormaliseRoot covers the various input forms the brute-forcer accepts.
func TestNormaliseRoot(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"example.com", "example.com"},
		{"  EXAMPLE.com.  ", "example.com"},
		{"https://example.com/path?x=1#h", "example.com"},
		{"example.com:8443", "example.com"},
		{"http://example.com", "example.com"},
		{"  ", ""},
	}
	for _, tc := range cases {
		got := normaliseRoot(tc.in)
		if got != tc.want {
			t.Errorf("normaliseRoot(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDedupLabels verifies dedupe + lower-case + trim + order preservation.
func TestDedupLabels(t *testing.T) {
	in := []string{"WWW", "www", "  mail ", "API", "api", "", "#comment"}
	out := dedupLabels(in)
	want := []string{"www", "mail", "api", "#comment"}
	if len(out) != len(want) {
		t.Fatalf("len=%d want %d (%v)", len(out), len(want), out)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("out[%d]=%q want %q", i, out[i], want[i])
		}
	}
}

// TestEqualIPSets checks order-independent equality.
func TestEqualIPSets(t *testing.T) {
	if !equalIPSets([]string{"1.1.1.1", "8.8.8.8"}, []string{"8.8.8.8", "1.1.1.1"}) {
		t.Errorf("expected equal sets")
	}
	if equalIPSets([]string{"1.1.1.1"}, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Errorf("unequal length should not match")
	}
	if equalIPSets([]string{"1.1.1.1"}, []string{"2.2.2.2"}) {
		t.Errorf("disjoint sets should not match")
	}
}

// TestLoadWordlistBuiltin verifies the loadWordlist resolver handles the
// "builtin:top5000" / "builtin:top20000" tokens and explicit slices.
func TestLoadWordlistBuiltin(t *testing.T) {
	for _, tok := range []string{"", "builtin:top5000", "builtin:top20000"} {
		b := New(Config{WordlistPath: tok})
		lst, err := b.loadWordlist()
		if err != nil {
			t.Fatalf("loadWordlist(%q) err: %v", tok, err)
		}
		if len(lst) < 100 {
			t.Errorf("%q: tiny wordlist len=%d", tok, len(lst))
		}
	}
	// Explicit Wordlist should win.
	b := New(Config{Wordlist: []string{"www", "mail", "www"}})
	lst, err := b.loadWordlist()
	if err != nil {
		t.Fatal(err)
	}
	if len(lst) != 2 {
		t.Errorf("dedup failed: %v", lst)
	}
}
