package cloud_bucket

import "testing"

func TestExtractBase(t *testing.T) {
	s := NewCloudBucket()
	cases := map[string]string{
		"baidu.com":           "baidu",
		"www.baidu.com":       "baidu",
		"news.baidu.com":      "baidu",
		"https://www.qq.com/": "qq",
		"test.example.co.uk":  "example",
		"baidu":               "baidu",
		"BAIDU.COM":           "baidu",
		"  baidu.com  ":       "baidu",
		"a.b.c.d.example.cn":  "example",
		"":                    "",
	}
	for in, want := range cases {
		if got := s.extractBase(in); got != want {
			t.Errorf("extractBase(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestGenerateCandidatesDedup(t *testing.T) {
	s := NewCloudBucket()
	cands := s.generateCandidates("baidu.com", nil)
	seen := map[string]struct{}{}
	for _, c := range cands {
		if _, dup := seen[c.host]; dup {
			t.Errorf("duplicate candidate host: %s", c.host)
		}
		seen[c.host] = struct{}{}
	}
	// 确保 {name}.qingstor.com 这种无占位符模板只出现 1 次（修复前出现 32 次）
	count := 0
	for _, c := range cands {
		if c.host == "baidu.qingstor.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("baidu.qingstor.com appears %d times; want 1", count)
	}
}
