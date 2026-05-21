package server

import "testing"

func TestClassifyOne(t *testing.T) {
	cases := []struct {
		in    string
		class smartTargetClass
	}{
		{"8.8.8.8", classIP},
		{"1.1.1.0/24", classCIDR},
		{"222.186.212.57-222.186.212.61", classIPRange},
		{"222. 186. 212. 57-222. 186. 212. 61", classIPRange}, // xlsx 里常见的带空格写法
		{"10.0.0.5-9", classIPRange},                          // 短格式
		{"https://example.com/foo", classURL},
		{"example.com:8080", classURL},
		{"127.0.0.1:22", classURL},
		{"example.com", classRoot},
		{"www.example.com", classSub},
		{"sub.deep.example.co.uk", classSub},
		{"example.co.uk", classRoot},
		{"阿里巴巴集团", classCorp},
		{"Acme Inc.", classCorp},
		{"some company", classCorp},
		{"random gibberish", classUnkown}, // 无关键字/CJK/点：归 unknown
		{"justaword", classUnkown},
		{"", classUnkown},
	}
	for _, c := range cases {
		got, _ := classifyOne(c.in)
		if got != c.class {
			t.Errorf("classifyOne(%q) = %q, want %q", c.in, got, c.class)
		}
	}
}

func TestClassifyAllBuckets(t *testing.T) {
	raws := []string{
		"8.8.8.8", "8.8.8.8", // dedup
		"1.1.1.0/24",
		"https://example.com",
		"example.com",
		"www.example.com",
		"阿里巴巴集团",
		"10.0.0.5-10.0.0.7", // expands to 3 IPs
		"",
		"   ",
	}
	bk := classifyAll(raws)
	// 1 single IP + 3 expanded from range = 4
	if len(bk.IPs) != 4 {
		t.Errorf("IPs=%v want 4", bk.IPs)
	}
	if len(bk.CIDRs) != 1 {
		t.Errorf("CIDRs=%v want 1", bk.CIDRs)
	}
	if len(bk.URLs) != 1 {
		t.Errorf("URLs=%v want 1", bk.URLs)
	}
	if len(bk.Roots) != 1 {
		t.Errorf("Roots=%v want 1", bk.Roots)
	}
	if len(bk.Subs) != 1 {
		t.Errorf("Subs=%v want 1", bk.Subs)
	}
	if len(bk.Companies) != 1 {
		t.Errorf("Companies=%v want 1", bk.Companies)
	}
	if bk.OrderTotal != 7 {
		t.Errorf("OrderTotal=%d want 7", bk.OrderTotal)
	}
}
