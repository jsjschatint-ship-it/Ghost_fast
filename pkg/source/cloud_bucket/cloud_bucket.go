package cloud_bucket

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
	"golang.org/x/net/publicsuffix"
)

// CloudBucket 实现云存储桶枚举
type CloudBucket struct {
	*source.BaseSource
	templates []bucketTemplate
}

type bucketTemplate struct {
	provider string
	pattern  string // 支持 {name} {region} {suffix}
}

// NewCloudBucket 创建 CloudBucket
func NewCloudBucket() *CloudBucket {
	s := &CloudBucket{
		BaseSource: source.NewBaseSource("cloud_bucket"),
		templates:  buildTemplates(),
	}
	return s
}

// Name 返回名称
func (s *CloudBucket) Name() string {
	return s.BaseSource.Name()
}

// Accepts 接受的输入类型
func (s *CloudBucket) Accepts() []string {
	return []string{"domain", "company"}
}

// NeedsKey 是否需要 API Key
func (s *CloudBucket) NeedsKey() bool {
	return false
}

// SetConfig 设置配置
func (s *CloudBucket) SetConfig(cfg map[string]any) error {
	_ = s.BaseSource.SetConfig(cfg)
	return nil
}

// Search 执行搜索
func (s *CloudBucket) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	cfg := &source.SearchConfig{
		MaxAssets: 800,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	// 生成候选桶名
	candidates := s.generateCandidates(target, cfg)
	if len(candidates) == 0 {
		return nil, nil
	}

	var allAssets []*models.Asset
	var mu sync.Mutex
	var wg sync.WaitGroup
	seenHost := make(map[string]struct{}, len(candidates)) // 结果去重，防止不同模板碰撞同一 host

	for _, cand := range candidates {
		wg.Add(1)
		go func(c candidate) {
			defer wg.Done()
			// DNS 解析检查
			ips, err := net.LookupHost(c.host)
			if err != nil || len(ips) == 0 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if _, dup := seenHost[c.host]; dup {
				return
			}
			seenHost[c.host] = struct{}{}
			if cfg.MaxAssets > 0 && len(allAssets) >= cfg.MaxAssets {
				return
			}
			asset := models.NewAsset().
				WithTitle(fmt.Sprintf("[%s] %s", c.provider, c.host)).
				WithHost(c.host).
				WithSource(s.Name()).
				WithTags("cloud", "bucket", c.provider).
				WithRaw("provider", c.provider).
				WithRaw("region", c.region).
				WithRaw("ips", strings.Join(ips, ","))
			allAssets = append(allAssets, asset)
		}(cand)
	}
	wg.Wait()

	if cfg.MaxAssets > 0 && len(allAssets) > cfg.MaxAssets {
		allAssets = allAssets[:cfg.MaxAssets]
	}
	return allAssets, nil
}

type candidate struct {
	provider string
	host     string
	region   string
}

// generateCandidates 生成候选桶名
func (s *CloudBucket) generateCandidates(target string, cfg *source.SearchConfig) []candidate {
	if cfg == nil {
		cfg = &source.SearchConfig{}
	}
	// 从目标提取公司名/域名根
	base := s.extractBase(target)
	var names []string
	if base != "" {
		names = append(names, base)
	}
	// 从 cfg.Extra 读取额外候选名称
	if cfg.Extra != nil {
		if extra, ok := cfg.Extra["extra_names"].([]string); ok {
			names = append(names, extra...)
		} else if extra, ok := cfg.Extra["extra_names"].([]any); ok {
			for _, x := range extra {
				if s, ok2 := x.(string); ok2 {
					names = append(names, s)
				}
			}
		}
	}

	// 区域：默认覆盖主要区域，可被 cfg.Extra["regions"] 覆盖
	regions := []string{"us-east-1", "us-west-1", "us-west-2", "eu-west-1", "ap-northeast-1", "ap-southeast-1", "cn-north-1", "cn-northwest-1"}
	if cfg.Extra != nil {
		if v, ok := cfg.Extra["regions"].([]string); ok && len(v) > 0 {
			regions = v
		} else if v, ok := cfg.Extra["regions"].([]any); ok && len(v) > 0 {
			regions = regions[:0]
			for _, x := range v {
				if s, ok2 := x.(string); ok2 {
					regions = append(regions, s)
				}
			}
		}
	}

	// 候选去重：模板里如果没有 {region}/{suffix} 占位符，外层循环会产生 N 次相同字符串；
	// 必须在 DNS 之前按 host 去重，否则同一个 host 会被解析 N 次且生成 N 条重复 asset。
	seen := make(map[string]struct{}, 1024)
	var candidates []candidate
	suffixes := []string{"", "-storage", "-bucket", "-data"}
	for _, name := range names {
		if name == "" {
			continue
		}
		for _, tmpl := range s.templates {
			hasRegion := strings.Contains(tmpl.pattern, "{region}")
			hasSuffix := strings.Contains(tmpl.pattern, "{suffix}")
			regionList := regions
			if !hasRegion {
				regionList = []string{""} // 跳过 region 循环
			}
			suffixList := suffixes
			if !hasSuffix {
				suffixList = []string{""}
			}
			for _, region := range regionList {
				for _, suf := range suffixList {
					h := strings.ReplaceAll(tmpl.pattern, "{name}", name)
					h = strings.ReplaceAll(h, "{region}", region)
					h = strings.ReplaceAll(h, "{suffix}", suf)
					if _, dup := seen[h]; dup {
						continue
					}
					seen[h] = struct{}{}
					candidates = append(candidates, candidate{
						provider: tmpl.provider,
						host:     h,
						region:   region,
					})
				}
			}
		}
	}
	return candidates
}

// extractBase 从目标提取基础名称（用 publicsuffix 拿 eTLD+1，再去掉 TLD 段）。
// 例：
//
//	www.baidu.com   → baidu
//	news.baidu.com  → baidu          （而不是错误的 "news"）
//	test.example.co.uk → example      （eTLD = co.uk）
//	target="baidu"  → baidu          （没有点的字符串当公司名直接用）
func (s *CloudBucket) extractBase(target string) string {
	t := strings.ToLower(strings.TrimSpace(target))
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.Index(t, ":"); i >= 0 {
		t = t[:i]
	}
	t = strings.TrimSpace(strings.Trim(t, "."))
	if t == "" {
		return ""
	}
	// 没有点 → 公司名 / 单词，直接用
	if !strings.Contains(t, ".") {
		return t
	}
	// 用 publicsuffix 拿真正的注册域 (eTLD+1)；再切掉 TLD 留下二级名
	etld1, err := publicsuffix.EffectiveTLDPlusOne(t)
	if err != nil || etld1 == "" {
		// 兜底：取最后一个 . 之前的那一段
		parts := strings.Split(t, ".")
		if len(parts) >= 2 {
			return parts[len(parts)-2]
		}
		return t
	}
	if i := strings.Index(etld1, "."); i > 0 {
		return etld1[:i]
	}
	return etld1
}

// buildTemplates 构建桶名模板
func buildTemplates() []bucketTemplate {
	return []bucketTemplate{
		{"AWS S3", "{name}.s3.{region}.amazonaws.com"},
		{"AWS S3", "{name}-{region}.s3.amazonaws.com"},
		{"AWS S3", "{name}.s3.amazonaws.com"},
		{"阿里云 OSS", "{name}.oss-{region}.aliyuncs.com"},
		{"阿里云 OSS", "{name}.oss-cn-{region}.aliyuncs.com"},
		{"腾讯云 COS", "{name}-{region}.cos.myqcloud.com"},
		{"腾讯云 COS", "{name}.cos.ap-{region}.myqcloud.com"},
		{"华为云 OBS", "{name}.obs.{region}.myhuaweicloud.com"},
		{"华为云 OBS", "{name}.obs-{region}.myhuaweicloud.com"},
		{"Azure Blob", "{name}.blob.core.windows.net"},
		{"GCP GCS", "{name}.storage.googleapis.com"},
		{"七牛云 Kodo", "{name}.qiniudns.com"},
		{"七牛云 Kodo", "{name}.qn.qiniudns.com"},
		{"又拍云 UPYUN", "{name}.upyun.com"},
		{"青云 QingStor", "{name}.qingstor.com"},
	}
}
