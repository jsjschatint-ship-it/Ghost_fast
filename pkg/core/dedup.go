package core

import (
	"fmt"
	"strings"

	"github.com/wgpsec/ENScan/pkg/models"
)

// KeyStrategy 主键策略
type KeyStrategy string

const (
	KeySmart    KeyStrategy = "smart"
	KeyIPPort   KeyStrategy = "ip_port"
	KeyIP       KeyStrategy = "ip"
	KeyDomain   KeyStrategy = "domain"
	KeyURL      KeyStrategy = "url"
	KeyHostPort KeyStrategy = "host_port"
	// KeyCustom：从 customFields 里按顺序取字段值拼成 key（任一字段为空 → 整条丢弃）
	KeyCustom KeyStrategy = "custom"
)

// CustomDedupFields 支持的自定义字段名（小写）。
// 与 KeyCustom 配合用；map value = 提取函数，返回该字段在某条 asset 上的字符串值。
var CustomDedupFields = map[string]func(*models.Asset) string{
	"ip": func(a *models.Asset) string { return a.IP },
	"port": func(a *models.Asset) string {
		if a.Port == 0 {
			return ""
		}
		return fmt.Sprintf("%d", a.Port)
	},
	"host":     func(a *models.Asset) string { return strings.ToLower(a.Host) },
	"domain":   func(a *models.Asset) string { return strings.ToLower(a.Domain) },
	"url":      func(a *models.Asset) string { return strings.ToLower(a.URL) },
	"title":    func(a *models.Asset) string { return a.Title },
	"service":  func(a *models.Asset) string { return strings.ToLower(a.Service) },
	"protocol": func(a *models.Asset) string { return strings.ToLower(a.Protocol) },
	"asn":      func(a *models.Asset) string { return a.ASN },
	"country":  func(a *models.Asset) string { return a.Country },
	"source":   func(a *models.Asset) string { return a.Source },
}

// Deduper 去重器
type Deduper struct {
	strategy KeyStrategy
	// 仅 KeyCustom 用：按这里的顺序拼接字段值；map 中查不到的字段名直接忽略
	customFields []string
}

// NewDeduper 创建去重器
func NewDeduper(strategy KeyStrategy) *Deduper {
	if strategy == "" {
		strategy = KeySmart
	}
	return &Deduper{strategy: strategy}
}

// NewCustomDeduper 创建自定义字段组合的去重器。
func NewCustomDeduper(fields []string) *Deduper {
	clean := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if _, ok := CustomDedupFields[f]; ok {
			clean = append(clean, f)
		}
	}
	return &Deduper{strategy: KeyCustom, customFields: clean}
}

// DedupCustom 等价于 DedupWithStats(KeyCustom)，但接受字段列表。
func DedupCustom(assets []*models.Asset, fields []string) ([]*models.Asset, DedupStats) {
	d := NewCustomDeduper(fields)
	return dedupWithDeduper(d, assets)
}

// DedupStats 去重统计（与 Python core/dedup.dedup_with_stats 对齐）
type DedupStats struct {
	Strategy     string `json:"strategy"`
	TotalIn      int    `json:"total_in"`
	TotalOut     int    `json:"total_out"`
	Reduced      int    `json:"reduced"`
	MergedGroups int    `json:"merged_groups"`  // 同 key 命中 >=2 次的组数
	DroppedNoKey int    `json:"dropped_no_key"` // 没法生成 key 而被丢弃的资产数
}

// DedupWithStats 函数式 wrapper：构造 Deduper、执行、附带统计返回。
// 等价 Python core/dedup.py 的 dedup_with_stats。
func DedupWithStats(assets []*models.Asset, strategy KeyStrategy) ([]*models.Asset, DedupStats) {
	return dedupWithDeduper(NewDeduper(strategy), assets)
}

// dedupWithDeduper 内部：用给定 Deduper 跑去重并返回统计。
func dedupWithDeduper(d *Deduper, assets []*models.Asset) ([]*models.Asset, DedupStats) {
	counts := map[string]int{}
	dropped := 0
	m := make(map[string]*models.Asset, len(assets))
	for _, a := range assets {
		if a == nil {
			dropped++
			continue
		}
		k := d.keyFunc(a)
		if k == "" {
			dropped++
			continue
		}
		counts[k]++
		if existing, ok := m[k]; ok {
			d.merge(existing, a)
		} else {
			m[k] = cloneAsset(a)
		}
	}
	out := make([]*models.Asset, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	merged := 0
	for _, c := range counts {
		if c > 1 {
			merged++
		}
	}
	stratName := string(d.strategy)
	if d.strategy == KeyCustom && len(d.customFields) > 0 {
		stratName = "custom:" + strings.Join(d.customFields, "+")
	}
	return out, DedupStats{
		Strategy:     stratName,
		TotalIn:      len(assets),
		TotalOut:     len(out),
		Reduced:      len(assets) - len(out),
		MergedGroups: merged,
		DroppedNoKey: dropped,
	}
}

// Dedup 执行去重合并
func (d *Deduper) Dedup(assets []*models.Asset) []*models.Asset {
	m := make(map[string]*models.Asset)
	for _, a := range assets {
		if a == nil {
			continue
		}
		key := d.keyFunc(a)
		if key == "" {
			continue
		}
		if existing, ok := m[key]; ok {
			d.merge(existing, a)
		} else {
			m[key] = cloneAsset(a)
		}
	}
	var out []*models.Asset
	for _, a := range m {
		out = append(out, a)
	}
	return out
}

// keyFunc 根据策略返回主键
func (d *Deduper) keyFunc(a *models.Asset) string {
	if a == nil {
		return ""
	}
	switch d.strategy {
	case KeyIPPort:
		if a.IP != "" && a.Port != 0 {
			return fmt.Sprintf("%s:%d", a.IP, a.Port)
		}
		return ""
	case KeyIP:
		return a.IP
	case KeyDomain:
		return strings.ToLower(a.Domain)
	case KeyURL:
		return strings.ToLower(a.URL)
	case KeyHostPort:
		host := a.Host
		if host == "" {
			host = a.Domain
		}
		if host != "" && a.Port != 0 {
			return fmt.Sprintf("%s:%d", strings.ToLower(host), a.Port)
		}
		return ""
	case KeyCustom:
		if len(d.customFields) == 0 {
			return a.Key() // 没指定字段就退化为 smart
		}
		parts := make([]string, 0, len(d.customFields))
		for _, f := range d.customFields {
			getter, ok := CustomDedupFields[f]
			if !ok {
				continue
			}
			v := getter(a)
			if v == "" {
				return "" // 任一必需字段为空 → 该资产无法成 key，丢弃
			}
			parts = append(parts, v)
		}
		return strings.Join(parts, "|")
	case KeySmart:
		fallthrough
	default:
		return a.Key()
	}
}

// merge 合并两个资产（非空覆盖）
func (d *Deduper) merge(existing, incoming *models.Asset) {
	// 非空覆盖（已有值不被空值覆盖）
	if existing.IP == "" && incoming.IP != "" {
		existing.IP = incoming.IP
	}
	if existing.Port == 0 && incoming.Port != 0 {
		existing.Port = incoming.Port
	}
	if existing.Protocol == "" && incoming.Protocol != "" {
		existing.Protocol = incoming.Protocol
	}
	if existing.Domain == "" && incoming.Domain != "" {
		existing.Domain = incoming.Domain
	}
	if existing.Host == "" && incoming.Host != "" {
		existing.Host = incoming.Host
	}
	if existing.URL == "" && incoming.URL != "" {
		existing.URL = incoming.URL
	}
	if existing.Service == "" && incoming.Service != "" {
		existing.Service = incoming.Service
	}
	if existing.Title == "" && incoming.Title != "" {
		existing.Title = incoming.Title
	}
	if existing.Server == "" && incoming.Server != "" {
		existing.Server = incoming.Server
	}
	if existing.OS == "" && incoming.OS != "" {
		existing.OS = incoming.OS
	}
	if existing.Country == "" && incoming.Country != "" {
		existing.Country = incoming.Country
	}
	if existing.Province == "" && incoming.Province != "" {
		existing.Province = incoming.Province
	}
	if existing.City == "" && incoming.City != "" {
		existing.City = incoming.City
	}
	if existing.ASN == "" && incoming.ASN != "" {
		existing.ASN = incoming.ASN
	}
	if existing.Org == "" && incoming.Org != "" {
		existing.Org = incoming.Org
	}
	if existing.ISP == "" && incoming.ISP != "" {
		existing.ISP = incoming.ISP
	}
	if existing.CertSubject == "" && incoming.CertSubject != "" {
		existing.CertSubject = incoming.CertSubject
	}
	if existing.CertIssuer == "" && incoming.CertIssuer != "" {
		existing.CertIssuer = incoming.CertIssuer
	}
	if existing.JARM == "" && incoming.JARM != "" {
		existing.JARM = incoming.JARM
	}
	if existing.JA3S == "" && incoming.JA3S != "" {
		existing.JA3S = incoming.JA3S
	}
	if existing.FaviconHash == "" && incoming.FaviconHash != "" {
		existing.FaviconHash = incoming.FaviconHash
	}
	if existing.ICP == "" && incoming.ICP != "" {
		existing.ICP = incoming.ICP
	}
	if existing.UpdateTime == "" && incoming.UpdateTime != "" {
		existing.UpdateTime = incoming.UpdateTime
	}
	// 列表字段：并集去重
	existing.Products = union(existing.Products, incoming.Products)
	existing.CertDomains = union(existing.CertDomains, incoming.CertDomains)
	existing.Tags = union(existing.Tags, incoming.Tags)
	// source：叠加为 "fofa+quake"
	if existing.Source != "" && incoming.Source != "" {
		existing.Source = existing.Source + "+" + incoming.Source
	} else if existing.Source == "" {
		existing.Source = incoming.Source
	}
	// raw：按源归档进 _extra（这里简单合并，实际可按源区分）
	if len(incoming.Raw) > 0 && existing.Raw == nil {
		existing.Raw = make(map[string]string, len(incoming.Raw))
	}
	for k, v := range incoming.Raw {
		existing.Raw[k] = v
	}
}

func cloneAsset(a *models.Asset) *models.Asset {
	if a == nil {
		return nil
	}
	cp := *a
	if a.Raw != nil {
		cp.Raw = make(map[string]string, len(a.Raw))
		for k, v := range a.Raw {
			cp.Raw[k] = v
		}
	}
	return &cp
}

// union 字符串切片并集去重
func union(a, b []string) []string {
	m := make(map[string]bool)
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		m[s] = true
	}
	var out []string
	for s := range m {
		out = append(out, s)
	}
	return out
}
