// Package wayback 提供 Wayback Machine 的轻量工具：把 URL 解析为最新缓存快照。
// 用于让需要读 JS / .js.map 的 source 改走 archive.org 缓存，
// 从而对目标实现 0 流量。
package wayback

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
)

const availabilityURL = "https://archive.org/wayback/available"

// SnapshotURL 通过 Wayback availability API 解析 url 的最新快照实际地址。
// 命中返回完整的 https://web.archive.org/web/<ts>/<url>，未命中返回空串。
// raw=true 会把 https://web.archive.org/web/<ts>id_/<url> 形式返回，
// 取到的是原始未改写的资源体（适合做 JS / source map 解析）。
func SnapshotURL(ctx context.Context, c *req.Client, target string, raw bool) (string, error) {
	if c == nil {
		c = req.C().SetTimeout(20 * time.Second).SetUserAgent("Ghost/1.0 (passive)")
	}
	resp, err := c.R().
		SetContext(ctx).
		SetQueryParam("url", target).
		Get(availabilityURL)
	if err != nil {
		return "", fmt.Errorf("wayback availability: %w", err)
	}
	body := resp.String()
	if !gjson.Valid(body) {
		return "", fmt.Errorf("wayback availability: invalid json")
	}
	closest := gjson.Get(body, "archived_snapshots.closest")
	if !closest.Exists() || !closest.Get("available").Bool() {
		return "", nil
	}
	snap := closest.Get("url").String()
	if snap == "" {
		return "", nil
	}
	if raw {
		// https://web.archive.org/web/20240101000000/https://x.com/a.js
		// -> https://web.archive.org/web/20240101000000id_/https://x.com/a.js
		// id_ 后缀返回原始字节，不带 archive.org 注入的脚本/横幅
		if idx := strings.LastIndex(snap, "/http"); idx > 0 {
			tsPart := snap[:idx]
			rest := snap[idx:]
			return tsPart + "id_" + rest, nil
		}
	}
	return snap, nil
}

// IsLikelySameHost 粗判 jsURL 与 target 同源（用于决定是否走 wayback）。
func IsLikelySameHost(jsURL, target string) bool {
	ju, err := url.Parse(jsURL)
	if err != nil {
		return false
	}
	tu, err := url.Parse(ensureScheme(target))
	if err != nil {
		return false
	}
	return ju.Host != "" && tu.Host != "" && strings.EqualFold(ju.Host, tu.Host)
}

func ensureScheme(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	return "https://" + s
}
