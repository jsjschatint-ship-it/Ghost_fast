package runner

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// dnsInstalled 用 sync.Once 保证 net.DefaultResolver 只被改一次（避免并发 runner 互相覆盖）
var dnsInstalled sync.Once

// installCustomDNS 替换 net.DefaultResolver，让 Go 的所有 DNS 解析都走指定的公网 DNS。
//
// 这是为了对抗用户机器上 Clash/V2Ray 等代理软件的 fake-ip 模式：
//
//	enhanced-mode: fake-ip
//
// 该模式下系统 DNS 被劫持，所有域名 → 198.18.x.x 假 IP，直连必死。
// 改用我们自己的 net.Resolver 通过 UDP 直连 8.8.8.8 / 223.5.5.5 等公网 DNS，
// 拿到真实 IP 后给 dial 用，从根本上绕过 fake-ip。
//
// 参数 servers：DNS 服务器列表，例 ["223.5.5.5:53", "8.8.8.8:53"]。
//   - 空 / nil → 用 defaultDNSServers
//   - 包含 "off" / "system" → 不安装自定义 resolver，回退系统 DNS
func installCustomDNS(servers []string) {
	// 显式关闭
	for _, s := range servers {
		if s == "off" || s == "system" || s == "false" || s == "0" {
			return
		}
	}
	dnsInstalled.Do(func() {
		// 规范化：补 :53 端口
		list := append([]string{}, servers...)
		if len(list) == 0 {
			list = append(list, defaultDNSServers...)
		}
		normalized := make([]string, 0, len(list))
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !strings.Contains(s, ":") {
				s += ":53"
			}
			normalized = append(normalized, s)
		}
		if len(normalized) == 0 {
			return
		}
		log.Printf("[runner] custom DNS resolver: %v", normalized)

		// 构造 round-robin dialer：依次尝试 servers，第一个能用就用
		net.DefaultResolver.PreferGo = true
		net.DefaultResolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			var lastErr error
			for _, srv := range normalized {
				// 强制 UDP（DNS 标准）；某些 Resolver 调用会传 tcp，统一改 udp
				netw := network
				if !strings.HasPrefix(netw, "udp") {
					netw = "udp"
				}
				conn, err := d.DialContext(ctx, netw, srv)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		}
	})
}
