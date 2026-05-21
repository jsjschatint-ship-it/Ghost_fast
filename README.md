# Ghost Fast — 企业信息收集（被动 + 主动）

Ghost / ENScan 体系的开源简版。Go 重写的多源资产测绘 / 攻击面发现工具，单二进制 + Web Dashboard，专注于授权场景下的合规信息收集与基础主动验证。

> 兼容 ENScan Python 版的配置文件格式，迁移零成本。

---

## 下载

预编译二进制：**[Releases](https://github.com/jsjschatint-ship-it/Ghost_fast/releases)**

| 平台 | 文件 |
|---|---|
| Windows x64 | `ghost_windows_amd64.exe` |
| Windows ARM64 | `ghost_windows_arm64.exe` |
| macOS Intel | `ghost_darwin_amd64` |
| macOS Apple Silicon | `ghost_darwin_arm64` |
| Linux x64 | `ghost_linux_amd64` |
| Linux ARM64 | `ghost_linux_arm64` |

校验：每次 Release 附带 `SHA256SUMS.txt`，下载后验证：

```bash
sha256sum -c SHA256SUMS.txt    # Linux/macOS
Get-FileHash ghost_windows_amd64.exe -Algorithm SHA256   # PowerShell
```

macOS / Linux 下载后记得 `chmod +x ghost_*`。

---

## 快速开始

### 1) Web Dashboard 模式（推荐）

```bash
# 复制配置模板，填入你的 API Key（FOFA / Quake / Hunter / Shodan ...）
cp config.empty.yaml config.yaml

# 启动 Web 控制台（默认 :8080）
./ghost server -c config.yaml

# 加 token 防止公网裸跑
./ghost server -c config.yaml --auth-token=$(openssl rand -hex 16)
```

浏览器打开 `http://localhost:8080`，左侧导航：

- **被动采集** — 单/多目标、多数据源勾选式启停、跨源去重、xlsx/csv/json 导出
- **主动探测** — 子域爆破 / HTTP 指纹 / 端口扫 / DNS 高级 / **JS 爬取** / TLS 证书 / DNS 记录 / 敏感文件 / CDN-WAF / ASN / Whois-RDAP / WebMeta
- **历史 / 编排链** — 多步 pipeline 串接、历史记录回溯

### 2) CLI 模式

```bash
# 单目标
./ghost -t example.com -c config.yaml

# 多目标 + 限制数据源
./ghost -T a.com,b.com -s fofa,quake,hunter -c config.yaml

# 子命令（13 个主动探测各自独立）
./ghost subbrute -t example.com -w wordlists/top20000.txt
./ghost jscrawl -t https://app.example.com --depth 3 --use-ast
./ghost portscan -t 192.0.2.0/24 --top1000
./ghost tlscert -t example.com --do-crtsh
./ghost --help    # 看全部子命令
```

查看版本：`./ghost version`

---

## 核心特性

**被动数据源**

- 测绘引擎：FOFA / Quake / Hunter / ZoomEye / Shodan / 零零信安 / Censys / Netlas / FullHunt / BinaryEdge / Onyphe / DAYDAYMAP
- DNS / 证书：crt.sh / CertSpotter / SecurityTrails / VirusTotal / DNSDumpster / RapidDNS / ThreatMiner
- 子公司 / 工商：百度站长 / Beianx / 中航 / 企业结构 API
- 历史快照：Wayback Machine / URLScan
- ASN / BGP：BGPView / bgp.he.net
- WHOIS / RDAP：实时 + 历史反查
- 邮箱 / 泄露索引：HIBP / EmailRep / HudsonRock / BreachDirectory / Hunter.io
- 其他公开 OSINT：AbuseIPDB / AlienVault OTX / GreyNoise / IPInfo / LeakIX / Maltiverse / InternetDB / Chaos / hackertarget / ...

**主动探测模块（13）**

| 模块 | 说明 |
|---|---|
| `subbrute` | 子域字典爆破 + 通配符识别（top5000/top20000） |
| `httpx` | HTTP 指纹 / favicon murmurhash / wappalyzer 风格识别 |
| `portscan` | TCP connect 扫描（top100/top1000）+ 服务识别 |
| `dnsadv` | AXFR 区域传输 + 子域接管 |
| `jscrawl` | **JS 爬虫**：递归 + form 抓取 + sourcemap 反扫 + secret 命中 + 外置 `katana` + AST 模板字符串提取 |
| `tlscert` | TLS handshake + crt.sh + favicon 哈希 |
| `dnsrecord` | 全类型 DNS 枚举 + TXT token 抽取 |
| `sensifile` | 敏感文件存在性（`.git/` `.env` `wp-admin` ...） |
| `cdninfo` | CDN/WAF 指纹 + 源站 hunting |
| `asn` | ASN/BGP 网段扩展 |
| `whoisrdap` | RDAP + WHOIS 实时查 + 反查 |
| `webmeta` | 网页元信息 + robots/sitemap |

**JS 爬虫亮点（jscrawl）**

21 项 [katana](https://github.com/projectdiscovery/katana) 等价特性 + 5 项独有：

- 内置 secret 扫描（API Key / JWT / 私钥 / OAuth token）
- `.js.map` 反扫复原源码（含 sourcesContent 二次扫密）
- WebSocket URL / Form / Parameter 全自动聚合
- 路由对象 `{ path: "/users/:id" }` 提取（goja AST）
- 模板字符串 `` `${API}/users/${id}` `` 还原为 pattern
- 可选 shell out 到本地 `katana` 二进制（开 Chrome headless 跑 SPA）

---

## 从源码编译

需要 **Go 1.22+**：

```bash
# 单平台编译当前机器架构
go build -o ghost ./cmd/enscan

# 跨平台一次性编全部 6 个目标 (windows/mac/linux × amd64/arm64)
.\scripts\build-all.ps1            # Windows PowerShell
# 或单独某一个：
.\scripts\build-all.ps1 -Filter linux
```

产物在 `dist/`，附 `SHA256SUMS.txt`。

CI 自动 Release：推 `v*.*.*` tag 触发 [.github/workflows/release.yml](.github/workflows/release.yml)，自动编全平台 + 创建 GitHub Release。

```bash
git tag v0.1.0 -m "first public release"
git push origin v0.1.0
# → 几分钟后 Releases 页面就有产物
```

---

## 配置文件

参考 `config.empty.yaml`（注意：**真实 `config.yaml` 已被 `.gitignore` 忽略**，绝不会上传到仓库）。

API Key 优先级：CLI 参数 > 环境变量 > `config.yaml` > 默认（空）。

```yaml
engines:
  fofa:
    keys: ["EMAIL+KEY1", "EMAIL+KEY2"]   # 多 key 自动轮询
  quake:
    keys: ["YOUR_QUAKE_KEY"]
  hunter:
    keys: ["YOUR_HUNTER_KEY"]
  shodan:
    keys: ["YOUR_SHODAN_KEY"]
runner:
  enabled_sources: [fofa, quake, crt_sh, wayback, certspotter]
  max_concurrency: 8
  timeout: 30
  proxy: ""   # http://127.0.0.1:8080
```

---

## 安全 / 合规

- **被动模式默认不发任何流量到目标**；只查测绘 API + 公共 CT log + 历史快照
- **主动模式** 会真实发包到目标，使用前请确认授权（HW/SRC 范围内）
- 全局 `--proxy` 支持，必要时走 Burp/mitmproxy 审计流量
- 全局限速 / 重试 / 超时，避免对目标产生异常负载
- `config.yaml` 自动被 `.gitignore` 排除，密钥不外泄

---

## 目录结构

```
cmd/enscan/                  CLI 主入口（cobra）
internal/subcmd/             13 个主动探测子命令 + server
pkg/active/                  主动探测库代码
  ├── subdomain/             子域爆破
  ├── httpx/                 HTTP 指纹
  ├── portscan/              TCP 扫
  ├── jscrawl/               JS 爬虫（21 项 katana 兼容 + AST）
  ├── katana/                外置 katana shell-out 集成
  ├── tlscert/               TLS + crt.sh + favicon
  ├── dnsadv/ dnsrecord/     DNS 高级 / 全类型
  ├── sensifile/ cdninfo/    敏感文件 / CDN-WAF
  ├── asn/ whoisrdap/        ASN / WHOIS
  └── webmeta/               网页元信息
pkg/source/                  公开数据源
pkg/engine/                  测绘引擎适配器
pkg/runner/ pkg/core/        编排 / 去重 / 导出
pkg/config/ pkg/models/      配置 / 数据模型
scripts/build-all.ps1        跨平台构建脚本
.github/workflows/           CI（tag 自动 Release）
```

---

## License / Credits

- 兼容并致敬 [ENScan](https://github.com/wgpsec/ENScan_GO) 原 Python 项目
- JS 爬虫思路参考 [projectdiscovery/katana](https://github.com/projectdiscovery/katana)
- AST 解析基于 [dop251/goja](https://github.com/dop251/goja)

仅用于 **合法的安全测试 / SRC 漏洞挖掘 / 红队评估**，使用者承担所有合规责任。
