# 无流量·可视化信息收集系统

完全**被动**的资产测绘聚合平台：仅调用第三方测绘 API 与读取本地导出表，**绝不向目标资产发送任何探测流量**。

## 数据源

| 类型 | 来源 | 说明 |
|---|---|---|
| 本地导入 | FOFA xlsx 导出 | 兼容 FOFA 网页"导出全部"格式 |
| 本地导入 | Quake xlsx 导出 | 兼容 360 Quake 网页"数据导出"格式 |
| 被动 API | FOFA | `host` 接口聚合 + `search` 接口明细 |
| 被动 API | Quake | `service/search` 接口 |
| 被动 API | Hunter | 奇安信 Hunter 资产搜索 |
| 被动 API | ZoomEye | 知道创宇 search/host |
| 被动 API | Shodan | shodan/host/search |
| 被动 API | 零零信安 0.zone | OpenAPI 资产搜索 |
| 被动 API | crt.sh | 证书透明度日志（无需 key） |
| 被动 API | Wayback Machine | web.archive.org CDX 历史快照（无需 key） |

## 快速开始

```bash
pip install -r requirements.txt
copy config.yaml.example config.yaml   # 填入你的 API Key
streamlit run app.py
```

浏览器打开 `http://localhost:8501`，左侧上传你已有的 `FOFA_*.xlsx` / `Quake_*.xlsx`，或填写查询语句，点 **开始收集** 即可。

## 功能

- 多源聚合 + 跨源去重（按 ip:port + domain 维度）
- 统一资产模型（IP / 域名 / 端口 / 协议 / 服务 / 标题 / 指纹 / 证书 / 地理位置 / ASN）
- 可视化：端口分布、服务/组件 TOP、国家地图、ASN 分布、根域子域树
- 资产打标：CDN 识别、敏感端口、可疑后台、登录入口
- 一键导出：合并后的 xlsx / csv / json

## 目录结构

```
.
├── app.py                 # Streamlit 主界面
├── cli.py                 # 命令行入口（可选）
├── config.yaml.example
├── requirements.txt
├── core/
│   ├── models.py          # Asset 数据模型
│   ├── normalize.py       # 各源字段 -> Asset
│   ├── dedup.py           # 跨源去重合并
│   ├── tagger.py          # CDN / 敏感资产打标
│   ├── exporter.py        # 导出 xlsx/csv/json
│   └── engines/
│       ├── base.py
│       ├── fofa.py
│       ├── quake.py
│       ├── hunter.py
│       ├── zoomeye.py
│       └── shodan.py
├── importers/
│   ├── fofa_xlsx.py
│   └── quake_xlsx.py
└── plugins/
    └── ct_log.py          # crt.sh
```

## 安全说明

- 所有引擎 **仅与第三方测绘平台通信**，不直连目标主机
- crt.sh 也是查询公共 CT 日志，不接触目标
- 你导入的 xlsx 完全本地处理
