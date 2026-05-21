// Package fofahelper 供应链系列插件共用的 FOFA 调用工具。
package fofahelper

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
)

// Client 轻量 FOFA 客户端
type Client struct {
	Key     string
	Email   string
	Proxy   string
	Timeout time.Duration
	rc      *req.Client
}

// New 创建客户端
func New(key string) *Client {
	return &Client{Key: key, Timeout: 30 * time.Second}
}

// build 构造底层 client
func (c *Client) build() *req.Client {
	if c.rc != nil {
		return c.rc
	}
	rc := req.C().SetTimeout(c.Timeout).SetUserAgent("Mozilla/5.0 (compatible; PassiveRecon/1.0)")
	if c.Proxy != "" {
		rc.SetProxyURL(c.Proxy)
	}
	c.rc = rc
	return rc
}

// Row FOFA 一行结果（fields → value）
type Row map[string]string

// Search 执行搜索
func (c *Client) Search(ctx context.Context, query, fields string, size int) ([]Row, error) {
	if c.Key == "" {
		return nil, fmt.Errorf("fofa key empty")
	}
	qb64 := base64.StdEncoding.EncodeToString([]byte(query))
	r := c.build().R().
		SetContext(ctx).
		SetHeader("Accept", "application/json").
		SetQueryParam("key", c.Key).
		SetQueryParam("qbase64", qb64).
		SetQueryParam("page", "1").
		SetQueryParam("size", strconv.Itoa(size)).
		SetQueryParam("fields", fields).
		SetQueryParam("full", "false")
	if c.Email != "" {
		r.SetQueryParam("email", c.Email)
	}
	resp, err := r.Get("https://fofa.info/api/v1/search/all")
	if err != nil {
		return nil, fmt.Errorf("fofa request: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fofa status %d", resp.StatusCode)
	}
	body := resp.String()
	if gjson.Get(body, "error").Bool() {
		return nil, fmt.Errorf("fofa error: %s", gjson.Get(body, "errmsg").String())
	}
	fnames := strings.Split(fields, ",")
	rows := gjson.Get(body, "results").Array()
	out := make([]Row, 0, len(rows))
	for _, row := range rows {
		arr := row.Array()
		m := make(Row, len(fnames))
		for i, f := range fnames {
			if i < len(arr) {
				m[strings.TrimSpace(f)] = arr[i].String()
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// SearchPaginated 分页拉取，返回 Row 列表（按 host/link/domain/ip/port/title 字段最易转 Asset）
func (c *Client) SearchPaginated(ctx context.Context, query, fields string, maxTotal int) ([]Row, error) {
	if c.Key == "" {
		return nil, fmt.Errorf("fofa key empty")
	}
	if maxTotal <= 0 {
		maxTotal = 1000
	}
	qb64 := base64.StdEncoding.EncodeToString([]byte(query))
	const pageSize = 100
	var out []Row
	fnames := strings.Split(fields, ",")
	for page := 1; page <= 100 && len(out) < maxTotal; page++ {
		r := c.build().R().
			SetContext(ctx).
			SetHeader("Accept", "application/json").
			SetQueryParam("key", c.Key).
			SetQueryParam("qbase64", qb64).
			SetQueryParam("page", strconv.Itoa(page)).
			SetQueryParam("size", strconv.Itoa(pageSize)).
			SetQueryParam("fields", fields).
			SetQueryParam("full", "false")
		if c.Email != "" {
			r.SetQueryParam("email", c.Email)
		}
		resp, err := r.Get("https://fofa.info/api/v1/search/all")
		if err != nil {
			return out, err
		}
		if resp.StatusCode != 200 {
			return out, fmt.Errorf("fofa status %d", resp.StatusCode)
		}
		body := resp.String()
		if gjson.Get(body, "error").Bool() {
			return out, fmt.Errorf("fofa: %s", gjson.Get(body, "errmsg").String())
		}
		rows := gjson.Get(body, "results").Array()
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			arr := row.Array()
			m := make(Row, len(fnames))
			for i, f := range fnames {
				if i < len(arr) {
					m[strings.TrimSpace(f)] = arr[i].String()
				}
			}
			out = append(out, m)
			if len(out) >= maxTotal {
				return out, nil
			}
		}
		if len(rows) < pageSize {
			break
		}
	}
	return out, nil
}

// RowToAssetFields 把 Row 转换为常用字段（host/ip/port/title/domain/url）。
func RowToAssetFields(r Row) (host, ip string, port int, title, domain, urlStr string) {
	host = r["host"]
	ip = r["ip"]
	if p, err := strconv.Atoi(r["port"]); err == nil {
		port = p
	}
	title = r["title"]
	domain = r["domain"]
	urlStr = r["link"]
	return
}
