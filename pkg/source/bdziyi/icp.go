package bdziyi

// bdziyi 的 ICP 备案查询（异步 + 滑块验证码代理）：
//   POST /icp/php/pyicp_query.php   {action:"single", target, type:"web"|"app"|"mapp"|"kapp"}
//      → {status, code, task_id}
//   GET  /icp/php/pyicp_poll.php?task_id=...&log_offset=N
//      → {status, progress, logs, log_offset, result, error}
// 默认 disabled，必须 cfg.bdziyi_icp.enabled=true 才会真正发起请求
// （因为消耗站点点数 + OCR/滑块 处理较慢）。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

const (
	bdICPQuery = "https://bdziyi.com/icp/php/pyicp_query.php"
	bdICPPoll  = "https://bdziyi.com/icp/php/pyicp_poll.php"
)

func (s *BDZiyi) searchICP(ctx context.Context, target string, cfg *source.SearchConfig) ([]*models.Asset, error) {
	// 开关：默认关闭
	if !s.configBool("enabled") {
		return nil, nil
	}
	cookie := s.cookie()
	if cookie == "" {
		return nil, nil // 未配 cookie 静默跳过
	}
	qtype := strings.ToLower(s.configString("type", "web"))
	pollMs := s.configInt("poll_interval_ms", 1500)
	maxWait := s.configInt("max_wait_sec", 60)

	headers := s.baseHeaders(bdHomeICP, "application/json")
	headers["Cookie"] = cookie

	// Step 1: 提交查询
	subBody, _ := json.Marshal(map[string]any{
		"action": "single",
		"target": strings.TrimSpace(target),
		"type":   qtype,
	})
	resp, err := s.client.R().
		SetContext(ctx).
		SetHeaders(headers).
		SetBodyJsonBytes(subBody).
		Post(bdICPQuery)
	if err != nil {
		return []*models.Asset{s.errAsset("提交异常: %v", err)}, nil
	}
	if resp.StatusCode != 200 {
		return []*models.Asset{s.errAsset("HTTP %d", resp.StatusCode)}, nil
	}
	sub := gjson.Parse(resp.String())
	if sub.Get("status").String() != "success" || sub.Get("task_id").String() == "" {
		return []*models.Asset{
			s.errAsset("提交失败: %s", sub.Get("message").String()),
		}, nil
	}
	taskID := sub.Get("task_id").String()

	// Step 2: 轮询
	deadline := time.Now().Add(time.Duration(maxWait) * time.Second)
	logOffset := int64(0)
	pollHeaders := s.baseHeaders(bdHomeICP, "")
	pollHeaders["Cookie"] = cookie

	var final gjson.Result
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		pr, err := s.client.R().
			SetContext(ctx).
			SetHeaders(pollHeaders).
			SetQueryParams(map[string]string{
				"task_id":    taskID,
				"log_offset": fmt.Sprintf("%d", logOffset),
			}).
			Get(bdICPPoll)
		if err != nil {
			time.Sleep(time.Duration(pollMs) * time.Millisecond)
			continue
		}
		j := gjson.Parse(pr.String())
		if v := j.Get("log_offset"); v.Exists() {
			logOffset = v.Int()
		}
		status := strings.ToLower(j.Get("status").String())
		if status == "done" || status == "success" || status == "completed" {
			final = j
			break
		}
		if status == "failed" || status == "error" {
			return []*models.Asset{
				s.errAsset("%s: 站点失败 %s", target, j.Get("error").String()),
			}, nil
		}
		time.Sleep(time.Duration(pollMs) * time.Millisecond)
	}
	if !final.Exists() {
		return []*models.Asset{
			s.errAsset("%s: 超时（%ds 未完成）", target, maxWait),
		}, nil
	}

	rows := final.Get("result").Array()
	out := make([]*models.Asset, 0, len(rows))
	for _, row := range rows {
		if !row.IsObject() {
			continue
		}
		a := icpRowToAsset(row, target, s.Name())
		if a != nil {
			out = append(out, a)
		}
		if cfg.MaxAssets > 0 && len(out) >= cfg.MaxAssets {
			break
		}
	}
	return out, nil
}

func icpRowToAsset(row gjson.Result, target, srcName string) *models.Asset {
	unit := strings.TrimSpace(row.Get("unitName").String())
	mainLic := strings.TrimSpace(row.Get("mainLicence").String())
	svcLic := strings.TrimSpace(row.Get("serviceLicence").String())
	nature := strings.TrimSpace(row.Get("natureName").String())
	contentType := strings.TrimSpace(row.Get("contentTypeName").String())
	updateTime := strings.TrimSpace(row.Get("updateRecordTime").String())
	domain := strings.ToLower(strings.TrimSpace(row.Get("domain").String()))
	if domain == "" {
		domain = strings.ToLower(strings.TrimSpace(target))
	}
	icp := svcLic
	if icp == "" {
		icp = mainLic
	}
	tags := []string{"bdziyi", "bdziyi-icp"}
	if nature != "" {
		tags = append(tags, "主体:"+nature)
	}
	if contentType != "" {
		tags = append(tags, "类型:"+contentType)
	}
	if v := strings.ToLower(strings.TrimSpace(row.Get("limitAccess").String())); v == "限制接入" || v == "true" {
		tags = append(tags, "限制接入")
	}
	return models.NewAsset().
		WithDomain(domain).
		WithHost(domain).
		WithOrg(unit).
		WithICP(icp).
		WithUpdateTime(updateTime).
		WithTitle(unit).
		WithSource(srcName).
		WithTags(tags...)
}
