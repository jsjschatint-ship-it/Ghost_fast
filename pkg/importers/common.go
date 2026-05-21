// Package importers 提供 xlsx 文件 → Asset 列表的导入器。
// 对应 Python 版 importers/*.py。
package importers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

// ReadXLSXRows 读取首个 sheet，返回 list of dict（首行为表头）。
func ReadXLSXRows(path string) ([]map[string]string, error) {
	f, err := excelize.OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("open xlsx: %w", err)
	}
	defer f.Close()

	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, nil
	}
	rows, err := f.GetRows(sheets[0])
	if err != nil {
		return nil, fmt.Errorf("get rows: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	headers := rows[0]
	out := make([]map[string]string, 0, len(rows)-1)
	for _, r := range rows[1:] {
		m := make(map[string]string, len(headers))
		for i, h := range headers {
			if i < len(r) {
				m[h] = r[i]
			} else {
				m[h] = ""
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// S 取字符串字段并 trim
func S(m map[string]string, key string) string {
	if v, ok := m[key]; ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// I 转 int，失败返回 0
func I(m map[string]string, key string) int {
	v := S(m, key)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	// 兼容 "8080.0"
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return int(f)
	}
	return 0
}

// SOr 返回首个非空字段
func SOr(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := S(m, k); v != "" {
			return v
		}
	}
	return ""
}
