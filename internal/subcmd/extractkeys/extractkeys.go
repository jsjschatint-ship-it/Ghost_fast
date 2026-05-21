// Package extractkeys 提供 Ghost extract-quake-keys 子命令
package extractkeys

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// New 返回 cobra 子命令
func New() *cobra.Command {
	return &cobra.Command{
		Use:   "extract-quake-keys <file>",
		Short: "从文件中提取 Quake API 密钥（32 位十六进制 + 上下文启发）",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			file := args[0]
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read %s: %w", file, err)
			}
			keys := extractQuakeKeys(string(data))
			fmt.Printf("Found %d Quake API keys:\n", len(keys))
			for _, k := range keys {
				fmt.Println(k)
			}
			return nil
		},
	}
}

func extractQuakeKeys(content string) []string {
	var keys []string
	re := regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	for _, m := range re.FindAllString(content, -1) {
		if isQuakeKey(m, content) {
			keys = append(keys, m)
		}
	}
	return keys
}

func isQuakeKey(key, content string) bool {
	lc := strings.ToLower(content)
	idx := strings.Index(lc, strings.ToLower(key))
	if idx == -1 {
		return false
	}
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + len(key) + 100
	if end > len(lc) {
		end = len(lc)
	}
	ctx := lc[start:end]
	return strings.Contains(ctx, "quake") ||
		strings.Contains(ctx, "api") ||
		strings.Contains(ctx, "key") ||
		strings.Contains(ctx, "token")
}
