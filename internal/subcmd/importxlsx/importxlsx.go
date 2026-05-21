// Package importxlsx 提供 Ghost import-xlsx 子命令
package importxlsx

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/wgpsec/ENScan/pkg/importers"
	"github.com/wgpsec/ENScan/pkg/models"
)

// New 返回 cobra 子命令
func New() *cobra.Command {
	var in, out, kind string
	cmd := &cobra.Command{
		Use:   "import-xlsx",
		Short: "把 FOFA / Quake / 自家 recon 导出的 xlsx 转成统一资产 JSON/YAML",
		Long: `用法：
  Ghost import-xlsx --in fofa.xlsx  --kind fofa  --out assets.json
  Ghost import-xlsx --in quake.xlsx --kind quake --out assets.yaml
  Ghost import-xlsx --in recon.xlsx --kind recon --out assets.json
  Ghost import-xlsx --in any.xlsx   --kind auto`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if in == "" {
				return fmt.Errorf("missing --in <path>")
			}
			assets, used, err := dispatch(in, kind)
			if err != nil {
				return fmt.Errorf("import: %w", err)
			}
			fmt.Fprintf(os.Stderr, "[import-xlsx] %d 条资产从 %s 解析 (kind=%s)\n", len(assets), in, used)

			format := "json"
			if strings.HasSuffix(strings.ToLower(out), ".yaml") || strings.HasSuffix(strings.ToLower(out), ".yml") {
				format = "yaml"
			}
			var data []byte
			switch format {
			case "yaml":
				data, err = yaml.Marshal(assets)
			default:
				data, err = json.MarshalIndent(assets, "", "  ")
			}
			if err != nil {
				return fmt.Errorf("marshal: %w", err)
			}
			if out == "" {
				os.Stdout.Write(data)
				os.Stdout.Write([]byte("\n"))
				return nil
			}
			if err := os.WriteFile(out, data, 0644); err != nil {
				return fmt.Errorf("write: %w", err)
			}
			fmt.Fprintln(os.Stderr, "[import-xlsx] 已写入", out)
			return nil
		},
	}
	cmd.Flags().StringVar(&in, "in", "", "输入 xlsx 路径（必填）")
	cmd.Flags().StringVar(&out, "out", "", "输出文件路径，默认 stdout")
	cmd.Flags().StringVar(&kind, "kind", "auto", "fofa | quake | recon | auto")
	return cmd
}

func dispatch(path, kind string) ([]*models.Asset, string, error) {
	switch strings.ToLower(kind) {
	case "fofa":
		a, e := importers.ImportFOFAXLSX(path)
		return a, "fofa", e
	case "quake":
		a, e := importers.ImportQuakeXLSX(path)
		return a, "quake", e
	case "recon":
		a, e := importers.ImportReconXLSX(path)
		return a, "recon", e
	case "auto":
		rows, err := importers.ReadXLSXRows(path)
		if err != nil {
			return nil, "", err
		}
		if len(rows) == 0 {
			return nil, "auto", nil
		}
		headers := rows[0]
		if _, ok := headers["ICP备案号"]; ok {
			a, e := importers.ImportFOFAXLSX(path)
			return a, "fofa", e
		}
		if _, ok := headers["传输协议"]; ok {
			a, e := importers.ImportQuakeXLSX(path)
			return a, "quake", e
		}
		a, e := importers.ImportReconXLSX(path)
		return a, "recon", e
	default:
		return nil, "", fmt.Errorf("unknown --kind %q (fofa | quake | recon | auto)", kind)
	}
}
