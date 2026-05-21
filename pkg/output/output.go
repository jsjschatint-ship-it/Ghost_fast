package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/wgpsec/ENScan/pkg/models"
	"gopkg.in/yaml.v3"
)

// Format 输出格式
type Format string

const (
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
	FormatText Format = "text"
)

// Write 输出资产到文件或标准输出
func Write(assets []*models.Asset, format Format, filename string) error {
	if filename != "" {
		f, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		return writeStream(f, assets, format)
	}
	return writeStream(os.Stdout, assets, format)
}

// writeStream 输出到流
func writeStream(w *os.File, assets []*models.Asset, format Format) error {
	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(assets)
	case FormatYAML:
		data, err := yaml.Marshal(assets)
		if err != nil {
			return fmt.Errorf("marshal yaml: %w", err)
		}
		_, err = w.Write(data)
		return err
	case FormatText:
		// 简洁文本格式
		fmt.Fprintf(w, "# %d assets\n", len(assets))
		for _, a := range assets {
			var tags []string
			if len(a.Tags) > 0 {
				tags = a.Tags
			}
			line := fmt.Sprintf("- %s", a.Title)
			if a.Host != "" {
				line += fmt.Sprintf(" | host=%s", a.Host)
			}
			if a.Source != "" {
				line += fmt.Sprintf(" | source=%s", a.Source)
			}
			if len(tags) > 0 {
				line += fmt.Sprintf(" | tags=%s", strings.Join(tags, ","))
			}
			fmt.Fprintln(w, line)
		}
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}
