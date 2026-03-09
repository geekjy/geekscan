package report

import (
	"encoding/json"
	"fmt"
	"os"
)

func GenerateJSON(data *ReportData, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}
