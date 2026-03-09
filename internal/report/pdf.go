package report

import (
	"fmt"
	"os"
)

// GeneratePDF is a stub that writes a placeholder file.
// Replace with a real PDF library (e.g. go-wkhtmltopdf, gofpdf) later.
func GeneratePDF(data *ReportData, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "PDF generation not yet implemented.\nTask: %s\nTargets: %v\n", data.TaskName, data.Targets)
	if err != nil {
		return fmt.Errorf("write stub: %w", err)
	}
	return nil
}
