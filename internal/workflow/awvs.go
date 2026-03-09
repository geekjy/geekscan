package workflow

import (
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"go.temporal.io/sdk/workflow"
)

type AwvsInput struct {
	Targets []model.HttpxResult `json:"targets"`
	Options model.AwvsOptions   `json:"options"`
}

type AwvsOutput struct {
	Vulnerabilities []model.VulnResult `json:"vulnerabilities"`
	ScanIDs         []string           `json:"scan_ids"`
}

func AwvsWorkflow(ctx workflow.Context, input AwvsInput) (*AwvsOutput, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("AwvsWorkflow started", "targetCount", len(input.Targets))

	ao := workflow.ActivityOptions{
		StartToCloseTimeout: time.Duration(input.Options.MaxTime+10) * time.Minute,
		HeartbeatTimeout:    60 * time.Second,
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	output := &AwvsOutput{}

	for _, target := range input.Targets {
		var targetID string
		if err := workflow.ExecuteActivity(ctx, "AwvsAddTargetActivity", target.URL, input.Options).Get(ctx, &targetID); err != nil {
			logger.Warn("AWVS add target failed", "url", target.URL, "error", err)
			continue
		}

		var scanID string
		if err := workflow.ExecuteActivity(ctx, "AwvsCreateScanActivity", targetID, input.Options).Get(ctx, &scanID); err != nil {
			logger.Warn("AWVS create scan failed", "error", err)
			continue
		}
		output.ScanIDs = append(output.ScanIDs, scanID)
	}

	for _, scanID := range output.ScanIDs {
		var vulns []model.VulnResult
		if err := workflow.ExecuteActivity(ctx, "AwvsPollScanActivity", scanID, input.Options).Get(ctx, &vulns); err != nil {
			logger.Warn("AWVS poll failed", "scanID", scanID, "error", err)
			continue
		}
		output.Vulnerabilities = append(output.Vulnerabilities, vulns...)
	}

	logger.Info("AwvsWorkflow completed", "vulns", len(output.Vulnerabilities))
	return output, nil
}
