package workflow

import (
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"go.temporal.io/sdk/workflow"
)

type BruteTarget struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
}

type BruteForceInput struct {
	Targets []BruteTarget         `json:"targets"`
	Options model.BruteForceOptions `json:"options"`
}

type BruteForceOutput struct {
	Results []model.BruteResult `json:"results"`
}

func BruteForceWorkflow(ctx workflow.Context, input BruteForceInput) (*BruteForceOutput, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("BruteForceWorkflow started", "targetCount", len(input.Targets))

	ao := workflow.ActivityOptions{
		StartToCloseTimeout: time.Duration(input.Options.MaxTime+5) * time.Minute,
		HeartbeatTimeout:    30 * time.Second,
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	output := &BruteForceOutput{}
	var futures []workflow.Future
	for _, target := range input.Targets {
		f := workflow.ExecuteActivity(ctx, "BruteForceActivity", target, input.Options)
		futures = append(futures, f)
	}

	for _, f := range futures {
		var results []model.BruteResult
		if err := f.Get(ctx, &results); err != nil {
			logger.Warn("brute force activity failed", "error", err)
			continue
		}
		output.Results = append(output.Results, results...)
	}

	logger.Info("BruteForceWorkflow completed", "results", len(output.Results))
	return output, nil
}
