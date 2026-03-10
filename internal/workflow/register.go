package workflow

import (
	"github.com/xiaoyu/distributed-scanner/internal/activity"
	"github.com/xiaoyu/distributed-scanner/internal/store"
	"github.com/xiaoyu/distributed-scanner/pkg/config"
	"go.temporal.io/sdk/worker"
)

func Register(w worker.Worker, cfg *config.Config, db *store.MongoDB) {
	// Register workflows
	w.RegisterWorkflow(MasterScanWorkflow)
	w.RegisterWorkflow(PortScanWorkflow)
	w.RegisterWorkflow(BruteForceWorkflow)
	w.RegisterWorkflow(AwvsWorkflow)

	// Register activities
	acts := activity.NewActivities(cfg, db)
	w.RegisterActivity(acts.SubfinderActivity)
	w.RegisterActivity(acts.DNSResolveActivity)
	w.RegisterActivity(acts.NaabuScanActivity)
	w.RegisterActivity(acts.HttpxActivity)
	w.RegisterActivity(acts.FfufScanActivity)
	w.RegisterActivity(acts.RadCrawlActivity)
	w.RegisterActivity(acts.NucleiScanActivity)
	w.RegisterActivity(acts.BruteForceActivity)
	w.RegisterActivity(acts.WebBruteForceActivity)
	w.RegisterActivity(acts.AwvsAddTargetActivity)
	w.RegisterActivity(acts.AwvsCreateScanActivity)
	w.RegisterActivity(acts.AwvsPollScanActivity)
	w.RegisterActivity(acts.ReportActivity)
	w.RegisterActivity(acts.SaveResultsActivity)
	w.RegisterActivity(acts.UpdateTaskStatusActivity)
}
