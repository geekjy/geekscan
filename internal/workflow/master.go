package workflow

import (
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"go.temporal.io/sdk/workflow"
)

type MasterScanOutput struct {
	PortResults      []model.PortResult  `json:"port_results"`
	HttpxResults     []model.HttpxResult `json:"httpx_results"`
	DirResults       []model.DirResult   `json:"dir_results"`
	CrawlResults     []model.CrawlResult `json:"crawl_results"`
	VulnResults      []model.VulnResult  `json:"vuln_results"`
	BruteResults     []model.BruteResult `json:"brute_results"`
	AwvsVulnResults  []model.VulnResult  `json:"awvs_vuln_results"`
}

func MasterScanWorkflow(ctx workflow.Context, task model.ScanTask) (*MasterScanOutput, error) {
	logger := workflow.GetLogger(ctx)
	logger.Info("MasterScanWorkflow started")

	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Minute,
		HeartbeatTimeout:    2 * time.Minute,
	}
	ctx = workflow.WithActivityOptions(ctx, ao)

	output := &MasterScanOutput{}

	// ===== Stage 1: Asset Discovery (parallel) =====
	var subdomains []string
	var dnsMap map[string][]string

	subfinderFuture := workflow.ExecuteActivity(ctx, "SubfinderActivity", task.Domains, task.SubfinderOptions)
	dnsFuture := workflow.ExecuteActivity(ctx, "DNSResolveActivity", task.Domains)

	if err := subfinderFuture.Get(ctx, &subdomains); err != nil {
		logger.Warn("subfinder failed", "error", err)
	}
	if err := dnsFuture.Get(ctx, &dnsMap); err != nil {
		logger.Warn("DNS resolve failed", "error", err)
	}

	allDomains := append(task.Domains, subdomains...)

	// ===== Stage 2: Build Host→IP Matrix =====
	hostIPMap := buildHostIPMap(allDomains, dnsMap, task.IPs)
	uniqueIPs := extractUniqueIPs(hostIPMap)

	// ===== Stage 3: Port Scan =====
	portScanInput := PortScanInput{
		IPs:     uniqueIPs,
		Options: task.NaabuOptions,
	}
	var portScanOutput PortScanOutput

	portCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
		WorkflowRunTimeout: 60 * time.Minute,
	})
	if err := workflow.ExecuteChildWorkflow(portCtx, PortScanWorkflow, portScanInput).Get(ctx, &portScanOutput); err != nil {
		logger.Error("port scan failed", "error", err)
		return output, err
	}
	output.PortResults = portScanOutput.OpenPorts

	ipPortMap := buildIPPortMap(portScanOutput.OpenPorts)

	// ===== Stage 4: Two parallel tracks =====

	// Track A: Protocol brute force
	var bruteFuture workflow.ChildWorkflowFuture
	if task.BruteForceOptions.Enabled {
		bruteInput := BruteForceInput{
			Targets: buildBruteTargets(ipPortMap),
			Options: task.BruteForceOptions,
		}
		bruteCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
			WorkflowRunTimeout: 30 * time.Minute,
		})
		bruteFuture = workflow.ExecuteChildWorkflow(bruteCtx, BruteForceWorkflow, bruteInput)
	}

	// Track B: Web scan chain
	httpxTargets := expandHostTargets(hostIPMap, ipPortMap)

	var httpxResults []model.HttpxResult
	if err := workflow.ExecuteActivity(ctx, "HttpxActivity", httpxTargets, task.HttpxOptions).Get(ctx, &httpxResults); err != nil {
		logger.Warn("httpx failed", "error", err)
	}
	output.HttpxResults = httpxResults

	aliveWebs := filterAliveWebs(httpxResults)

	// Stage 6: ffuf + rad + web brute + AWVS (all parallel)

	// AWVS fire-and-forget
	if task.AwvsOptions.Enabled {
		awvsCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
			WorkflowRunTimeout: 180 * time.Minute,
		})
		_ = workflow.ExecuteChildWorkflow(awvsCtx, AwvsWorkflow, AwvsInput{
			Targets: aliveWebs,
			Options: task.AwvsOptions,
		})
	}

	// ffuf
	var ffufFutures []workflow.Future
	for _, web := range aliveWebs {
		f := workflow.ExecuteActivity(ctx, "FfufScanActivity", web, task.FfufOptions)
		ffufFutures = append(ffufFutures, f)
	}

	// rad
	var radFutures []workflow.Future
	if task.RadOptions.Enabled {
		for _, web := range aliveWebs {
			f := workflow.ExecuteActivity(ctx, "RadCrawlActivity", web, task.RadOptions)
			radFutures = append(radFutures, f)
		}
	}

	// Collect ffuf results
	for _, f := range ffufFutures {
		var dirs []model.DirResult
		if err := f.Get(ctx, &dirs); err == nil {
			output.DirResults = append(output.DirResults, dirs...)
		}
	}

	// Collect rad results
	for _, f := range radFutures {
		var crawls []model.CrawlResult
		if err := f.Get(ctx, &crawls); err == nil {
			output.CrawlResults = append(output.CrawlResults, crawls...)
		}
	}

	// Stage 7: Nuclei
	nucleiTargets := buildNucleiTargets(httpxResults, output.DirResults, output.CrawlResults)
	var nucleiFutures []workflow.Future
	for _, target := range nucleiTargets {
		f := workflow.ExecuteActivity(ctx, "NucleiScanActivity", target, task.NucleiOptions)
		nucleiFutures = append(nucleiFutures, f)
	}
	for _, f := range nucleiFutures {
		var vulns []model.VulnResult
		if err := f.Get(ctx, &vulns); err == nil {
			output.VulnResults = append(output.VulnResults, vulns...)
		}
	}

	// Stage 8: Wait for brute force
	if bruteFuture != nil {
		var bruteOutput BruteForceOutput
		if err := bruteFuture.Get(ctx, &bruteOutput); err == nil {
			output.BruteResults = bruteOutput.Results
		}
	}

	logger.Info("MasterScanWorkflow completed")
	return output, nil
}
