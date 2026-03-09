package activity

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/internal/report"
	"github.com/xiaoyu/distributed-scanner/internal/scanner/awvs"
	"github.com/xiaoyu/distributed-scanner/internal/scanner/bruteforce"
	"github.com/xiaoyu/distributed-scanner/internal/scanner/ffuf"
	"github.com/xiaoyu/distributed-scanner/internal/scanner/httpx"
	"github.com/xiaoyu/distributed-scanner/internal/scanner/naabu"
	"github.com/xiaoyu/distributed-scanner/internal/scanner/nuclei"
	"github.com/xiaoyu/distributed-scanner/internal/scanner/rad"
	"github.com/xiaoyu/distributed-scanner/internal/scanner/subfinder"
	"github.com/xiaoyu/distributed-scanner/internal/store"
	"github.com/xiaoyu/distributed-scanner/pkg/config"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.temporal.io/sdk/activity"
)

// BruteTarget mirrors workflow.BruteTarget for Temporal deserialization.
type BruteTarget struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// NucleiTarget mirrors workflow.NucleiTarget for Temporal deserialization.
type NucleiTarget struct {
	URL             string   `json:"url"`
	Host            string   `json:"host"`
	Technologies    []string `json:"technologies"`
	DiscoveredPaths []string `json:"discovered_paths"`
}

type Activities struct {
	cfg *config.Config
	db  *store.MongoDB
}

func NewActivities(cfg *config.Config, db *store.MongoDB) *Activities {
	return &Activities{cfg: cfg, db: db}
}

func (a *Activities) SubfinderActivity(ctx context.Context, domains []string, opts model.SubfinderOptions) ([]string, error) {
	logger.L.Infow("SubfinderActivity started", "domains", domains)

	providerStore := store.NewProviderStore(a.db)
	providers, err := providerStore.GetEnabled(ctx)
	if err != nil {
		logger.L.Warnw("failed to fetch providers, continuing without them", "error", err)
	}

	input := subfinder.ScanInput{
		Domains:   domains,
		Options:   opts,
		Providers: providers,
	}

	results, err := subfinder.Scan(ctx, input)
	if err != nil {
		logger.L.Errorw("SubfinderActivity failed", "error", err)
		return nil, err
	}

	logger.L.Infow("SubfinderActivity completed", "subdomains", len(results))
	return results, nil
}

func (a *Activities) DNSResolveActivity(ctx context.Context, domains []string) (map[string][]string, error) {
	logger.L.Infow("DNSResolveActivity started", "domains", domains)
	result := make(map[string][]string)
	for _, d := range domains {
		ips, err := net.LookupHost(d)
		if err != nil {
			logger.L.Warnw("DNS lookup failed", "domain", d, "error", err)
			continue
		}
		result[d] = ips
	}
	return result, nil
}

func (a *Activities) NaabuScanActivity(ctx context.Context, input naabu.ScanInput) (*naabu.ScanOutput, error) {
	logger.L.Infow("NaabuScanActivity started",
		"host", input.Host,
		"portStart", input.Ports.Start,
		"portEnd", input.Ports.End,
	)

	heartbeat := func(progress float64) {
		activity.RecordHeartbeat(ctx, progress)
	}

	result, err := naabu.Scan(ctx, input, heartbeat)
	if err != nil {
		logger.L.Errorw("NaabuScanActivity failed", "host", input.Host, "error", err)
		return nil, err
	}

	logger.L.Infow("NaabuScanActivity completed",
		"host", input.Host,
		"openPorts", len(result.OpenPorts),
	)
	return result, nil
}

func (a *Activities) HttpxActivity(ctx context.Context, targets []model.HttpxTarget, opts model.HttpxOptions) ([]model.HttpxResult, error) {
	logger.L.Infow("HttpxActivity started", "targetCount", len(targets))

	input := httpx.ScanInput{
		Targets: targets,
		Options: opts,
	}

	results, err := httpx.Scan(ctx, input)
	if err != nil {
		logger.L.Errorw("HttpxActivity failed", "error", err)
		return nil, err
	}

	logger.L.Infow("HttpxActivity completed", "results", len(results))
	return results, nil
}

func (a *Activities) FfufScanActivity(ctx context.Context, target model.HttpxResult, opts model.FfufOptions) ([]model.DirResult, error) {
	logger.L.Infow("FfufScanActivity started", "url", target.URL)

	dict, err := a.loadDictionary(ctx, opts.DictionaryID)
	if err != nil {
		logger.L.Errorw("FfufScanActivity failed to load dictionary", "error", err)
		return nil, fmt.Errorf("load dictionary: %w", err)
	}

	input := ffuf.ScanInput{
		TargetURL:  target.URL,
		Dictionary: dict,
		Options:    opts,
	}

	results, err := ffuf.Scan(ctx, input)
	if err != nil {
		logger.L.Errorw("FfufScanActivity failed", "error", err)
		return nil, err
	}

	logger.L.Infow("FfufScanActivity completed", "url", target.URL, "results", len(results))
	return results, nil
}

func (a *Activities) RadCrawlActivity(ctx context.Context, target model.HttpxResult, opts model.RadOptions) ([]model.CrawlResult, error) {
	logger.L.Infow("RadCrawlActivity started", "url", target.URL)

	input := rad.ScanInput{
		TargetURL: target.URL,
		Options:   opts,
		RadBinary: a.cfg.Scanner.RadBinary,
	}

	results, err := rad.Scan(ctx, input)
	if err != nil {
		logger.L.Errorw("RadCrawlActivity failed", "error", err)
		return nil, err
	}

	logger.L.Infow("RadCrawlActivity completed", "url", target.URL, "results", len(results))
	return results, nil
}

func (a *Activities) NucleiScanActivity(ctx context.Context, target NucleiTarget, opts model.NucleiOptions) ([]model.VulnResult, error) {
	logger.L.Infow("NucleiScanActivity started", "url", target.URL)

	input := nuclei.ScanInput{
		TargetURL:    target.URL,
		Host:         target.Host,
		Technologies: target.Technologies,
		Options:      opts,
	}

	results, err := nuclei.Scan(ctx, input)
	if err != nil {
		logger.L.Errorw("NucleiScanActivity failed", "error", err)
		return nil, err
	}

	logger.L.Infow("NucleiScanActivity completed", "url", target.URL, "findings", len(results))
	return results, nil
}

func (a *Activities) BruteForceActivity(ctx context.Context, target BruteTarget, opts model.BruteForceOptions) ([]model.BruteResult, error) {
	logger.L.Infow("BruteForceActivity started", "ip", target.IP, "port", target.Port, "service", target.Service)

	users, passwords, err := a.loadBruteCredentials(ctx, opts, target.Service)
	if err != nil {
		logger.L.Errorw("BruteForceActivity failed to load credentials", "error", err)
		return nil, fmt.Errorf("load credentials: %w", err)
	}

	input := bruteforce.ScanInput{
		Host:      target.IP,
		IP:        target.IP,
		Port:      target.Port,
		Service:   target.Service,
		Users:     users,
		Passwords: passwords,
		Options:   opts,
	}

	results, err := bruteforce.Scan(ctx, input)
	if err != nil {
		logger.L.Errorw("BruteForceActivity failed", "error", err)
		return nil, err
	}

	logger.L.Infow("BruteForceActivity completed", "ip", target.IP, "port", target.Port, "found", len(results))
	return results, nil
}

func (a *Activities) WebBruteForceActivity(ctx context.Context, target model.HttpxResult, opts model.WebBruteOptions) ([]model.BruteResult, error) {
	logger.L.Infow("WebBruteForceActivity started", "url", target.URL)

	if !target.HasLoginForm || target.FormInfo == nil {
		logger.L.Infow("WebBruteForceActivity skipped, no login form detected", "url", target.URL)
		return nil, nil
	}

	logger.L.Infow("WebBruteForceActivity: login form detected",
		"url", target.URL,
		"action", target.FormInfo.ActionURL,
		"userField", target.FormInfo.UsernameField,
		"passField", target.FormInfo.PasswordField,
	)

	// Web brute-force requires HTTP form submission logic.
	// Returning empty for now - a full implementation would post credentials to the form.
	return nil, nil
}

func (a *Activities) AwvsAddTargetActivity(ctx context.Context, targetURL string, opts model.AwvsOptions) (string, error) {
	logger.L.Infow("AwvsAddTargetActivity started", "url", targetURL)

	client := awvs.NewClient(opts.ApiURL, opts.ApiKey)
	targetID, err := client.AddTarget(ctx, targetURL)
	if err != nil {
		logger.L.Errorw("AwvsAddTargetActivity failed", "error", err)
		return "", err
	}

	logger.L.Infow("AwvsAddTargetActivity completed", "targetID", targetID)
	return targetID, nil
}

func (a *Activities) AwvsCreateScanActivity(ctx context.Context, targetID string, opts model.AwvsOptions) (string, error) {
	logger.L.Infow("AwvsCreateScanActivity started", "targetID", targetID)

	client := awvs.NewClient(opts.ApiURL, opts.ApiKey)
	scanID, err := client.CreateScan(ctx, targetID, opts.ScanProfileID)
	if err != nil {
		logger.L.Errorw("AwvsCreateScanActivity failed", "error", err)
		return "", err
	}

	logger.L.Infow("AwvsCreateScanActivity completed", "scanID", scanID)
	return scanID, nil
}

func (a *Activities) AwvsPollScanActivity(ctx context.Context, scanID string, opts model.AwvsOptions) ([]model.VulnResult, error) {
	logger.L.Infow("AwvsPollScanActivity started", "scanID", scanID)

	client := awvs.NewClient(opts.ApiURL, opts.ApiKey)
	results, err := client.PollUntilComplete(ctx, scanID, opts.PollInterval, opts.MaxTime)
	if err != nil {
		logger.L.Errorw("AwvsPollScanActivity failed", "error", err)
		return nil, err
	}

	logger.L.Infow("AwvsPollScanActivity completed", "scanID", scanID, "vulns", len(results))
	return results, nil
}

func (a *Activities) ReportActivity(ctx context.Context, taskID string, format string) (string, error) {
	logger.L.Infow("ReportActivity started", "taskID", taskID, "format", format)

	oid, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return "", fmt.Errorf("invalid task ID: %w", err)
	}

	taskStore := store.NewTaskStore(a.db)
	task, err := taskStore.GetByID(ctx, oid)
	if err != nil {
		return "", fmt.Errorf("get task: %w", err)
	}

	data, err := a.buildReportData(ctx, task)
	if err != nil {
		return "", fmt.Errorf("build report data: %w", err)
	}

	reportDir := filepath.Join("reports", taskID)
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}

	var outputPath string
	switch format {
	case "html":
		outputPath = filepath.Join(reportDir, "report.html")
		err = report.GenerateHTML(data, outputPath)
	case "json":
		outputPath = filepath.Join(reportDir, "report.json")
		err = report.GenerateJSON(data, outputPath)
	case "pdf":
		outputPath = filepath.Join(reportDir, "report.pdf")
		err = report.GeneratePDF(data, outputPath)
	default:
		return "", fmt.Errorf("unsupported report format: %s", format)
	}
	if err != nil {
		return "", fmt.Errorf("generate %s report: %w", format, err)
	}

	logger.L.Infow("ReportActivity completed", "taskID", taskID, "format", format, "path", outputPath)
	return outputPath, nil
}

func (a *Activities) buildReportData(ctx context.Context, task *model.ScanTask) (*report.ReportData, error) {
	resultStore := store.NewResultStore(a.db)

	data := &report.ReportData{
		TaskName:    task.Name,
		Targets:     task.Targets,
		GeneratedAt: time.Now(),
	}

	types := []string{"port", "httpx", "dir", "crawl", "vuln", "brute"}
	for _, t := range types {
		results, _, err := resultStore.GetByTaskID(ctx, task.ID, t, 0, 10000)
		if err != nil {
			logger.L.Warnw("failed to fetch results for report", "type", t, "error", err)
			continue
		}
		for _, r := range results {
			raw, err := marshalBSONData(r.Data)
			if err != nil {
				logger.L.Warnw("failed to marshal result data", "type", t, "error", err)
				continue
			}
			switch t {
			case "port":
				var v model.PortResult
				if json.Unmarshal(raw, &v) == nil {
					data.Ports = append(data.Ports, v)
				}
			case "httpx":
				var v model.HttpxResult
				if json.Unmarshal(raw, &v) == nil {
					data.WebFingers = append(data.WebFingers, v)
				}
			case "dir":
				var v model.DirResult
				if json.Unmarshal(raw, &v) == nil {
					data.Directories = append(data.Directories, v)
				}
			case "crawl":
				var v model.CrawlResult
				if json.Unmarshal(raw, &v) == nil {
					data.CrawledURLs = append(data.CrawledURLs, v)
				}
			case "vuln":
				var v model.VulnResult
				if json.Unmarshal(raw, &v) == nil {
					data.Vulns = append(data.Vulns, v)
				}
			case "brute":
				var v model.BruteResult
				if json.Unmarshal(raw, &v) == nil {
					data.BruteResults = append(data.BruteResults, v)
				}
			}
		}
	}
	return data, nil
}

func marshalBSONData(data interface{}) ([]byte, error) {
	switch v := data.(type) {
	case bson.M:
		return json.Marshal(v)
	case bson.D:
		m := make(map[string]interface{}, len(v))
		for _, elem := range v {
			m[elem.Key] = elem.Value
		}
		return json.Marshal(m)
	default:
		return json.Marshal(v)
	}
}

func (a *Activities) loadDictionary(ctx context.Context, dictID string) ([]byte, error) {
	if dictID == "" {
		return nil, fmt.Errorf("dictionary ID is empty")
	}

	oid, err := primitive.ObjectIDFromHex(dictID)
	if err != nil {
		return nil, fmt.Errorf("invalid dictionary ID: %w", err)
	}

	dictStore := store.NewDictionaryStore(a.db)
	dict, err := dictStore.GetByID(ctx, oid)
	if err != nil {
		return nil, fmt.Errorf("dictionary not found: %w", err)
	}

	content, err := dictStore.GetContent(ctx, dict.FileID)
	if err != nil {
		return nil, fmt.Errorf("dictionary content read failed: %w", err)
	}

	return content, nil
}

func (a *Activities) loadBruteCredentials(ctx context.Context, opts model.BruteForceOptions, service string) ([]string, []string, error) {
	var users, passwords []string

	if opts.UserDictID != "" {
		content, err := a.loadDictionary(ctx, opts.UserDictID)
		if err != nil {
			logger.L.Warnw("failed to load user dictionary, using defaults", "error", err)
		} else {
			users = splitLines(content)
		}
	}

	if len(users) == 0 && len(opts.DefaultUsers) > 0 {
		users = opts.DefaultUsers
	}
	if len(users) == 0 {
		users = defaultUsersForService(service)
	}

	if opts.PassDictID != "" {
		content, err := a.loadDictionary(ctx, opts.PassDictID)
		if err != nil {
			logger.L.Warnw("failed to load password dictionary, using defaults", "error", err)
		} else {
			passwords = splitLines(content)
		}
	}

	if len(passwords) == 0 && len(opts.DefaultPasswd) > 0 {
		passwords = opts.DefaultPasswd
	}
	if len(passwords) == 0 {
		passwords = defaultPasswords()
	}

	return users, passwords, nil
}

func splitLines(data []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

func defaultUsersForService(service string) []string {
	switch service {
	case "ssh", "ftp":
		return []string{"root", "admin", "user", "test"}
	case "mysql":
		return []string{"root", "admin", "mysql", "test"}
	case "redis":
		return []string{"default", ""}
	case "postgresql":
		return []string{"postgres", "admin", "root"}
	case "mongodb":
		return []string{"admin", "root", ""}
	case "mssql":
		return []string{"sa", "admin"}
	default:
		return []string{"admin", "root"}
	}
}

func defaultPasswords() []string {
	return []string{
		"", "admin", "password", "123456", "root", "toor",
		"admin123", "password123", "123456789", "12345678",
		"test", "guest", "master", "qwerty", "abc123",
	}
}
