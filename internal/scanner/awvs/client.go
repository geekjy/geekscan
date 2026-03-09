package awvs

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

const (
	defaultPollInterval = 30
	defaultMaxTime      = 3600
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

type addTargetReq struct {
	Address     string `json:"address"`
	Description string `json:"description"`
	Criticality int    `json:"criticality"`
}

type addTargetResp struct {
	TargetID string `json:"target_id"`
}

func (c *Client) AddTarget(ctx context.Context, targetURL string) (string, error) {
	body := addTargetReq{
		Address:     targetURL,
		Description: "distributed-scanner auto-added",
		Criticality: 10,
	}

	respBody, err := c.doJSON(ctx, http.MethodPost, "/api/v1/targets", body)
	if err != nil {
		return "", fmt.Errorf("add target: %w", err)
	}

	var resp addTargetResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("parse add target response: %w", err)
	}

	logger.L.Infow("AWVS target added", "targetID", resp.TargetID, "url", targetURL)
	return resp.TargetID, nil
}

type createScanReq struct {
	TargetID  string     `json:"target_id"`
	ProfileID string     `json:"profile_id"`
	Schedule  scanSchedule `json:"schedule"`
}

type scanSchedule struct {
	Disable    bool   `json:"disable"`
	StartDate *string `json:"start_date"`
}

type createScanResp struct {
	ScanID string `json:"scan_id,omitempty"`
	// AWVS may return different fields depending on version
	CurrentSession *struct {
		ScanID string `json:"scan_id"`
	} `json:"current_session,omitempty"`
}

var defaultProfileID = "11111111-1111-1111-1111-111111111111" // Full Scan

func (c *Client) CreateScan(ctx context.Context, targetID, profileID string) (string, error) {
	if profileID == "" {
		profileID = defaultProfileID
	}

	body := createScanReq{
		TargetID:  targetID,
		ProfileID: profileID,
		Schedule:  scanSchedule{Disable: false},
	}

	respBody, err := c.doJSON(ctx, http.MethodPost, "/api/v1/scans", body)
	if err != nil {
		return "", fmt.Errorf("create scan: %w", err)
	}

	var resp createScanResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", fmt.Errorf("parse create scan response: %w", err)
	}

	scanID := resp.ScanID
	if scanID == "" && resp.CurrentSession != nil {
		scanID = resp.CurrentSession.ScanID
	}

	logger.L.Infow("AWVS scan created", "scanID", scanID, "targetID", targetID, "profileID", profileID)
	return scanID, nil
}

type scanStatusResp struct {
	CurrentSession *struct {
		Status       string `json:"status"`
		Progress     int    `json:"progress"`
		SeverityCounts struct {
			High   int `json:"high"`
			Medium int `json:"medium"`
			Low    int `json:"low"`
			Info   int `json:"info"`
		} `json:"severity_counts"`
	} `json:"current_session"`
}

func (c *Client) GetScanStatus(ctx context.Context, scanID string) (string, int, error) {
	path := fmt.Sprintf("/api/v1/scans/%s", scanID)
	respBody, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", 0, fmt.Errorf("get scan status: %w", err)
	}

	var resp scanStatusResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return "", 0, fmt.Errorf("parse scan status: %w", err)
	}

	if resp.CurrentSession == nil {
		return "unknown", 0, nil
	}

	return resp.CurrentSession.Status, resp.CurrentSession.Progress, nil
}

type vulnListResp struct {
	Vulnerabilities []vulnEntry `json:"vulnerabilities"`
}

type vulnEntry struct {
	VulnID    string `json:"vuln_id"`
	Severity  int    `json:"severity"`
	Target    string `json:"affects_url"`
	VulnName  string `json:"vt_name"`
	Status    string `json:"status"`
	Confidence int   `json:"confidence"`
}

type vulnDetailResp struct {
	Description  string   `json:"description"`
	Impact       string   `json:"impact"`
	AffectsURL   string   `json:"affects_url"`
	Request      string   `json:"request"`
	References   []string `json:"references"`
	Tags         []string `json:"tags"`
	Recommendation string `json:"recommendation"`
}

func (c *Client) GetVulnerabilities(ctx context.Context, scanID string) ([]model.VulnResult, error) {
	path := fmt.Sprintf("/api/v1/scans/%s/results", scanID)
	respBody, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("get vulnerabilities: %w", err)
	}

	var resp vulnListResp
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("parse vulnerabilities: %w", err)
	}

	var results []model.VulnResult
	for _, v := range resp.Vulnerabilities {
		result := model.VulnResult{
			TemplateID: v.VulnID,
			Name:       v.VulnName,
			Severity:   awvsSeverityToString(v.Severity),
			URL:        v.Target,
			MatchedAt:  v.Target,
			Source:     "awvs",
			Timestamp:  time.Now(),
		}

		detail, err := c.getVulnDetail(ctx, scanID, v.VulnID)
		if err == nil && detail != nil {
			result.Reference = detail.References
			result.Tags = detail.Tags
			if detail.Request != "" {
				result.CURLCommand = detail.Request
			}
		}

		results = append(results, result)
	}

	logger.L.Infow("AWVS vulnerabilities retrieved", "scanID", scanID, "count", len(results))
	return results, nil
}

func (c *Client) getVulnDetail(ctx context.Context, scanID, vulnID string) (*vulnDetailResp, error) {
	path := fmt.Sprintf("/api/v1/scans/%s/results/%s", scanID, vulnID)
	respBody, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var detail vulnDetailResp
	if err := json.Unmarshal(respBody, &detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

func (c *Client) PollUntilComplete(ctx context.Context, scanID string, pollInterval, maxTime int) ([]model.VulnResult, error) {
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	if maxTime <= 0 {
		maxTime = defaultMaxTime
	}

	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(maxTime)*time.Second)
	defer cancel()

	ticker := time.NewTicker(time.Duration(pollInterval) * time.Second)
	defer ticker.Stop()

	logger.L.Infow("polling AWVS scan", "scanID", scanID, "interval", pollInterval, "maxTime", maxTime)

	for {
		select {
		case <-pollCtx.Done():
			logger.L.Warnw("AWVS poll timeout, returning partial results", "scanID", scanID)
			return c.GetVulnerabilities(ctx, scanID)
		case <-ticker.C:
			status, progress, err := c.GetScanStatus(pollCtx, scanID)
			if err != nil {
				logger.L.Warnw("AWVS poll status error", "scanID", scanID, "error", err)
				continue
			}

			logger.L.Infow("AWVS scan progress", "scanID", scanID, "status", status, "progress", progress)

			if status == "completed" || status == "failed" || status == "aborted" {
				return c.GetVulnerabilities(ctx, scanID)
			}
		}
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	url := c.baseURL + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-Auth", c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("AWVS API error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func awvsSeverityToString(severity int) string {
	switch severity {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "info"
	}
}
