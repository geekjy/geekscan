package rad

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

const (
	defaultMaxTime       = 120
	defaultMaxCrawlCount = 200
	defaultMaxDepth      = 3
	defaultThreads       = 5
	maxBodyRead          = 1024 * 1024
)

type ScanInput struct {
	TargetURL string           `json:"target_url"`
	Options   model.RadOptions `json:"options"`
	RadBinary string           `json:"rad_binary"`
}

type radJSONEntry struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

var linkRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#][^"']*)["']`)

func Scan(ctx context.Context, input ScanInput) ([]model.CrawlResult, error) {
	opts := input.Options
	maxTime := coalesce(opts.MaxTime, defaultMaxTime)

	crawlCtx, cancel := context.WithTimeout(ctx, time.Duration(maxTime)*time.Second)
	defer cancel()

	if input.RadBinary != "" {
		results, err := runRadBinary(crawlCtx, input)
		if err == nil {
			return results, nil
		}
		logger.L.Warnw("rad binary execution failed, falling back to built-in crawler",
			"binary", input.RadBinary,
			"error", err,
		)
	} else {
		if path, err := exec.LookPath("rad"); err == nil {
			input.RadBinary = path
			results, err := runRadBinary(crawlCtx, input)
			if err == nil {
				return results, nil
			}
			logger.L.Warnw("rad binary from PATH failed, falling back to built-in crawler", "error", err)
		}
	}

	return builtinCrawl(crawlCtx, input)
}

func runRadBinary(ctx context.Context, input ScanInput) ([]model.CrawlResult, error) {
	opts := input.Options
	args := []string{
		"-t", input.TargetURL,
		"-json",
	}

	if opts.MaxCrawlCount > 0 {
		args = append(args, "-max-links", fmt.Sprintf("%d", opts.MaxCrawlCount))
	}
	if opts.MaxDepth > 0 {
		args = append(args, "-max-depth", fmt.Sprintf("%d", opts.MaxDepth))
	}
	if opts.Cookies != "" {
		args = append(args, "-cookie", opts.Cookies)
	}
	for _, h := range opts.Headers {
		args = append(args, "-header", h)
	}
	if opts.HttpProxy != "" {
		args = append(args, "-proxy", opts.HttpProxy)
	}
	if opts.WaitLoad > 0 {
		args = append(args, "-wait", fmt.Sprintf("%d", opts.WaitLoad))
	}

	logger.L.Infow("running rad binary", "binary", input.RadBinary, "args", args)

	cmd := exec.CommandContext(ctx, input.RadBinary, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rad execution failed: %w", err)
	}

	return parseRadOutput(output, input.TargetURL)
}

func parseRadOutput(output []byte, targetURL string) ([]model.CrawlResult, error) {
	parsed, _ := url.Parse(targetURL)
	host := ""
	if parsed != nil {
		host = parsed.Host
	}

	var results []model.CrawlResult
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry radJSONEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			if strings.HasPrefix(line, "http") {
				p, _ := url.Parse(line)
				path := ""
				if p != nil {
					path = p.Path
				}
				results = append(results, model.CrawlResult{
					URL:    line,
					Method: "GET",
					Host:   host,
					Path:   path,
					Source: "rad",
				})
			}
			continue
		}

		p, _ := url.Parse(entry.URL)
		path := ""
		params := make(map[string]string)
		if p != nil {
			path = p.Path
			for k, v := range p.Query() {
				if len(v) > 0 {
					params[k] = v[0]
				}
			}
		}

		method := entry.Method
		if method == "" {
			method = "GET"
		}

		results = append(results, model.CrawlResult{
			URL:        entry.URL,
			Method:     method,
			Host:       host,
			Path:       path,
			Parameters: params,
			Headers:    entry.Headers,
			Source:     "rad",
		})
	}

	logger.L.Infow("rad output parsed", "results", len(results))
	return results, nil
}

type crawlItem struct {
	url   string
	depth int
}

func builtinCrawl(ctx context.Context, input ScanInput) ([]model.CrawlResult, error) {
	opts := input.Options
	maxCrawl := coalesce(opts.MaxCrawlCount, defaultMaxCrawlCount)
	maxDepth := coalesce(opts.MaxDepth, defaultMaxDepth)
	threads := coalesce(opts.Threads, defaultThreads)

	parsedBase, err := url.Parse(input.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	logger.L.Infow("built-in crawler starting",
		"target", input.TargetURL,
		"maxCrawl", maxCrawl,
		"maxDepth", maxDepth,
		"threads", threads,
	)

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConnsPerHost: threads,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	excludeExts := toStringSet(opts.ExcludeExts)
	excludePaths := opts.ExcludePaths

	visited := &sync.Map{}
	var (
		mu      sync.Mutex
		results []model.CrawlResult
		count   int64
	)

	queue := make(chan crawlItem, maxCrawl+1)

	addURL := func(rawURL string, depth int) {
		if atomic.LoadInt64(&count) >= int64(maxCrawl) {
			return
		}

		parsed, err := url.Parse(rawURL)
		if err != nil {
			return
		}

		if parsed.Host != "" && parsed.Host != parsedBase.Host {
			if !isAllowedDomain(parsed.Host, opts.IncludeDomain) {
				return
			}
		}

		if parsed.Host == "" {
			parsed.Scheme = parsedBase.Scheme
			parsed.Host = parsedBase.Host
		}

		parsed.Fragment = ""
		normalized := parsed.String()

		if shouldExcludeExt(parsed.Path, excludeExts) {
			return
		}
		if shouldExcludePath(parsed.Path, excludePaths) {
			return
		}

		if _, loaded := visited.LoadOrStore(normalized, struct{}{}); loaded {
			return
		}

		select {
		case queue <- crawlItem{url: normalized, depth: depth}:
		default:
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range queue {
				if ctx.Err() != nil {
					return
				}
				if atomic.LoadInt64(&count) >= int64(maxCrawl) {
					return
				}

				links := fetchAndExtractLinks(ctx, client, item.url, opts)
				atomic.AddInt64(&count, 1)

				parsed, _ := url.Parse(item.url)
				path := ""
				params := make(map[string]string)
				if parsed != nil {
					path = parsed.Path
					for k, v := range parsed.Query() {
						if len(v) > 0 {
							params[k] = v[0]
						}
					}
				}

				mu.Lock()
				results = append(results, model.CrawlResult{
					URL:        item.url,
					Method:     "GET",
					Host:       parsedBase.Host,
					Path:       path,
					Parameters: params,
					Source:     "crawler",
				})
				mu.Unlock()

				if item.depth < maxDepth {
					for _, link := range links {
						resolved := resolveURL(parsedBase, item.url, link)
						if resolved != "" {
							addURL(resolved, item.depth+1)
						}
					}
				}
			}
		}()
	}

	visited.Store(input.TargetURL, struct{}{})
	queue <- crawlItem{url: input.TargetURL, depth: 0}

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		idleCount := 0
		for {
			select {
			case <-ctx.Done():
				close(queue)
				return
			case <-ticker.C:
				if atomic.LoadInt64(&count) >= int64(maxCrawl) {
					close(queue)
					return
				}
				if len(queue) == 0 {
					idleCount++
					if idleCount >= 6 {
						close(queue)
						return
					}
				} else {
					idleCount = 0
				}
			}
		}
	}()

	wg.Wait()

	logger.L.Infow("built-in crawler completed",
		"target", input.TargetURL,
		"results", len(results),
	)
	return results, nil
}

func fetchAndExtractLinks(ctx context.Context, client *http.Client, targetURL string, opts model.RadOptions) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) distributed-scanner/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")

	if opts.Cookies != "" {
		req.Header.Set("Cookie", opts.Cookies)
	}
	for _, h := range opts.Headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(maxBodyRead)))

	matches := linkRe.FindAllSubmatch(body, -1)
	var links []string
	for _, m := range matches {
		if len(m) > 1 {
			link := strings.TrimSpace(string(m[1]))
			if link != "" && !strings.HasPrefix(link, "javascript:") && !strings.HasPrefix(link, "data:") {
				links = append(links, link)
			}
		}
	}
	return links
}

func resolveURL(base *url.URL, currentPage, link string) string {
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return link
	}
	if strings.HasPrefix(link, "//") {
		return base.Scheme + ":" + link
	}

	current, err := url.Parse(currentPage)
	if err != nil {
		current = base
	}

	ref, err := url.Parse(link)
	if err != nil {
		return ""
	}

	resolved := current.ResolveReference(ref)
	return resolved.String()
}

func isAllowedDomain(host string, includeDomains []string) bool {
	if len(includeDomains) == 0 {
		return false
	}
	for _, d := range includeDomains {
		if strings.HasSuffix(host, d) {
			return true
		}
	}
	return false
}

func shouldExcludeExt(path string, excludeExts map[string]struct{}) bool {
	if len(excludeExts) == 0 {
		return false
	}
	lastDot := strings.LastIndex(path, ".")
	if lastDot < 0 {
		return false
	}
	ext := strings.ToLower(path[lastDot+1:])
	_, ok := excludeExts[ext]
	return ok
}

func shouldExcludePath(path string, excludePaths []string) bool {
	for _, ep := range excludePaths {
		if strings.Contains(path, ep) {
			return true
		}
	}
	return false
}

func toStringSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		s[strings.ToLower(item)] = struct{}{}
	}
	return s
}

func coalesce(val, fallback int) int {
	if val > 0 {
		return val
	}
	return fallback
}
