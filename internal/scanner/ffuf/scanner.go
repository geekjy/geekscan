package ffuf

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

const (
	defaultThreads   = 40
	defaultTimeoutS  = 10
	maxBodyRead      = 512 * 1024
	calibrationPaths = 3
)

type ScanInput struct {
	TargetURL  string           `json:"target_url"`
	Dictionary []byte           `json:"dictionary"`
	Options    model.FfufOptions `json:"options"`
}

type calibrationEntry struct {
	size  int
	words int
	lines int
}

func Scan(ctx context.Context, input ScanInput) ([]model.DirResult, error) {
	opts := input.Options
	threads := coalesce(opts.Threads, defaultThreads)
	timeout := time.Duration(coalesce(opts.Timeout, defaultTimeoutS)) * time.Second

	baseURL := strings.TrimRight(input.TargetURL, "/")
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	words := parseDict(input.Dictionary, opts.Extensions)
	if len(words) == 0 {
		return nil, nil
	}

	logger.L.Infow("ffuf scan starting",
		"target", baseURL,
		"words", len(words),
		"threads", threads,
	)

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: false,
		MaxIdleConnsPerHost: threads,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	matchCodes := toSet(opts.MatchCodes)
	if len(matchCodes) == 0 {
		matchCodes = toSet([]int{200, 201, 204, 301, 302, 307, 401, 403, 405})
	}
	filterCodes := toSet(opts.FilterCodes)
	filterSizes := toSet(opts.FilterSize)
	filterWords := toSet(opts.FilterWords)

	var calibrated []calibrationEntry
	if opts.AutoCalibrate {
		calibrated = runCalibration(ctx, client, baseURL)
	}

	wordCh := make(chan string, threads*2)
	var (
		mu      sync.Mutex
		results []model.DirResult
		scanned int64
	)

	var rateLimiter <-chan time.Time
	if opts.Rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(opts.Rate))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordCh {
				if ctx.Err() != nil {
					return
				}
				if rateLimiter != nil {
					select {
					case <-rateLimiter:
					case <-ctx.Done():
						return
					}
				}

				targetURL := baseURL + "/" + word
				result := probeWord(ctx, client, targetURL, parsedBase.Host, word)
				atomic.AddInt64(&scanned, 1)
				if result == nil {
					continue
				}

				if !shouldKeepCode(result.StatusCode, matchCodes, filterCodes) {
					continue
				}
				if shouldFilterBySize(result.ContentLength, filterSizes) {
					continue
				}
				if shouldFilterByWords(result.Words, filterWords) {
					continue
				}
				if isCalibrated(result, calibrated) {
					continue
				}

				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}()
	}

	go func() {
		defer close(wordCh)
		for _, w := range words {
			select {
			case wordCh <- w:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	logger.L.Infow("ffuf scan completed",
		"target", baseURL,
		"scanned", atomic.LoadInt64(&scanned),
		"results", len(results),
	)
	return results, nil
}

func probeWord(ctx context.Context, client *http.Client, targetURL, host, path string) *model.DirResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) distributed-scanner/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	wordCount := countWords(body)
	lineCount := countLines(body)

	return &model.DirResult{
		URL:           targetURL,
		Host:          host,
		Path:          "/" + path,
		StatusCode:    resp.StatusCode,
		ContentLength: len(body),
		Words:         wordCount,
		Lines:         lineCount,
	}
}

func runCalibration(ctx context.Context, client *http.Client, baseURL string) []calibrationEntry {
	randomPaths := []string{
		"ds_calibration_a1b2c3d4e5f6",
		"ds_calibration_x7y8z9w0v1u2",
		"ds_calibration_m3n4o5p6q7r8",
	}

	var entries []calibrationEntry
	for _, p := range randomPaths {
		targetURL := baseURL + "/" + p
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 distributed-scanner/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
		resp.Body.Close()

		entries = append(entries, calibrationEntry{
			size:  len(body),
			words: countWords(body),
			lines: countLines(body),
		})
	}

	logger.L.Infow("ffuf auto-calibrate completed", "entries", len(entries))
	return entries
}

func isCalibrated(result *model.DirResult, calibrated []calibrationEntry) bool {
	for _, c := range calibrated {
		if result.ContentLength == c.size && result.Words == c.words && result.Lines == c.lines {
			return true
		}
	}
	return false
}

func parseDict(data []byte, extensions []string) []string {
	var words []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
		for _, ext := range extensions {
			ext = strings.TrimPrefix(ext, ".")
			words = append(words, line+"."+ext)
		}
	}
	return words
}

func countWords(data []byte) int {
	count := 0
	inWord := false
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			if inWord {
				count++
				inWord = false
			}
		} else {
			inWord = true
		}
	}
	if inWord {
		count++
	}
	return count
}

func countLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	count := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		count++
	}
	return count
}

func shouldKeepCode(code int, matchCodes, filterCodes map[int]struct{}) bool {
	if len(matchCodes) > 0 {
		if _, ok := matchCodes[code]; !ok {
			return false
		}
	}
	if len(filterCodes) > 0 {
		if _, ok := filterCodes[code]; ok {
			return false
		}
	}
	return true
}

func shouldFilterBySize(size int, filterSizes map[int]struct{}) bool {
	if len(filterSizes) == 0 {
		return false
	}
	_, ok := filterSizes[size]
	return ok
}

func shouldFilterByWords(words int, filterWords map[int]struct{}) bool {
	if len(filterWords) == 0 {
		return false
	}
	_, ok := filterWords[words]
	return ok
}

func toSet(vals []int) map[int]struct{} {
	if len(vals) == 0 {
		return nil
	}
	s := make(map[int]struct{}, len(vals))
	for _, v := range vals {
		s[v] = struct{}{}
	}
	return s
}

func coalesce(val, fallback int) int {
	if val > 0 {
		return val
	}
	return fallback
}
