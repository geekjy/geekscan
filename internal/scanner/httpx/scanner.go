package httpx

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

const (
	defaultThreads  = 25
	defaultTimeoutS = 10
	defaultRetries  = 1
	maxBodyRead     = 2 * 1024 * 1024 // 2 MB
)

var (
	titleRe    = regexp.MustCompile(`(?i)<title[^>]*>\s*(.*?)\s*</title>`)
	passwordRe = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']password["'][^>]*>`)
	formRe     = regexp.MustCompile(`(?i)<form[^>]*>`)
	actionRe   = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
	methodRe   = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
	inputNameRe = regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']([^"']*)["'][^>]*>`)
	inputTypeRe = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']*)["']`)

	techSignatures = []techRule{
		{keyword: "wordpress", tech: "WordPress"},
		{keyword: "wp-content", tech: "WordPress"},
		{keyword: "wp-includes", tech: "WordPress"},
		{keyword: "joomla", tech: "Joomla"},
		{keyword: "drupal", tech: "Drupal"},
		{keyword: "laravel", tech: "Laravel"},
		{keyword: "django", tech: "Django"},
		{keyword: "flask", tech: "Flask"},
		{keyword: "express", tech: "Express"},
		{keyword: "next.js", tech: "Next.js"},
		{keyword: "nuxt", tech: "Nuxt.js"},
		{keyword: "vue", tech: "Vue.js"},
		{keyword: "react", tech: "React"},
		{keyword: "angular", tech: "Angular"},
		{keyword: "jquery", tech: "jQuery"},
		{keyword: "bootstrap", tech: "Bootstrap"},
		{keyword: "tomcat", tech: "Apache Tomcat"},
		{keyword: "phpmyadmin", tech: "phpMyAdmin"},
		{keyword: "grafana", tech: "Grafana"},
		{keyword: "kibana", tech: "Kibana"},
		{keyword: "gitlab", tech: "GitLab"},
		{keyword: "jenkins", tech: "Jenkins"},
		{keyword: "sonarqube", tech: "SonarQube"},
		{keyword: "swagger", tech: "Swagger"},
		{keyword: "spring", tech: "Spring"},
		{keyword: "thinkphp", tech: "ThinkPHP"},
		{keyword: "asp.net", tech: "ASP.NET"},
	}

	headerTechSignatures = []headerTechRule{
		{header: "Server", keyword: "nginx", tech: "Nginx"},
		{header: "Server", keyword: "apache", tech: "Apache"},
		{header: "Server", keyword: "iis", tech: "Microsoft IIS"},
		{header: "Server", keyword: "tomcat", tech: "Apache Tomcat"},
		{header: "Server", keyword: "openresty", tech: "OpenResty"},
		{header: "Server", keyword: "caddy", tech: "Caddy"},
		{header: "Server", keyword: "litespeed", tech: "LiteSpeed"},
		{header: "Server", keyword: "cloudflare", tech: "Cloudflare"},
		{header: "X-Powered-By", keyword: "php", tech: "PHP"},
		{header: "X-Powered-By", keyword: "asp.net", tech: "ASP.NET"},
		{header: "X-Powered-By", keyword: "express", tech: "Express"},
		{header: "X-Powered-By", keyword: "next.js", tech: "Next.js"},
	}
)

type techRule struct {
	keyword string
	tech    string
}

type headerTechRule struct {
	header  string
	keyword string
	tech    string
}

type ScanInput struct {
	Targets []model.HttpxTarget `json:"targets"`
	Options model.HttpxOptions  `json:"options"`
}

func Scan(ctx context.Context, input ScanInput) ([]model.HttpxResult, error) {
	opts := input.Options
	threads := coalesce(opts.Threads, defaultThreads)
	timeout := time.Duration(coalesce(opts.Timeout, defaultTimeoutS)) * time.Second
	retries := coalesce(opts.Retries, defaultRetries)

	logger.L.Infow("httpx scan starting",
		"targets", len(input.Targets),
		"threads", threads,
		"timeout", timeout,
	)

	targetCh := make(chan model.HttpxTarget, threads*2)
	var (
		mu      sync.Mutex
		results []model.HttpxResult
	)

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 0,
		}).DialContext,
	}

	if opts.HttpProxy != "" {
		logger.L.Infow("using HTTP proxy", "proxy", opts.HttpProxy)
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if opts.FollowRedirect {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	matchCodes := toSet(opts.MatchCodes)
	filterCodes := toSet(opts.FilterCodes)

	var rateLimiter <-chan time.Time
	if opts.RateLimit > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(opts.RateLimit))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetCh {
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
				result := probeTarget(ctx, client, target, opts, retries)
				if result == nil {
					continue
				}
				if !shouldKeep(result.StatusCode, matchCodes, filterCodes) {
					continue
				}
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}()
	}

	go func() {
		defer close(targetCh)
		for _, t := range input.Targets {
			select {
			case targetCh <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	logger.L.Infow("httpx scan completed", "results", len(results))
	return results, nil
}

func probeTarget(ctx context.Context, client *http.Client, target model.HttpxTarget, opts model.HttpxOptions, retries int) *model.HttpxResult {
	protocol := target.Protocol
	if protocol == "" {
		if target.Port == 443 || target.Port == 8443 {
			protocol = "https"
		} else {
			protocol = "http"
		}
	}

	connectAddr := target.IP
	if connectAddr == "" {
		connectAddr = target.Host
	}

	url := fmt.Sprintf("%s://%s:%d", protocol, connectAddr, target.Port)

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return nil
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}

		if target.Host != "" {
			req.Host = target.Host
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) distributed-scanner/1.0")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "close")

		for _, h := range opts.CustomHeaders {
			if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
		resp.Body.Close()
		bodyStr := string(body)
		bodyLower := strings.ToLower(bodyStr)

		result := &model.HttpxResult{
			URL:           fmt.Sprintf("%s://%s:%d", protocol, target.Host, target.Port),
			Host:          target.Host,
			IP:            target.IP,
			Port:          target.Port,
			StatusCode:    resp.StatusCode,
			ContentLength: len(body),
			ResponseHash:  fmt.Sprintf("%x", md5.Sum(body)),
		}

		if opts.Title {
			result.Title = extractTitle(bodyStr)
		}

		if opts.TechDetect {
			result.Technologies = detectTechnologies(bodyLower, resp.Header)
		}

		loginForm := detectLoginForm(bodyStr)
		if loginForm != nil {
			result.HasLoginForm = true
			result.FormInfo = loginForm
		}

		return result
	}

	if lastErr != nil {
		logger.L.Debugw("httpx probe failed",
			"host", target.Host,
			"ip", target.IP,
			"port", target.Port,
			"error", lastErr,
		)
	}
	return nil
}

func extractTitle(body string) string {
	matches := titleRe.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		if len(title) > 200 {
			title = title[:200]
		}
		return title
	}
	return ""
}

func detectTechnologies(bodyLower string, headers http.Header) []string {
	seen := make(map[string]struct{})
	var techs []string

	for _, rule := range techSignatures {
		if strings.Contains(bodyLower, rule.keyword) {
			if _, ok := seen[rule.tech]; !ok {
				seen[rule.tech] = struct{}{}
				techs = append(techs, rule.tech)
			}
		}
	}

	for _, rule := range headerTechSignatures {
		val := strings.ToLower(headers.Get(rule.header))
		if val != "" && strings.Contains(val, rule.keyword) {
			if _, ok := seen[rule.tech]; !ok {
				seen[rule.tech] = struct{}{}
				techs = append(techs, rule.tech)
			}
		}
	}

	return techs
}

func detectLoginForm(body string) *model.FormInfo {
	if !passwordRe.MatchString(body) {
		return nil
	}

	forms := formRe.FindAllStringIndex(body, -1)
	if len(forms) == 0 {
		return nil
	}

	for _, loc := range forms {
		endIdx := strings.Index(body[loc[0]:], "</form>")
		if endIdx == -1 {
			endIdx = len(body) - loc[0]
		}
		formHTML := body[loc[0] : loc[0]+endIdx]

		if !passwordRe.MatchString(formHTML) {
			continue
		}

		info := &model.FormInfo{Method: "POST"}

		if m := actionRe.FindStringSubmatch(formHTML); len(m) > 1 {
			info.ActionURL = m[1]
		}
		if m := methodRe.FindStringSubmatch(formHTML); len(m) > 1 {
			info.Method = strings.ToUpper(m[1])
		}

		inputs := inputNameRe.FindAllStringSubmatch(formHTML, -1)
		for _, inp := range inputs {
			if len(inp) < 2 {
				continue
			}
			name := inp[1]
			fullTag := inp[0]
			typeParts := inputTypeRe.FindStringSubmatch(fullTag)
			inputType := ""
			if len(typeParts) > 1 {
				inputType = strings.ToLower(typeParts[1])
			}

			switch inputType {
			case "password":
				info.PasswordField = name
			case "hidden":
				nameLower := strings.ToLower(name)
				if strings.Contains(nameLower, "csrf") || strings.Contains(nameLower, "token") || strings.Contains(nameLower, "_xsrf") {
					info.CSRFField = name
				}
			default:
				if info.UsernameField == "" && inputType != "submit" && inputType != "button" && inputType != "checkbox" && inputType != "radio" {
					nameLower := strings.ToLower(name)
					if strings.Contains(nameLower, "user") || strings.Contains(nameLower, "email") ||
						strings.Contains(nameLower, "login") || strings.Contains(nameLower, "name") ||
						strings.Contains(nameLower, "account") {
						info.UsernameField = name
					}
				}
			}
		}

		if info.UsernameField == "" {
			for _, inp := range inputs {
				if len(inp) < 2 {
					continue
				}
				typeParts := inputTypeRe.FindStringSubmatch(inp[0])
				inputType := "text"
				if len(typeParts) > 1 {
					inputType = strings.ToLower(typeParts[1])
				}
				if inputType == "text" || inputType == "email" || inputType == "" {
					info.UsernameField = inp[1]
					break
				}
			}
		}

		return info
	}

	return nil
}

func shouldKeep(code int, matchCodes, filterCodes map[int]struct{}) bool {
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

func toSet(codes []int) map[int]struct{} {
	if len(codes) == 0 {
		return nil
	}
	s := make(map[int]struct{}, len(codes))
	for _, c := range codes {
		s[c] = struct{}{}
	}
	return s
}

func coalesce(val, fallback int) int {
	if val > 0 {
		return val
	}
	return fallback
}

