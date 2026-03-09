package nuclei

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

const (
	defaultMaxTime  = 300
	defaultThreads  = 10
	defaultTimeout  = 10
	maxBodyRead     = 512 * 1024
)

type ScanInput struct {
	TargetURL    string              `json:"target_url"`
	Host         string              `json:"host"`
	Technologies []string            `json:"technologies"`
	Options      model.NucleiOptions `json:"options"`
}

type check struct {
	ID       string
	Name     string
	Severity string
	Tags     []string
	Run      func(ctx context.Context, client *http.Client, target string) *model.VulnResult
}

var techToTags = map[string][]string{
	"WordPress":     {"wordpress", "wp"},
	"Joomla":        {"joomla"},
	"Drupal":        {"drupal"},
	"Laravel":       {"laravel"},
	"Django":        {"django"},
	"Flask":         {"flask"},
	"Apache Tomcat": {"tomcat", "apache"},
	"phpMyAdmin":    {"phpmyadmin"},
	"Grafana":       {"grafana"},
	"Kibana":        {"kibana"},
	"GitLab":        {"gitlab"},
	"Jenkins":       {"jenkins"},
	"SonarQube":     {"sonarqube"},
	"Swagger":       {"swagger"},
	"Spring":        {"spring"},
	"ThinkPHP":      {"thinkphp"},
	"ASP.NET":       {"aspnet"},
	"Nginx":         {"nginx"},
	"Apache":        {"apache"},
	"PHP":           {"php"},
	"React":         {"react"},
	"Vue.js":        {"vuejs"},
	"Next.js":       {"nextjs"},
}

func Scan(ctx context.Context, input ScanInput) ([]model.VulnResult, error) {
	opts := input.Options
	maxTime := coalesce(opts.MaxTime, defaultMaxTime)
	threads := coalesce(opts.Threads, defaultThreads)
	timeout := time.Duration(coalesce(opts.Timeout, defaultTimeout)) * time.Second

	scanCtx, cancel := context.WithTimeout(ctx, time.Duration(maxTime)*time.Second)
	defer cancel()

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
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
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	allChecks := buildChecks()
	checks := filterChecks(allChecks, input.Technologies, opts)

	logger.L.Infow("nuclei scan starting",
		"target", input.TargetURL,
		"totalChecks", len(checks),
		"threads", threads,
	)

	checkCh := make(chan check, threads*2)
	var (
		mu      sync.Mutex
		results []model.VulnResult
	)

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
			for c := range checkCh {
				if scanCtx.Err() != nil {
					return
				}
				if rateLimiter != nil {
					select {
					case <-rateLimiter:
					case <-scanCtx.Done():
						return
					}
				}

				result := c.Run(scanCtx, client, input.TargetURL)
				if result != nil {
					result.Host = input.Host
					result.Source = "nuclei"
					result.Timestamp = time.Now()
					mu.Lock()
					results = append(results, *result)
					mu.Unlock()
					logger.L.Infow("vulnerability found",
						"template", result.TemplateID,
						"name", result.Name,
						"severity", result.Severity,
						"url", result.URL,
					)
				}
			}
		}()
	}

	go func() {
		defer close(checkCh)
		for _, c := range checks {
			select {
			case checkCh <- c:
			case <-scanCtx.Done():
				return
			}
		}
	}()

	wg.Wait()

	logger.L.Infow("nuclei scan completed",
		"target", input.TargetURL,
		"findings", len(results),
	)
	return results, nil
}

func filterChecks(allChecks []check, technologies []string, opts model.NucleiOptions) []check {
	relevantTags := make(map[string]struct{})

	if opts.AutoFingerprintMatch && len(technologies) > 0 {
		for _, tech := range technologies {
			if tags, ok := techToTags[tech]; ok {
				for _, t := range tags {
					relevantTags[t] = struct{}{}
				}
			}
		}
	}

	for _, t := range opts.Tags {
		relevantTags[strings.ToLower(t)] = struct{}{}
	}

	excludeTags := make(map[string]struct{})
	for _, t := range opts.ExcludeTags {
		excludeTags[strings.ToLower(t)] = struct{}{}
	}

	templateIDs := make(map[string]struct{})
	for _, id := range opts.TemplateIDs {
		templateIDs[id] = struct{}{}
	}
	excludeIDs := make(map[string]struct{})
	for _, id := range opts.ExcludeIDs {
		excludeIDs[id] = struct{}{}
	}

	severitySet := make(map[string]struct{})
	for _, s := range opts.Severity {
		severitySet[strings.ToLower(s)] = struct{}{}
	}

	var filtered []check
	for _, c := range allChecks {
		if _, excluded := excludeIDs[c.ID]; excluded {
			continue
		}

		if len(templateIDs) > 0 {
			if _, ok := templateIDs[c.ID]; !ok {
				continue
			}
		}

		if len(severitySet) > 0 {
			if _, ok := severitySet[c.Severity]; !ok {
				continue
			}
		}

		excluded := false
		for _, tag := range c.Tags {
			if _, ok := excludeTags[tag]; ok {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		if len(relevantTags) > 0 {
			hasRelevant := false
			for _, tag := range c.Tags {
				if _, ok := relevantTags[tag]; ok {
					hasRelevant = true
					break
				}
			}
			if len(c.Tags) > 0 && !hasRelevant {
				if !isGenericCheck(c) {
					continue
				}
			}
		}

		filtered = append(filtered, c)
	}

	return filtered
}

func isGenericCheck(c check) bool {
	for _, tag := range c.Tags {
		if tag == "generic" || tag == "exposure" || tag == "misconfig" {
			return true
		}
	}
	return false
}

func buildChecks() []check {
	return []check{
		pathTraversalCheck(),
		dotEnvExposure(),
		gitExposure(),
		dsStoreExposure(),
		svnExposure(),
		backupFilesCheck(),
		openRedirectCheck(),
		defaultCredentialsCheck(),
		serverHeaderCheck(),
		robotsTxtCheck(),
		sitemapCheck(),
		securityHeadersCheck(),
		corsWildcardCheck(),
		directoryListingCheck(),
		phpInfoCheck(),
		springActuatorCheck(),
		swaggerUICheck(),
		graphQLCheck(),
		wordpressUserEnum(),
		wpXMLRPC(),
	}
}

func makeRequest(ctx context.Context, client *http.Client, method, url string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) distributed-scanner/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	return resp, body, nil
}

func pathTraversalCheck() check {
	return check{
		ID: "path-traversal-basic", Name: "Path Traversal Detection",
		Severity: "high", Tags: []string{"generic", "lfi"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			payloads := []string{
				"/../../../etc/passwd",
				"/..%2f..%2f..%2fetc%2fpasswd",
				"/....//....//....//etc/passwd",
			}
			for _, p := range payloads {
				url := target + p
				_, body, err := makeRequest(ctx, client, http.MethodGet, url)
				if err != nil {
					continue
				}
				if strings.Contains(string(body), "root:") && strings.Contains(string(body), "/bin/") {
					return &model.VulnResult{
						TemplateID: "path-traversal-basic",
						Name:       "Path Traversal - /etc/passwd",
						Severity:   "high",
						URL:        url,
						MatchedAt:  url,
						Tags:       []string{"generic", "lfi"},
						CURLCommand: fmt.Sprintf("curl -k '%s'", url),
					}
				}
			}
			return nil
		},
	}
}

func dotEnvExposure() check {
	return check{
		ID: "dotenv-exposure", Name: ".env File Exposure",
		Severity: "high", Tags: []string{"generic", "exposure", "misconfig"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			paths := []string{"/.env", "/.env.local", "/.env.production", "/.env.backup"}
			for _, p := range paths {
				url := target + p
				resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
				if err != nil {
					continue
				}
				bodyStr := string(body)
				if resp.StatusCode == 200 &&
					(strings.Contains(bodyStr, "DB_PASSWORD") ||
						strings.Contains(bodyStr, "APP_KEY") ||
						strings.Contains(bodyStr, "SECRET_KEY") ||
						strings.Contains(bodyStr, "API_KEY") ||
						strings.Contains(bodyStr, "DATABASE_URL")) {
					return &model.VulnResult{
						TemplateID: "dotenv-exposure",
						Name:       ".env File Exposure",
						Severity:   "high",
						URL:        url,
						MatchedAt:  url,
						Tags:       []string{"exposure", "misconfig"},
						CURLCommand: fmt.Sprintf("curl -k '%s'", url),
					}
				}
			}
			return nil
		},
	}
}

func gitExposure() check {
	return check{
		ID: "git-exposure", Name: ".git Directory Exposure",
		Severity: "medium", Tags: []string{"generic", "exposure", "misconfig"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			url := target + "/.git/config"
			resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
			if err != nil {
				return nil
			}
			if resp.StatusCode == 200 && strings.Contains(string(body), "[core]") {
				return &model.VulnResult{
					TemplateID: "git-exposure",
					Name:       ".git Directory Exposure",
					Severity:   "medium",
					URL:        url,
					MatchedAt:  url,
					Tags:       []string{"exposure", "misconfig"},
					CURLCommand: fmt.Sprintf("curl -k '%s'", url),
				}
			}
			return nil
		},
	}
}

func dsStoreExposure() check {
	return check{
		ID: "ds-store-exposure", Name: ".DS_Store File Exposure",
		Severity: "low", Tags: []string{"generic", "exposure"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			url := target + "/.DS_Store"
			resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
			if err != nil {
				return nil
			}
			if resp.StatusCode == 200 && len(body) > 8 {
				// DS_Store magic bytes: 0x00 0x00 0x00 0x01 Bud1
				if (body[0] == 0x00 && body[1] == 0x00 && body[2] == 0x00 && body[3] == 0x01) ||
					strings.Contains(string(body), "Bud1") {
					return &model.VulnResult{
						TemplateID: "ds-store-exposure",
						Name:       ".DS_Store File Exposure",
						Severity:   "low",
						URL:        url,
						MatchedAt:  url,
						Tags:       []string{"exposure"},
					}
				}
			}
			return nil
		},
	}
}

func svnExposure() check {
	return check{
		ID: "svn-exposure", Name: ".svn Directory Exposure",
		Severity: "medium", Tags: []string{"generic", "exposure", "misconfig"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			url := target + "/.svn/entries"
			resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
			if err != nil {
				return nil
			}
			if resp.StatusCode == 200 && (strings.HasPrefix(string(body), "10\n") || strings.HasPrefix(string(body), "12\n") || strings.Contains(string(body), "svn")) {
				return &model.VulnResult{
					TemplateID: "svn-exposure",
					Name:       ".svn Directory Exposure",
					Severity:   "medium",
					URL:        url,
					MatchedAt:  url,
					Tags:       []string{"exposure", "misconfig"},
				}
			}
			return nil
		},
	}
}

func backupFilesCheck() check {
	return check{
		ID: "backup-files", Name: "Backup File Detection",
		Severity: "medium", Tags: []string{"generic", "exposure"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			paths := []string{
				"/backup.sql", "/backup.zip", "/backup.tar.gz",
				"/db.sql", "/dump.sql", "/database.sql",
				"/web.config.bak", "/config.php.bak",
			}
			for _, p := range paths {
				url := target + p
				resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
				if err != nil {
					continue
				}
				if resp.StatusCode == 200 && len(body) > 100 {
					ct := resp.Header.Get("Content-Type")
					if strings.Contains(ct, "octet-stream") ||
						strings.Contains(ct, "zip") ||
						strings.Contains(ct, "gzip") ||
						strings.Contains(ct, "sql") ||
						strings.Contains(string(body[:min(100, len(body))]), "CREATE TABLE") ||
						strings.Contains(string(body[:min(100, len(body))]), "INSERT INTO") {
						return &model.VulnResult{
							TemplateID: "backup-files",
							Name:       "Backup File Detected: " + p,
							Severity:   "medium",
							URL:        url,
							MatchedAt:  url,
							Tags:       []string{"exposure"},
						}
					}
				}
			}
			return nil
		},
	}
}

func openRedirectCheck() check {
	return check{
		ID: "open-redirect", Name: "Open Redirect Detection",
		Severity: "medium", Tags: []string{"generic", "redirect"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			params := []string{"url", "redirect", "next", "return", "returnTo", "redirect_uri", "continue", "dest", "destination", "go", "target"}
			payload := "https://evil.com"
			for _, param := range params {
				url := fmt.Sprintf("%s/?%s=%s", target, param, payload)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 distributed-scanner/1.0")

				noRedirectClient := &http.Client{
					Timeout:   client.Timeout,
					Transport: client.Transport,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				resp, err := noRedirectClient.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()

				location := resp.Header.Get("Location")
				if (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307) &&
					strings.Contains(location, "evil.com") {
					return &model.VulnResult{
						TemplateID: "open-redirect",
						Name:       "Open Redirect via " + param,
						Severity:   "medium",
						URL:        url,
						MatchedAt:  url,
						Tags:       []string{"redirect"},
					}
				}
			}
			return nil
		},
	}
}

func defaultCredentialsCheck() check {
	return check{
		ID: "default-credentials", Name: "Default Credentials Detection",
		Severity: "high", Tags: []string{"generic", "default-login", "misconfig"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			endpoints := []struct {
				path  string
				creds [][2]string
				match string
			}{
				{"/manager/html", [][2]string{{"tomcat", "tomcat"}, {"admin", "admin"}}, "Tomcat"},
				{"/admin", [][2]string{{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"}}, ""},
			}

			for _, ep := range endpoints {
				for _, cred := range ep.creds {
					url := target + ep.path
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
					if err != nil {
						continue
					}
					req.SetBasicAuth(cred[0], cred[1])
					req.Header.Set("User-Agent", "Mozilla/5.0 distributed-scanner/1.0")

					resp, err := client.Do(req)
					if err != nil {
						continue
					}
					resp.Body.Close()

					if resp.StatusCode == 200 {
						return &model.VulnResult{
							TemplateID:       "default-credentials",
							Name:             fmt.Sprintf("Default Credentials: %s/%s at %s", cred[0], cred[1], ep.path),
							Severity:         "high",
							URL:              url,
							MatchedAt:        url,
							ExtractedResults: []string{fmt.Sprintf("%s:%s", cred[0], cred[1])},
							Tags:             []string{"default-login", "misconfig"},
						}
					}
				}
			}
			return nil
		},
	}
}

func serverHeaderCheck() check {
	return check{
		ID: "server-header-info", Name: "Server Header Information Disclosure",
		Severity: "info", Tags: []string{"generic", "exposure"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			resp, _, err := makeRequest(ctx, client, http.MethodGet, target)
			if err != nil {
				return nil
			}
			server := resp.Header.Get("Server")
			powered := resp.Header.Get("X-Powered-By")
			if server != "" && (strings.ContainsAny(server, "0123456789.") || powered != "") {
				extracted := []string{}
				if server != "" {
					extracted = append(extracted, "Server: "+server)
				}
				if powered != "" {
					extracted = append(extracted, "X-Powered-By: "+powered)
				}
				return &model.VulnResult{
					TemplateID:       "server-header-info",
					Name:             "Server Header Information Disclosure",
					Severity:         "info",
					URL:              target,
					MatchedAt:        target,
					ExtractedResults: extracted,
					Tags:             []string{"exposure"},
				}
			}
			return nil
		},
	}
}

func robotsTxtCheck() check {
	return check{
		ID: "robots-txt", Name: "robots.txt Found",
		Severity: "info", Tags: []string{"generic", "exposure"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			url := target + "/robots.txt"
			resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
			if err != nil {
				return nil
			}
			bodyStr := string(body)
			if resp.StatusCode == 200 &&
				(strings.Contains(bodyStr, "Disallow") || strings.Contains(bodyStr, "User-agent")) {
				return &model.VulnResult{
					TemplateID: "robots-txt",
					Name:       "robots.txt Found",
					Severity:   "info",
					URL:        url,
					MatchedAt:  url,
					Tags:       []string{"exposure"},
				}
			}
			return nil
		},
	}
}

func sitemapCheck() check {
	return check{
		ID: "sitemap-xml", Name: "sitemap.xml Found",
		Severity: "info", Tags: []string{"generic", "exposure"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			url := target + "/sitemap.xml"
			resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
			if err != nil {
				return nil
			}
			if resp.StatusCode == 200 && strings.Contains(string(body), "<urlset") {
				return &model.VulnResult{
					TemplateID: "sitemap-xml",
					Name:       "sitemap.xml Found",
					Severity:   "info",
					URL:        url,
					MatchedAt:  url,
					Tags:       []string{"exposure"},
				}
			}
			return nil
		},
	}
}

func securityHeadersCheck() check {
	return check{
		ID: "missing-security-headers", Name: "Missing Security Headers",
		Severity: "info", Tags: []string{"generic", "misconfig"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			resp, _, err := makeRequest(ctx, client, http.MethodGet, target)
			if err != nil {
				return nil
			}

			missing := []string{}
			headers := map[string]string{
				"X-Frame-Options":        "",
				"X-Content-Type-Options": "",
				"Strict-Transport-Security": "",
				"Content-Security-Policy": "",
			}
			for h := range headers {
				if resp.Header.Get(h) == "" {
					missing = append(missing, h)
				}
			}

			if len(missing) >= 3 {
				return &model.VulnResult{
					TemplateID:       "missing-security-headers",
					Name:             "Missing Security Headers",
					Severity:         "info",
					URL:              target,
					MatchedAt:        target,
					ExtractedResults: missing,
					Tags:             []string{"misconfig"},
				}
			}
			return nil
		},
	}
}

func corsWildcardCheck() check {
	return check{
		ID: "cors-wildcard", Name: "CORS Wildcard Configuration",
		Severity: "medium", Tags: []string{"generic", "misconfig", "cors"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				return nil
			}
			req.Header.Set("Origin", "https://evil.com")
			req.Header.Set("User-Agent", "Mozilla/5.0 distributed-scanner/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return nil
			}
			resp.Body.Close()

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acac := resp.Header.Get("Access-Control-Allow-Credentials")
			if acao == "*" || (acao == "https://evil.com" && acac == "true") {
				return &model.VulnResult{
					TemplateID:       "cors-wildcard",
					Name:             "CORS Misconfiguration",
					Severity:         "medium",
					URL:              target,
					MatchedAt:        target,
					ExtractedResults: []string{"ACAO: " + acao, "ACAC: " + acac},
					Tags:             []string{"misconfig", "cors"},
				}
			}
			return nil
		},
	}
}

func directoryListingCheck() check {
	return check{
		ID: "directory-listing", Name: "Directory Listing Enabled",
		Severity: "low", Tags: []string{"generic", "misconfig"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			paths := []string{"/", "/images/", "/assets/", "/static/", "/uploads/", "/css/", "/js/"}
			for _, p := range paths {
				url := target + p
				resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
				if err != nil {
					continue
				}
				bodyStr := string(body)
				if resp.StatusCode == 200 &&
					(strings.Contains(bodyStr, "Index of /") ||
						strings.Contains(bodyStr, "Directory listing for") ||
						strings.Contains(bodyStr, "<title>Directory listing")) {
					return &model.VulnResult{
						TemplateID: "directory-listing",
						Name:       "Directory Listing Enabled: " + p,
						Severity:   "low",
						URL:        url,
						MatchedAt:  url,
						Tags:       []string{"misconfig"},
					}
				}
			}
			return nil
		},
	}
}

func phpInfoCheck() check {
	return check{
		ID: "phpinfo-exposure", Name: "phpinfo() Exposure",
		Severity: "medium", Tags: []string{"php", "exposure"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			paths := []string{"/phpinfo.php", "/info.php", "/test.php", "/php_info.php", "/i.php"}
			for _, p := range paths {
				url := target + p
				resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
				if err != nil {
					continue
				}
				if resp.StatusCode == 200 && strings.Contains(string(body), "PHP Version") && strings.Contains(string(body), "phpinfo()") {
					return &model.VulnResult{
						TemplateID: "phpinfo-exposure",
						Name:       "phpinfo() Exposure: " + p,
						Severity:   "medium",
						URL:        url,
						MatchedAt:  url,
						Tags:       []string{"php", "exposure"},
					}
				}
			}
			return nil
		},
	}
}

func springActuatorCheck() check {
	return check{
		ID: "spring-actuator", Name: "Spring Boot Actuator Exposure",
		Severity: "high", Tags: []string{"spring", "exposure", "misconfig"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			paths := []string{
				"/actuator", "/actuator/env", "/actuator/health",
				"/actuator/configprops", "/actuator/mappings",
				"/env", "/health", "/mappings",
			}
			for _, p := range paths {
				url := target + p
				resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
				if err != nil {
					continue
				}
				bodyStr := string(body)
				if resp.StatusCode == 200 {
					ct := resp.Header.Get("Content-Type")
					if strings.Contains(ct, "json") &&
						(strings.Contains(bodyStr, "\"status\"") ||
							strings.Contains(bodyStr, "\"_links\"") ||
							strings.Contains(bodyStr, "\"activeProfiles\"") ||
							strings.Contains(bodyStr, "\"propertySources\"")) {
						return &model.VulnResult{
							TemplateID: "spring-actuator",
							Name:       "Spring Boot Actuator: " + p,
							Severity:   "high",
							URL:        url,
							MatchedAt:  url,
							Tags:       []string{"spring", "exposure"},
						}
					}
				}
			}
			return nil
		},
	}
}

func swaggerUICheck() check {
	return check{
		ID: "swagger-ui", Name: "Swagger UI Exposure",
		Severity: "low", Tags: []string{"swagger", "exposure"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			paths := []string{
				"/swagger-ui.html", "/swagger-ui/", "/swagger/",
				"/api-docs", "/v2/api-docs", "/v3/api-docs",
				"/swagger.json", "/openapi.json",
			}
			for _, p := range paths {
				url := target + p
				resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
				if err != nil {
					continue
				}
				bodyStr := string(body)
				if resp.StatusCode == 200 &&
					(strings.Contains(bodyStr, "swagger") ||
						strings.Contains(bodyStr, "openapi") ||
						strings.Contains(bodyStr, "\"paths\"") ||
						strings.Contains(bodyStr, "Swagger UI")) {
					return &model.VulnResult{
						TemplateID: "swagger-ui",
						Name:       "Swagger/OpenAPI Exposure: " + p,
						Severity:   "low",
						URL:        url,
						MatchedAt:  url,
						Tags:       []string{"swagger", "exposure"},
					}
				}
			}
			return nil
		},
	}
}

func graphQLCheck() check {
	return check{
		ID: "graphql-exposure", Name: "GraphQL Endpoint Exposure",
		Severity: "medium", Tags: []string{"generic", "graphql", "exposure"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			paths := []string{"/graphql", "/graphiql", "/v1/graphql", "/api/graphql"}
			for _, p := range paths {
				url := target + p + "?query={__schema{types{name}}}"
				resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
				if err != nil {
					continue
				}
				bodyStr := string(body)
				if resp.StatusCode == 200 &&
					(strings.Contains(bodyStr, "__schema") ||
						strings.Contains(bodyStr, "\"data\"") ||
						strings.Contains(bodyStr, "GraphiQL")) {
					return &model.VulnResult{
						TemplateID: "graphql-exposure",
						Name:       "GraphQL Endpoint: " + p,
						Severity:   "medium",
						URL:        target + p,
						MatchedAt:  target + p,
						Tags:       []string{"graphql", "exposure"},
					}
				}
			}
			return nil
		},
	}
}

func wordpressUserEnum() check {
	return check{
		ID: "wp-user-enum", Name: "WordPress User Enumeration",
		Severity: "low", Tags: []string{"wordpress", "wp"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			url := target + "/wp-json/wp/v2/users"
			resp, body, err := makeRequest(ctx, client, http.MethodGet, url)
			if err != nil {
				return nil
			}
			bodyStr := string(body)
			if resp.StatusCode == 200 && strings.Contains(bodyStr, "\"slug\"") && strings.Contains(bodyStr, "\"name\"") {
				return &model.VulnResult{
					TemplateID: "wp-user-enum",
					Name:       "WordPress User Enumeration",
					Severity:   "low",
					URL:        url,
					MatchedAt:  url,
					Tags:       []string{"wordpress", "wp"},
				}
			}
			return nil
		},
	}
}

func wpXMLRPC() check {
	return check{
		ID: "wp-xmlrpc", Name: "WordPress XML-RPC Enabled",
		Severity: "medium", Tags: []string{"wordpress", "wp"},
		Run: func(ctx context.Context, client *http.Client, target string) *model.VulnResult {
			url := target + "/xmlrpc.php"
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
				strings.NewReader(`<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`))
			if err != nil {
				return nil
			}
			req.Header.Set("Content-Type", "text/xml")
			req.Header.Set("User-Agent", "Mozilla/5.0 distributed-scanner/1.0")

			resp, err := client.Do(req)
			if err != nil {
				return nil
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

			bodyStr := string(body)
			if resp.StatusCode == 200 && strings.Contains(bodyStr, "methodResponse") {
				return &model.VulnResult{
					TemplateID: "wp-xmlrpc",
					Name:       "WordPress XML-RPC Enabled",
					Severity:   "medium",
					URL:        url,
					MatchedAt:  url,
					Tags:       []string{"wordpress", "wp"},
				}
			}
			return nil
		},
	}
}

func coalesce(val, fallback int) int {
	if val > 0 {
		return val
	}
	return fallback
}
