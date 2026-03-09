package subfinder

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

const (
	defaultThreads   = 20
	defaultTimeoutS  = 10
	defaultMaxEnum   = 300
	crtShURL         = "https://crt.sh/?q=%%25.%s&output=json"
)

var commonPrefixes = []string{
	"www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
	"dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev",
	"staging", "test", "api", "app", "admin", "portal", "vpn",
	"remote", "gateway", "gw", "proxy", "cdn", "static", "assets",
	"img", "images", "media", "docs", "wiki", "forum", "shop",
	"store", "m", "mobile", "beta", "alpha", "demo", "uat",
	"qa", "ci", "git", "svn", "jenkins", "jira", "confluence",
	"grafana", "monitor", "status", "health", "db", "database",
	"redis", "elastic", "es", "kafka", "mq", "rabbitmq",
	"sso", "auth", "login", "id", "oauth", "cas",
	"backup", "bak", "old", "new", "v2", "internal",
	"intranet", "extranet", "owa", "exchange", "autodiscover",
	"cpanel", "whm", "plesk", "panel", "console",
	"s3", "storage", "cloud", "aws", "azure", "gcp",
}

type ScanInput struct {
	Domains   []string                `json:"domains"`
	Options   model.SubfinderOptions  `json:"options"`
	Providers []*model.ProviderConfig `json:"providers"`
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func Scan(ctx context.Context, input ScanInput) ([]string, error) {
	opts := input.Options
	threads := coalesce(opts.Threads, defaultThreads)
	timeout := time.Duration(coalesce(opts.Timeout, defaultTimeoutS)) * time.Second
	maxEnum := time.Duration(coalesce(opts.MaxEnumTime, defaultMaxEnum)) * time.Second

	enumCtx, cancel := context.WithTimeout(ctx, maxEnum)
	defer cancel()

	logger.L.Infow("subfinder scan starting",
		"domains", input.Domains,
		"threads", threads,
		"timeout", timeout,
	)

	seen := &sync.Map{}
	var mu sync.Mutex
	var results []string

	addResult := func(sub string) {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub == "" {
			return
		}
		sub = strings.TrimPrefix(sub, "*.")
		if _, loaded := seen.LoadOrStore(sub, struct{}{}); !loaded {
			mu.Lock()
			results = append(results, sub)
			mu.Unlock()
		}
	}

	var wg sync.WaitGroup

	for _, domain := range input.Domains {
		d := domain

		wg.Add(1)
		go func() {
			defer wg.Done()
			subs := queryCrtSh(enumCtx, d, timeout)
			for _, s := range subs {
				addResult(s)
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			subs := dnsEnumerate(enumCtx, d, threads, timeout)
			for _, s := range subs {
				addResult(s)
			}
		}()

		addResult(d)
	}

	wg.Wait()

	sort.Strings(results)
	logger.L.Infow("subfinder scan completed", "total", len(results))
	return results, nil
}

func queryCrtSh(ctx context.Context, domain string, timeout time.Duration) []string {
	client := &http.Client{
		Timeout: timeout * 3,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	url := fmt.Sprintf(crtShURL, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logger.L.Warnw("crt.sh request build failed", "domain", domain, "error", err)
		return nil
	}
	req.Header.Set("User-Agent", "distributed-scanner/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logger.L.Warnw("crt.sh request failed", "domain", domain, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.L.Warnw("crt.sh non-200 response", "domain", domain, "status", resp.StatusCode)
		return nil
	}

	var entries []crtEntry
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		// crt.sh sometimes returns non-strict JSON; retry with lenient decoder
		logger.L.Debugw("crt.sh decode error, trying lenient parse", "error", err)
		return nil
	}

	var subs []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if name != "" && strings.HasSuffix(name, domain) {
				subs = append(subs, name)
			}
		}
	}

	logger.L.Infow("crt.sh results", "domain", domain, "found", len(subs))
	return subs
}

func dnsEnumerate(ctx context.Context, domain string, threads int, timeout time.Duration) []string {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	prefixCh := make(chan string, threads*2)
	var (
		mu      sync.Mutex
		results []string
		done    int64
		total   = int64(len(commonPrefixes))
	)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for prefix := range prefixCh {
				if ctx.Err() != nil {
					return
				}
				fqdn := prefix + "." + domain
				lookupCtx, cancel := context.WithTimeout(ctx, timeout)
				addrs, err := resolver.LookupHost(lookupCtx, fqdn)
				cancel()
				if err == nil && len(addrs) > 0 {
					mu.Lock()
					results = append(results, fqdn)
					mu.Unlock()
				}
				n := atomic.AddInt64(&done, 1)
				if n%50 == 0 {
					logger.L.Debugw("dns brute progress", "domain", domain, "done", n, "total", total)
				}
			}
		}()
	}

	go func() {
		defer close(prefixCh)
		for _, p := range commonPrefixes {
			select {
			case prefixCh <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	logger.L.Infow("dns enumeration results", "domain", domain, "found", len(results))
	return results
}

func coalesce(val, fallback int) int {
	if val > 0 {
		return val
	}
	return fallback
}
