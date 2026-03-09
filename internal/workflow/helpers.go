package workflow

import "github.com/xiaoyu/distributed-scanner/internal/model"

func buildHostIPMap(domains []string, dnsMap map[string][]string, extraIPs []string) map[string][]string {
	m := make(map[string][]string)
	for _, d := range domains {
		if ips, ok := dnsMap[d]; ok {
			m[d] = ips
		}
	}
	for _, ip := range extraIPs {
		if _, ok := m[ip]; !ok {
			m[ip] = []string{ip}
		}
	}
	return m
}

func extractUniqueIPs(hostIPMap map[string][]string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, ips := range hostIPMap {
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				result = append(result, ip)
			}
		}
	}
	return result
}

func buildIPPortMap(ports []model.PortResult) map[string][]model.PortResult {
	m := make(map[string][]model.PortResult)
	for _, p := range ports {
		m[p.IP] = append(m[p.IP], p)
	}
	return m
}

func expandHostTargets(hostIPMap map[string][]string, ipPortMap map[string][]model.PortResult) []model.HttpxTarget {
	var targets []model.HttpxTarget
	for host, ips := range hostIPMap {
		for _, ip := range ips {
			if ports, ok := ipPortMap[ip]; ok {
				for _, p := range ports {
					targets = append(targets, model.HttpxTarget{
						Host:     host,
						IP:       ip,
						Port:     p.Port,
						Protocol: p.Protocol,
					})
				}
			}
		}
	}
	return targets
}

func filterAliveWebs(results []model.HttpxResult) []model.HttpxResult {
	var alive []model.HttpxResult
	for _, r := range results {
		if r.StatusCode >= 200 && r.StatusCode < 400 {
			alive = append(alive, r)
		}
	}
	return alive
}

func buildBruteTargets(ipPortMap map[string][]model.PortResult) []BruteTarget {
	var targets []BruteTarget
	for ip, ports := range ipPortMap {
		for _, p := range ports {
			if svc, ok := model.PortServiceMap[p.Port]; ok {
				targets = append(targets, BruteTarget{
					IP:      ip,
					Port:    p.Port,
					Service: svc,
				})
			}
		}
	}
	return targets
}

type NucleiTarget struct {
	URL             string   `json:"url"`
	Host            string   `json:"host"`
	Technologies    []string `json:"technologies"`
	DiscoveredPaths []string `json:"discovered_paths"`
}

func buildNucleiTargets(httpx []model.HttpxResult, dirs []model.DirResult, crawls []model.CrawlResult) []NucleiTarget {
	pathsByHost := make(map[string][]string)
	for _, d := range dirs {
		pathsByHost[d.Host] = append(pathsByHost[d.Host], d.Path)
	}
	for _, c := range crawls {
		pathsByHost[c.Host] = append(pathsByHost[c.Host], c.URL)
	}

	var targets []NucleiTarget
	for _, h := range httpx {
		if h.StatusCode >= 200 && h.StatusCode < 400 {
			targets = append(targets, NucleiTarget{
				URL:             h.URL,
				Host:            h.Host,
				Technologies:    h.Technologies,
				DiscoveredPaths: pathsByHost[h.Host],
			})
		}
	}
	return targets
}
