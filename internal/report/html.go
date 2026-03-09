package report

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/xiaoyu/distributed-scanner/internal/model"
)

type ReportData struct {
	TaskName    string
	Targets     []string
	GeneratedAt time.Time

	Ports        []model.PortResult
	WebFingers   []model.HttpxResult
	Directories  []model.DirResult
	CrawledURLs  []model.CrawlResult
	Vulns        []model.VulnResult
	BruteResults []model.BruteResult
}

func GenerateHTML(data *ReportData, outputPath string) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityClass": severityClass,
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	return nil
}

func severityClass(sev string) string {
	switch sev {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	default:
		return "sev-info"
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>扫描报告 - {{.TaskName}}</title>
<style>
  :root {
    --bg: #f5f7fa;
    --card: #ffffff;
    --border: #e2e8f0;
    --text: #1a202c;
    --muted: #718096;
    --primary: #3182ce;
    --critical: #e53e3e;
    --high: #dd6b20;
    --medium: #d69e2e;
    --low: #38a169;
    --info: #718096;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text);
    line-height: 1.6; padding: 2rem;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
  h2 {
    font-size: 1.25rem; margin: 2rem 0 1rem;
    padding-bottom: 0.5rem; border-bottom: 2px solid var(--primary);
  }
  .meta { color: var(--muted); margin-bottom: 2rem; }
  .summary-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }
  .summary-card {
    background: var(--card); border-radius: 8px; padding: 1.25rem;
    border: 1px solid var(--border); text-align: center;
  }
  .summary-card .num { font-size: 2rem; font-weight: 700; color: var(--primary); }
  .summary-card .label { color: var(--muted); font-size: 0.875rem; }
  table {
    width: 100%; border-collapse: collapse; background: var(--card);
    border-radius: 8px; overflow: hidden; margin-bottom: 1.5rem;
    border: 1px solid var(--border);
  }
  th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: #edf2f7; font-weight: 600; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f7fafc; }
  .sev-critical { background: var(--critical); color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
  .sev-high { background: var(--high); color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
  .sev-medium { background: var(--medium); color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
  .sev-low { background: var(--low); color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
  .sev-info { background: var(--info); color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
  .empty { text-align: center; color: var(--muted); padding: 2rem; }
  .tag { display: inline-block; background: #ebf4ff; color: var(--primary); padding: 2px 6px; border-radius: 3px; font-size: 0.8rem; margin: 1px; }
  a { color: var(--primary); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .truncate { max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
</head>
<body>
<div class="container">
  <h1>扫描报告：{{.TaskName}}</h1>
  <div class="meta">
    生成时间：{{.GeneratedAt.Format "2006-01-02 15:04:05"}} &nbsp;|&nbsp;
    目标：{{range $i, $t := .Targets}}{{if $i}}, {{end}}{{$t}}{{end}}
  </div>

  <h2>概览</h2>
  <div class="summary-grid">
    <div class="summary-card"><div class="num">{{len .Ports}}</div><div class="label">开放端口</div></div>
    <div class="summary-card"><div class="num">{{len .WebFingers}}</div><div class="label">Web 指纹</div></div>
    <div class="summary-card"><div class="num">{{len .Directories}}</div><div class="label">目录/路径</div></div>
    <div class="summary-card"><div class="num">{{len .CrawledURLs}}</div><div class="label">爬取 URL</div></div>
    <div class="summary-card"><div class="num">{{len .Vulns}}</div><div class="label">漏洞</div></div>
    <div class="summary-card"><div class="num">{{len .BruteResults}}</div><div class="label">爆破结果</div></div>
  </div>

  {{if .Ports}}
  <h2>端口扫描</h2>
  <table>
    <thead><tr><th>IP</th><th>端口</th><th>协议</th><th>服务</th></tr></thead>
    <tbody>
    {{range .Ports}}
      <tr><td>{{.IP}}</td><td>{{.Port}}</td><td>{{.Protocol}}</td><td>{{.Service}}</td></tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  {{if .WebFingers}}
  <h2>Web 指纹</h2>
  <table>
    <thead><tr><th>URL</th><th>状态码</th><th>标题</th><th>技术栈</th></tr></thead>
    <tbody>
    {{range .WebFingers}}
      <tr>
        <td class="truncate"><a href="{{.URL}}">{{.URL}}</a></td>
        <td>{{.StatusCode}}</td>
        <td class="truncate">{{.Title}}</td>
        <td>{{range .Technologies}}<span class="tag">{{.}}</span>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  {{if .Directories}}
  <h2>目录扫描</h2>
  <table>
    <thead><tr><th>URL</th><th>路径</th><th>状态码</th><th>长度</th></tr></thead>
    <tbody>
    {{range .Directories}}
      <tr>
        <td class="truncate"><a href="{{.URL}}">{{.Host}}</a></td>
        <td>{{.Path}}</td>
        <td>{{.StatusCode}}</td>
        <td>{{.ContentLength}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  {{if .CrawledURLs}}
  <h2>爬取 URL</h2>
  <table>
    <thead><tr><th>URL</th><th>方法</th><th>路径</th><th>来源</th></tr></thead>
    <tbody>
    {{range .CrawledURLs}}
      <tr>
        <td class="truncate"><a href="{{.URL}}">{{.URL}}</a></td>
        <td>{{.Method}}</td>
        <td>{{.Path}}</td>
        <td>{{.Source}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  {{if .Vulns}}
  <h2>漏洞</h2>
  <table>
    <thead><tr><th>名称</th><th>严重性</th><th>URL</th><th>来源</th><th>标签</th></tr></thead>
    <tbody>
    {{range .Vulns}}
      <tr>
        <td>{{.Name}}</td>
        <td><span class="{{severityClass .Severity}}">{{.Severity}}</span></td>
        <td class="truncate"><a href="{{.URL}}">{{.URL}}</a></td>
        <td>{{.Source}}</td>
        <td>{{range .Tags}}<span class="tag">{{.}}</span>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  {{if .BruteResults}}
  <h2>爆破结果</h2>
  <table>
    <thead><tr><th>IP</th><th>端口</th><th>服务</th><th>用户名</th><th>密码</th><th>状态</th></tr></thead>
    <tbody>
    {{range .BruteResults}}
      <tr>
        <td>{{.IP}}</td>
        <td>{{.Port}}</td>
        <td>{{.Service}}</td>
        <td>{{.Username}}</td>
        <td>{{.Password}}</td>
        <td>{{if .Success}}<span class="sev-critical">成功</span>{{else}}失败{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}
</div>
</body>
</html>`
