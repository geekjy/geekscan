package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type SubdomainResult struct {
	Host string   `json:"host" bson:"host"`
	IPs  []string `json:"ips" bson:"ips"`
}

type PortResult struct {
	IP       string `json:"ip" bson:"ip"`
	Port     int    `json:"port" bson:"port"`
	Protocol string `json:"protocol" bson:"protocol"`
	Service  string `json:"service" bson:"service"`
}

type HttpxResult struct {
	URL            string   `json:"url" bson:"url"`
	Host           string   `json:"host" bson:"host"`
	IP             string   `json:"ip" bson:"ip"`
	Port           int      `json:"port" bson:"port"`
	StatusCode     int      `json:"status_code" bson:"status_code"`
	ContentLength  int      `json:"content_length" bson:"content_length"`
	Title          string   `json:"title" bson:"title"`
	Technologies   []string `json:"technologies" bson:"technologies"`
	ScreenshotPath string   `json:"screenshot_path" bson:"screenshot_path"`
	ResponseHash   string   `json:"response_hash" bson:"response_hash"`
	HasLoginForm   bool     `json:"has_login_form" bson:"has_login_form"`
	FormInfo       *FormInfo `json:"form_info,omitempty" bson:"form_info,omitempty"`
}

type FormInfo struct {
	ActionURL     string `json:"action_url" bson:"action_url"`
	Method        string `json:"method" bson:"method"`
	UsernameField string `json:"username_field" bson:"username_field"`
	PasswordField string `json:"password_field" bson:"password_field"`
	CSRFField     string `json:"csrf_field" bson:"csrf_field"`
}

type DirResult struct {
	URL           string `json:"url" bson:"url"`
	Host          string `json:"host" bson:"host"`
	Path          string `json:"path" bson:"path"`
	StatusCode    int    `json:"status_code" bson:"status_code"`
	ContentLength int    `json:"content_length" bson:"content_length"`
	Words         int    `json:"words" bson:"words"`
	Lines         int    `json:"lines" bson:"lines"`
}

type CrawlResult struct {
	URL        string            `json:"url" bson:"url"`
	Method     string            `json:"method" bson:"method"`
	Host       string            `json:"host" bson:"host"`
	Path       string            `json:"path" bson:"path"`
	Parameters map[string]string `json:"parameters" bson:"parameters"`
	Headers    map[string]string `json:"headers" bson:"headers"`
	Source     string            `json:"source" bson:"source"`
}

type VulnResult struct {
	TemplateID       string    `json:"template_id" bson:"template_id"`
	Name             string    `json:"name" bson:"name"`
	Severity         string    `json:"severity" bson:"severity"`
	Host             string    `json:"host" bson:"host"`
	URL              string    `json:"url" bson:"url"`
	MatchedAt        string    `json:"matched_at" bson:"matched_at"`
	ExtractedResults []string  `json:"extracted_results" bson:"extracted_results"`
	CURLCommand      string    `json:"curl_command" bson:"curl_command"`
	Reference        []string  `json:"reference" bson:"reference"`
	Tags             []string  `json:"tags" bson:"tags"`
	Source           string    `json:"source" bson:"source"` // "nuclei" or "awvs"
	Timestamp        time.Time `json:"timestamp" bson:"timestamp"`
}

type ScanResult struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	TaskID   primitive.ObjectID `json:"task_id" bson:"task_id"`
	Type     string             `json:"type" bson:"type"` // "port","httpx","dir","crawl","vuln","brute"
	Data     interface{}        `json:"data" bson:"data"`
	CreateAt time.Time          `json:"created_at" bson:"created_at"`
}
