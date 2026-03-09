package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusPaused    TaskStatus = "paused"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

type ScanTask struct {
	ID          primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name        string             `json:"name" bson:"name"`
	Status      TaskStatus         `json:"status" bson:"status"`
	WorkflowID  string             `json:"workflow_id" bson:"workflow_id"`
	RunID       string             `json:"run_id" bson:"run_id"`
	CurrentStage string            `json:"current_stage" bson:"current_stage"`
	Progress    float64            `json:"progress" bson:"progress"`

	Targets []string `json:"targets" bson:"targets"` // domains, IPs, CIDRs
	Domains []string `json:"domains" bson:"domains"`
	IPs     []string `json:"ips" bson:"ips"`

	NaabuOptions      NaabuOptions      `json:"naabu_options" bson:"naabu_options"`
	HttpxOptions      HttpxOptions      `json:"httpx_options" bson:"httpx_options"`
	SubfinderOptions  SubfinderOptions  `json:"subfinder_options" bson:"subfinder_options"`
	FfufOptions       FfufOptions       `json:"ffuf_options" bson:"ffuf_options"`
	RadOptions        RadOptions        `json:"rad_options" bson:"rad_options"`
	NucleiOptions     NucleiOptions     `json:"nuclei_options" bson:"nuclei_options"`
	BruteForceOptions BruteForceOptions `json:"bruteforce_options" bson:"bruteforce_options"`
	AwvsOptions       AwvsOptions       `json:"awvs_options" bson:"awvs_options"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

type NaabuOptions struct {
	PortStrategy  string `json:"port_strategy" bson:"port_strategy"`
	CustomPorts   string `json:"custom_ports" bson:"custom_ports"`
	ScanType      string `json:"scan_type" bson:"scan_type"`
	EnableUDP     bool   `json:"enable_udp" bson:"enable_udp"`
	Rate          int    `json:"rate" bson:"rate"`
	Threads       int    `json:"threads" bson:"threads"`
	Timeout       int    `json:"timeout" bson:"timeout"`
	Retries       int    `json:"retries" bson:"retries"`
	WarmUpTime    int    `json:"warm_up_time" bson:"warm_up_time"`
	InterfaceName string `json:"interface" bson:"interface"`
	Nmap          bool   `json:"nmap" bson:"nmap"`
	ExcludePorts  string `json:"exclude_ports" bson:"exclude_ports"`
	ChunkSize     int    `json:"chunk_size" bson:"chunk_size"`
}

type HttpxOptions struct {
	Threads        int      `json:"threads" bson:"threads"`
	Timeout        int      `json:"timeout" bson:"timeout"`
	Retries        int      `json:"retries" bson:"retries"`
	RateLimit      int      `json:"rate_limit" bson:"rate_limit"`
	StatusCode     bool     `json:"status_code" bson:"status_code"`
	ContentLength  bool     `json:"content_length" bson:"content_length"`
	Title          bool     `json:"title" bson:"title"`
	TechDetect     bool     `json:"tech_detect" bson:"tech_detect"`
	Screenshot     bool     `json:"screenshot" bson:"screenshot"`
	FollowRedirect bool     `json:"follow_redirect" bson:"follow_redirect"`
	CustomHeaders  []string `json:"custom_headers" bson:"custom_headers"`
	HttpProxy      string   `json:"http_proxy" bson:"http_proxy"`
	MatchCodes     []int    `json:"match_codes" bson:"match_codes"`
	FilterCodes    []int    `json:"filter_codes" bson:"filter_codes"`
}

type SubfinderOptions struct {
	Threads        int      `json:"threads" bson:"threads"`
	Timeout        int      `json:"timeout" bson:"timeout"`
	MaxEnumTime    int      `json:"max_enum_time" bson:"max_enum_time"`
	Sources        []string `json:"sources" bson:"sources"`
	ExcludeSources []string `json:"exclude_sources" bson:"exclude_sources"`
	All            bool     `json:"all" bson:"all"`
}

type FfufOptions struct {
	DictionaryID   string   `json:"dictionary_id" bson:"dictionary_id"`
	Threads        int      `json:"threads" bson:"threads"`
	Timeout        int      `json:"timeout" bson:"timeout"`
	Rate           int      `json:"rate" bson:"rate"`
	MatchCodes     []int    `json:"match_codes" bson:"match_codes"`
	FilterCodes    []int    `json:"filter_codes" bson:"filter_codes"`
	FilterSize     []int    `json:"filter_size" bson:"filter_size"`
	FilterWords    []int    `json:"filter_words" bson:"filter_words"`
	Extensions     []string `json:"extensions" bson:"extensions"`
	Recursion      bool     `json:"recursion" bson:"recursion"`
	RecursionDepth int      `json:"recursion_depth" bson:"recursion_depth"`
	CustomHeaders  []string `json:"custom_headers" bson:"custom_headers"`
	HttpProxy      string   `json:"http_proxy" bson:"http_proxy"`
	AutoCalibrate  bool     `json:"auto_calibrate" bson:"auto_calibrate"`
}

type RadOptions struct {
	Enabled       bool     `json:"enabled" bson:"enabled"`
	MaxTime       int      `json:"max_time" bson:"max_time"`
	MaxCrawlCount int      `json:"max_crawl_count" bson:"max_crawl_count"`
	MaxDepth      int      `json:"max_depth" bson:"max_depth"`
	Threads       int      `json:"threads" bson:"threads"`
	ExcludeExts   []string `json:"exclude_exts" bson:"exclude_exts"`
	ExcludePaths  []string `json:"exclude_paths" bson:"exclude_paths"`
	IncludeDomain []string `json:"include_domain" bson:"include_domain"`
	Cookies       string   `json:"cookies" bson:"cookies"`
	Headers       []string `json:"headers" bson:"headers"`
	HttpProxy     string   `json:"http_proxy" bson:"http_proxy"`
	WaitLoad      int      `json:"wait_load" bson:"wait_load"`
}

type NucleiOptions struct {
	MaxTime              int      `json:"max_time" bson:"max_time"`
	Severity             []string `json:"severity" bson:"severity"`
	Tags                 []string `json:"tags" bson:"tags"`
	ExcludeTags          []string `json:"exclude_tags" bson:"exclude_tags"`
	TemplateIDs          []string `json:"template_ids" bson:"template_ids"`
	ExcludeIDs           []string `json:"exclude_ids" bson:"exclude_ids"`
	Threads              int      `json:"threads" bson:"threads"`
	RateLimit            int      `json:"rate_limit" bson:"rate_limit"`
	BulkSize             int      `json:"bulk_size" bson:"bulk_size"`
	Timeout              int      `json:"timeout" bson:"timeout"`
	Retries              int      `json:"retries" bson:"retries"`
	AutoFingerprintMatch bool     `json:"auto_fingerprint_match" bson:"auto_fingerprint_match"`
	CustomHeaders        []string `json:"custom_headers" bson:"custom_headers"`
	HttpProxy            string   `json:"http_proxy" bson:"http_proxy"`
	InteractshURL        string   `json:"interactsh_url" bson:"interactsh_url"`
	HeadlessMode         bool     `json:"headless_mode" bson:"headless_mode"`
}

type BruteForceOptions struct {
	Enabled         bool     `json:"enabled" bson:"enabled"`
	Services        []string `json:"services" bson:"services"`
	ExcludeServices []string `json:"exclude_services" bson:"exclude_services"`
	UserDictID      string   `json:"user_dict_id" bson:"user_dict_id"`
	PassDictID      string   `json:"pass_dict_id" bson:"pass_dict_id"`
	DefaultUsers    []string `json:"default_users" bson:"default_users"`
	DefaultPasswd   []string `json:"default_passwd" bson:"default_passwd"`
	Threads         int      `json:"threads" bson:"threads"`
	Timeout         int      `json:"timeout" bson:"timeout"`
	MaxTime         int      `json:"max_time" bson:"max_time"`
	StopOnFirst     bool     `json:"stop_on_first" bson:"stop_on_first"`
	MaxRetries      int      `json:"max_retries" bson:"max_retries"`
	Delay           int      `json:"delay" bson:"delay"`
	WebOptions      WebBruteOptions `json:"web_options" bson:"web_options"`
}

type WebBruteOptions struct {
	Enabled        bool     `json:"enabled" bson:"enabled"`
	UserDictID     string   `json:"user_dict_id" bson:"user_dict_id"`
	PassDictID     string   `json:"pass_dict_id" bson:"pass_dict_id"`
	Threads        int      `json:"threads" bson:"threads"`
	MaxTime        int      `json:"max_time" bson:"max_time"`
	Delay          int      `json:"delay" bson:"delay"`
	SuccessPattern string   `json:"success_pattern" bson:"success_pattern"`
	FailurePattern string   `json:"failure_pattern" bson:"failure_pattern"`
	FollowRedirect bool     `json:"follow_redirect" bson:"follow_redirect"`
	CustomHeaders  []string `json:"custom_headers" bson:"custom_headers"`
	HttpProxy      string   `json:"http_proxy" bson:"http_proxy"`
}

type AwvsOptions struct {
	Enabled       bool   `json:"enabled" bson:"enabled"`
	ApiURL        string `json:"api_url" bson:"api_url"`
	ApiKey        string `json:"api_key" bson:"api_key"`
	ScanProfileID string `json:"scan_profile_id" bson:"scan_profile_id"`
	PollInterval  int    `json:"poll_interval" bson:"poll_interval"`
	MaxTime       int    `json:"max_time" bson:"max_time"`
	WaitForResult bool   `json:"wait_for_result" bson:"wait_for_result"`
}
