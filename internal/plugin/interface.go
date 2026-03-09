package plugin

import "context"

type Plugin interface {
	Name() string
	Category() string
	Execute(ctx context.Context, target Target) ([]Result, error)
}

type Target struct {
	URL  string
	Host string
	IP   string
	Port int
}

type Result struct {
	Name     string
	Severity string
	Detail   string
	URL      string
}
