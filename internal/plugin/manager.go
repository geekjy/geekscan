package plugin

import (
	"context"
	"fmt"
	"sync"

	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

type Manager struct {
	mu       sync.RWMutex
	plugins  map[string]Plugin
	disabled map[string]bool
}

func NewManager() *Manager {
	return &Manager{
		plugins:  make(map[string]Plugin),
		disabled: make(map[string]bool),
	}
}

func (m *Manager) Register(p Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := p.Name()
	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("plugin %q already registered", name)
	}
	m.plugins[name] = p
	logger.L.Infow("plugin registered", "name", name, "category", p.Category())
	return nil
}

func (m *Manager) List() []Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		list = append(list, p)
	}
	return list
}

func (m *Manager) Get(name string) (Plugin, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.plugins[name]
	return p, ok
}

func (m *Manager) Enable(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.plugins[name]; !ok {
		return fmt.Errorf("plugin %q not found", name)
	}
	delete(m.disabled, name)
	return nil
}

func (m *Manager) Disable(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.plugins[name]; !ok {
		return fmt.Errorf("plugin %q not found", name)
	}
	m.disabled[name] = true
	return nil
}

func (m *Manager) IsEnabled(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !m.disabled[name]
}

func (m *Manager) EnabledPlugins() []Plugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []Plugin
	for name, p := range m.plugins {
		if !m.disabled[name] {
			list = append(list, p)
		}
	}
	return list
}

func (m *Manager) ExecuteAll(ctx context.Context, target Target) ([]Result, error) {
	plugins := m.EnabledPlugins()

	var (
		mu         sync.Mutex
		allResults []Result
		wg         sync.WaitGroup
	)

	for _, p := range plugins {
		wg.Add(1)
		go func(plug Plugin) {
			defer wg.Done()
			results, err := plug.Execute(ctx, target)
			if err != nil {
				logger.L.Warnw("plugin execution failed",
					"plugin", plug.Name(),
					"error", err,
				)
				return
			}
			mu.Lock()
			allResults = append(allResults, results...)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	return allResults, nil
}
