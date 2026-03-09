package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	goplugin "plugin"
	"runtime"

	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

type Loader struct {
	manager *Manager
}

func NewLoader(manager *Manager) *Loader {
	return &Loader{manager: manager}
}

// LoadDir scans dir for .so plugin files and loads each one.
// On Windows, Go plugins (.so) are not supported; the loader logs a
// warning and returns gracefully.
func (l *Loader) LoadDir(dir string) error {
	if runtime.GOOS == "windows" {
		logger.L.Warnw("Go plugin loading is not supported on Windows, skipping",
			"dir", dir,
		)
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.L.Infow("plugin directory does not exist, skipping", "dir", dir)
			return nil
		}
		return fmt.Errorf("read plugin directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".so" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := l.loadPlugin(path); err != nil {
			logger.L.Warnw("failed to load plugin, skipping",
				"path", path,
				"error", err,
			)
		}
	}
	return nil
}

func (l *Loader) loadPlugin(path string) error {
	p, err := goplugin.Open(path)
	if err != nil {
		return fmt.Errorf("open plugin: %w", err)
	}

	sym, err := p.Lookup("NewPlugin")
	if err != nil {
		return fmt.Errorf("lookup NewPlugin symbol: %w", err)
	}

	newPluginFn, ok := sym.(func() Plugin)
	if !ok {
		return fmt.Errorf("NewPlugin has unexpected signature in %s", path)
	}

	plug := newPluginFn()
	if err := l.manager.Register(plug); err != nil {
		return fmt.Errorf("register plugin: %w", err)
	}

	logger.L.Infow("plugin loaded from file", "path", path, "name", plug.Name())
	return nil
}
