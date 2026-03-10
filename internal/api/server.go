package api

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/xiaoyu/distributed-scanner/internal/api/middleware"
	"github.com/xiaoyu/distributed-scanner/internal/store"
	"github.com/xiaoyu/distributed-scanner/pkg/config"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
	temporalclient "go.temporal.io/sdk/client"
)

type Server struct {
	engine   *gin.Engine
	cfg      *config.Config
	db       *store.MongoDB
	temporal temporalclient.Client
}

func NewServer(cfg *config.Config, db *store.MongoDB) (*Server, error) {
	tc, err := temporalclient.Dial(temporalclient.Options{
		HostPort:  cfg.Temporal.Host,
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to temporal: %w", err)
	}
	logger.L.Infow("connected to Temporal", "host", cfg.Temporal.Host)

	s := &Server{cfg: cfg, db: db, temporal: tc}
	s.engine = gin.New()
	s.engine.Use(gin.Recovery())
	s.engine.Use(middleware.CORS())
	s.setupRoutes()

	dictStore := store.NewDictionaryStore(db)
	if err := dictStore.SeedBuiltinDictionaries(context.Background(), cfg.Scanner.DictDir); err != nil {
		logger.L.Warnw("failed to seed builtin dictionaries", "error", err)
	}

	return s, nil
}

func (s *Server) Run(addr string) error {
	return s.engine.Run(addr)
}

func (s *Server) Close() {
	if s.temporal != nil {
		s.temporal.Close()
	}
}
