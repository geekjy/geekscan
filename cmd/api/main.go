package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiaoyu/distributed-scanner/internal/api"
	"github.com/xiaoyu/distributed-scanner/internal/store"
	"github.com/xiaoyu/distributed-scanner/pkg/config"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "config file path")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	logger.Init(cfg.Log.Level, cfg.Log.Format, cfg.Log.Output)
	defer logger.L.Sync()

	db, err := store.NewMongoDB(cfg.MongoDB.URI, cfg.MongoDB.Database)
	if err != nil {
		logger.L.Fatalf("failed to connect to MongoDB: %v", err)
	}
	defer db.Close(context.Background())

	srv, err := api.NewServer(cfg, db)
	if err != nil {
		logger.L.Fatalf("failed to create server: %v", err)
	}
	defer srv.Close()

	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
		logger.L.Infow("starting API server", "addr", addr)
		if err := srv.Run(addr); err != nil {
			logger.L.Fatalf("API server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.L.Info("shutting down API server")
}
