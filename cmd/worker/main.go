package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiaoyu/distributed-scanner/internal/store"
	"github.com/xiaoyu/distributed-scanner/internal/workflow"
	"github.com/xiaoyu/distributed-scanner/pkg/config"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
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

	tc, err := client.Dial(client.Options{
		HostPort:  cfg.Temporal.Host,
		Namespace: cfg.Temporal.Namespace,
	})
	if err != nil {
		logger.L.Fatalf("failed to connect to Temporal: %v", err)
	}
	defer tc.Close()

	w := worker.New(tc, cfg.Temporal.TaskQueue, worker.Options{})

	workflow.Register(w, cfg, db)

	logger.L.Infow("starting Temporal worker", "taskQueue", cfg.Temporal.TaskQueue)
	if err := w.Start(); err != nil {
		logger.L.Fatalf("worker start error: %v", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.L.Info("shutting down worker")
	w.Stop()
}
