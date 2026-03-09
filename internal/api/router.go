package api

import (
	"github.com/gin-gonic/gin"
	"github.com/xiaoyu/distributed-scanner/internal/api/handler"
	"github.com/xiaoyu/distributed-scanner/internal/store"
)

func (s *Server) setupRoutes() {
	taskStore := store.NewTaskStore(s.db)
	resultStore := store.NewResultStore(s.db)
	providerStore := store.NewProviderStore(s.db)
	dictStore := store.NewDictionaryStore(s.db)

	taskH := handler.NewTaskHandler(taskStore, resultStore, s.temporal, s.cfg)
	providerH := handler.NewProviderHandler(providerStore)
	dictH := handler.NewDictionaryHandler(dictStore)
	pluginH := handler.NewPluginHandler()

	v1 := s.engine.Group("/api/v1")
	{
		v1.GET("/health", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		tasks := v1.Group("/tasks")
		{
			tasks.POST("", taskH.Create)
			tasks.GET("", taskH.List)
			tasks.GET("/:id", taskH.Get)
			tasks.PUT("/:id/pause", taskH.Pause)
			tasks.PUT("/:id/resume", taskH.Resume)
			tasks.DELETE("/:id", taskH.Delete)
			tasks.GET("/:id/results", taskH.GetResults)
		}

		providers := v1.Group("/providers")
		{
			providers.GET("", providerH.List)
			providers.PUT("/:name", providerH.Upsert)
			providers.DELETE("/:name", providerH.Delete)
			providers.POST("/test", providerH.Test)
		}

		dictionaries := v1.Group("/dictionaries")
		{
			dictionaries.GET("", dictH.List)
			dictionaries.POST("", dictH.Upload)
			dictionaries.GET("/:id", dictH.Get)
			dictionaries.DELETE("/:id", dictH.Delete)
			dictionaries.GET("/:id/preview", dictH.Preview)
		}

		plugins := v1.Group("/plugins")
		{
			plugins.GET("", pluginH.List)
			plugins.POST("/reload", pluginH.Reload)
		}
	}
}
