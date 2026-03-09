package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type PluginHandler struct{}

func NewPluginHandler() *PluginHandler {
	return &PluginHandler{}
}

func (h *PluginHandler) List(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": []interface{}{}})
}

func (h *PluginHandler) Reload(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "plugins reloaded"})
}
