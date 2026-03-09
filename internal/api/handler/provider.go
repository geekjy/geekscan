package handler

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/internal/store"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
)

type ProviderHandler struct {
	providerStore *store.ProviderStore
}

func NewProviderHandler(ps *store.ProviderStore) *ProviderHandler {
	return &ProviderHandler{providerStore: ps}
}

func maskKey(key string) string {
	if len(key) <= 4 {
		return key
	}
	return key[:4] + "****"
}

func (h *ProviderHandler) List(c *gin.Context) {
	configs, err := h.providerStore.List(c.Request.Context())
	if err != nil {
		logger.L.Errorw("failed to list providers", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list providers"})
		return
	}

	type providerView struct {
		Provider  string `json:"provider"`
		APIKey    string `json:"api_key"`
		APISecret string `json:"api_secret"`
		Enabled   bool   `json:"enabled"`
	}

	configured := make(map[string]providerView)
	for _, cfg := range configs {
		configured[cfg.Provider] = providerView{
			Provider:  cfg.Provider,
			APIKey:    maskKey(cfg.APIKey),
			APISecret: maskKey(cfg.APISecret),
			Enabled:   cfg.Enabled,
		}
	}

	type providerStatus struct {
		Provider   string `json:"provider"`
		Configured bool   `json:"configured"`
		APIKey     string `json:"api_key,omitempty"`
		APISecret  string `json:"api_secret,omitempty"`
		Enabled    bool   `json:"enabled"`
	}

	var result []providerStatus
	for _, name := range model.SupportedProviders {
		ps := providerStatus{Provider: name}
		if v, ok := configured[name]; ok {
			ps.Configured = true
			ps.APIKey = v.APIKey
			ps.APISecret = v.APISecret
			ps.Enabled = v.Enabled
		}
		result = append(result, ps)
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}

func (h *ProviderHandler) Upsert(c *gin.Context) {
	name := c.Param("name")

	valid := false
	for _, p := range model.SupportedProviders {
		if p == name {
			valid = true
			break
		}
	}
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported provider: %s", name)})
		return
	}

	var req struct {
		APIKey    string `json:"api_key"`
		APISecret string `json:"api_secret"`
		Enabled   *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg := &model.ProviderConfig{
		Provider:  name,
		APIKey:    req.APIKey,
		APISecret: req.APISecret,
		Enabled:   true,
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}

	if err := h.providerStore.Upsert(c.Request.Context(), cfg); err != nil {
		logger.L.Errorw("failed to upsert provider", "error", err, "provider", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save provider config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "provider config saved"})
}

func (h *ProviderHandler) Delete(c *gin.Context) {
	name := c.Param("name")
	if err := h.providerStore.Delete(c.Request.Context(), name); err != nil {
		logger.L.Errorw("failed to delete provider", "error", err, "provider", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete provider config"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "provider config deleted"})
}

func (h *ProviderHandler) Test(c *gin.Context) {
	var req struct {
		Provider string `json:"provider" binding:"required"`
		APIKey   string `json:"api_key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	testURLs := map[string]string{
		"shodan":         "https://api.shodan.io/api-info?key=%s",
		"censys":         "https://search.censys.io/api/v1/account",
		"virustotal":     "https://www.virustotal.com/api/v3/users/me",
		"securitytrails": "https://api.securitytrails.com/v1/ping?apikey=%s",
		"fofa":           "https://fofa.info/api/v1/info/my?key=%s",
		"hunter":         "https://hunter.qianxin.com/openApi/search?api-key=%s&search=a&page=1&page_size=1",
		"quake":          "https://quake.360.net/api/v3/user/info",
		"zoomeye":        "https://api.zoomeye.org/resources-info",
	}

	url, ok := testURLs[req.Provider]
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"provider": req.Provider,
			"valid":    false,
			"message":  "no test endpoint available for this provider",
		})
		return
	}

	testURL := fmt.Sprintf(url, req.APIKey)
	client := &http.Client{Timeout: 10 * time.Second}
	httpReq, _ := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, testURL, nil)

	switch req.Provider {
	case "virustotal":
		httpReq.Header.Set("x-apikey", req.APIKey)
	case "quake":
		httpReq.Header.Set("X-QuakeToken", req.APIKey)
	case "zoomeye":
		httpReq.Header.Set("API-KEY", req.APIKey)
	case "censys":
		httpReq.SetBasicAuth(req.APIKey, "")
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"provider": req.Provider,
			"valid":    false,
			"message":  fmt.Sprintf("request failed: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	valid := resp.StatusCode >= 200 && resp.StatusCode < 300
	c.JSON(http.StatusOK, gin.H{
		"provider":    req.Provider,
		"valid":       valid,
		"status_code": resp.StatusCode,
	})
}
