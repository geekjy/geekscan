package handler

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/internal/store"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type DictionaryHandler struct {
	dictStore *store.DictionaryStore
}

func NewDictionaryHandler(ds *store.DictionaryStore) *DictionaryHandler {
	return &DictionaryHandler{dictStore: ds}
}

func (h *DictionaryHandler) List(c *gin.Context) {
	dicts, err := h.dictStore.List(c.Request.Context())
	if err != nil {
		logger.L.Errorw("failed to list dictionaries", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list dictionaries"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": dicts})
}

func (h *DictionaryHandler) Upload(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
		return
	}

	lineCount := 0
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			lineCount++
		}
	}

	name := c.PostForm("name")
	if name == "" {
		name = header.Filename
	}

	dict := &model.Dictionary{
		Name:        name,
		Description: c.PostForm("description"),
		Type:        c.DefaultPostForm("type", "custom"),
		LineCount:   lineCount,
		IsBuiltin:   false,
	}

	if err := h.dictStore.Create(c.Request.Context(), dict, content); err != nil {
		logger.L.Errorw("failed to create dictionary", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save dictionary"})
		return
	}

	c.JSON(http.StatusCreated, dict)
}

func (h *DictionaryHandler) Get(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dictionary id"})
		return
	}

	dict, err := h.dictStore.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dictionary not found"})
		return
	}

	c.JSON(http.StatusOK, dict)
}

func (h *DictionaryHandler) Delete(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dictionary id"})
		return
	}

	dict, err := h.dictStore.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dictionary not found"})
		return
	}

	if dict.IsBuiltin {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete builtin dictionary"})
		return
	}

	if err := h.dictStore.Delete(c.Request.Context(), id); err != nil {
		logger.L.Errorw("failed to delete dictionary", "error", err, "id", id.Hex())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete dictionary"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "dictionary deleted"})
}

func (h *DictionaryHandler) Preview(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dictionary id"})
		return
	}

	dict, err := h.dictStore.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dictionary not found"})
		return
	}

	content, err := h.dictStore.GetContent(c.Request.Context(), dict.FileID)
	if err != nil {
		logger.L.Errorw("failed to get dictionary content", "error", err, "id", id.Hex())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read dictionary content"})
		return
	}

	const maxLines = 100
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() && len(lines) < maxLines {
		lines = append(lines, scanner.Text())
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         dict.ID,
		"name":       dict.Name,
		"total_lines": dict.LineCount,
		"preview":    lines,
	})
}
