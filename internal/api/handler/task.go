package handler

import (
	"net"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/xiaoyu/distributed-scanner/internal/model"
	"github.com/xiaoyu/distributed-scanner/internal/store"
	"github.com/xiaoyu/distributed-scanner/pkg/config"
	"github.com/xiaoyu/distributed-scanner/pkg/logger"
	"go.mongodb.org/mongo-driver/bson/primitive"
	temporalclient "go.temporal.io/sdk/client"
)

type TaskHandler struct {
	taskStore   *store.TaskStore
	resultStore *store.ResultStore
	temporal    temporalclient.Client
	cfg         *config.Config
}

func NewTaskHandler(ts *store.TaskStore, rs *store.ResultStore, tc temporalclient.Client, cfg *config.Config) *TaskHandler {
	return &TaskHandler{
		taskStore:   ts,
		resultStore: rs,
		temporal:    tc,
		cfg:         cfg,
	}
}

func (h *TaskHandler) Create(c *gin.Context) {
	var task model.ScanTask
	if err := c.ShouldBindJSON(&task); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(task.Targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "targets is required"})
		return
	}

	task.Domains, task.IPs = classifyTargets(task.Targets)

	if err := h.taskStore.Create(c.Request.Context(), &task); err != nil {
		logger.L.Errorw("failed to create task", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create task"})
		return
	}

	workflowOpts := temporalclient.StartWorkflowOptions{
		ID:        "scan-" + task.ID.Hex(),
		TaskQueue: h.cfg.Temporal.TaskQueue,
	}

	we, err := h.temporal.ExecuteWorkflow(c.Request.Context(), workflowOpts, "MasterScanWorkflow", task)
	if err != nil {
		logger.L.Errorw("failed to start workflow", "error", err, "task_id", task.ID.Hex())
		_ = h.taskStore.UpdateStatus(c.Request.Context(), task.ID, model.TaskStatusFailed)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start scan workflow"})
		return
	}

	_ = h.taskStore.Update(c.Request.Context(), task.ID, primitive.M{
		"workflow_id": we.GetID(),
		"run_id":      we.GetRunID(),
		"status":      model.TaskStatusRunning,
	})
	task.WorkflowID = we.GetID()
	task.RunID = we.GetRunID()
	task.Status = model.TaskStatusRunning

	c.JSON(http.StatusCreated, task)
}

func (h *TaskHandler) List(c *gin.Context) {
	page, _ := strconv.ParseInt(c.DefaultQuery("page", "1"), 10, 64)
	pageSize, _ := strconv.ParseInt(c.DefaultQuery("page_size", "20"), 10, 64)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	skip := (page - 1) * pageSize

	tasks, total, err := h.taskStore.List(c.Request.Context(), skip, pageSize)
	if err != nil {
		logger.L.Errorw("failed to list tasks", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list tasks"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      tasks,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func (h *TaskHandler) Get(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	task, err := h.taskStore.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	c.JSON(http.StatusOK, task)
}

func (h *TaskHandler) Pause(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	task, err := h.taskStore.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	if task.Status != model.TaskStatusRunning {
		c.JSON(http.StatusConflict, gin.H{"error": "task is not running"})
		return
	}

	err = h.temporal.SignalWorkflow(c.Request.Context(), task.WorkflowID, task.RunID, "pause", nil)
	if err != nil {
		logger.L.Errorw("failed to send pause signal", "error", err, "task_id", id.Hex())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to pause task"})
		return
	}

	_ = h.taskStore.UpdateStatus(c.Request.Context(), id, model.TaskStatusPaused)
	c.JSON(http.StatusOK, gin.H{"message": "task paused"})
}

func (h *TaskHandler) Resume(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	task, err := h.taskStore.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	if task.Status != model.TaskStatusPaused {
		c.JSON(http.StatusConflict, gin.H{"error": "task is not paused"})
		return
	}

	err = h.temporal.SignalWorkflow(c.Request.Context(), task.WorkflowID, task.RunID, "resume", nil)
	if err != nil {
		logger.L.Errorw("failed to send resume signal", "error", err, "task_id", id.Hex())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resume task"})
		return
	}

	_ = h.taskStore.UpdateStatus(c.Request.Context(), id, model.TaskStatusRunning)
	c.JSON(http.StatusOK, gin.H{"message": "task resumed"})
}

func (h *TaskHandler) Delete(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	task, err := h.taskStore.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	if task.WorkflowID != "" && (task.Status == model.TaskStatusRunning || task.Status == model.TaskStatusPaused) {
		_ = h.temporal.CancelWorkflow(c.Request.Context(), task.WorkflowID, task.RunID)
	}

	_ = h.resultStore.DeleteByTaskID(c.Request.Context(), id)
	if err := h.taskStore.Delete(c.Request.Context(), id); err != nil {
		logger.L.Errorw("failed to delete task", "error", err, "task_id", id.Hex())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete task"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "task deleted"})
}

func classifyTargets(targets []string) (domains, ips []string) {
	for _, t := range targets {
		if _, _, err := net.ParseCIDR(t); err == nil {
			ips = append(ips, t)
		} else if net.ParseIP(t) != nil {
			ips = append(ips, t)
		} else {
			domains = append(domains, t)
		}
	}
	return
}

func (h *TaskHandler) GetResults(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	resultType := c.Query("type")
	page, _ := strconv.ParseInt(c.DefaultQuery("page", "1"), 10, 64)
	pageSize, _ := strconv.ParseInt(c.DefaultQuery("page_size", "50"), 10, 64)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	skip := (page - 1) * pageSize

	results, total, err := h.resultStore.GetByTaskID(c.Request.Context(), id, resultType, skip, pageSize)
	if err != nil {
		logger.L.Errorw("failed to get results", "error", err, "task_id", id.Hex())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get results"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      results,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}
