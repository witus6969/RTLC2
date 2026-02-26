package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/redteamleaders/rtlc2/teamserver/internal/agent"
	"github.com/redteamleaders/rtlc2/teamserver/internal/database"
	log "github.com/sirupsen/logrus"
)

// AutoTaskRule defines a task that is automatically queued when a new agent registers.
type AutoTaskRule struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	TaskType   int               `json:"task_type"`
	Data       string            `json:"data"`        // base64
	Params     map[string]string `json:"params"`
	OSFilter   string            `json:"os_filter"`   // windows, linux, macos, or empty for all
	ArchFilter string            `json:"arch_filter"` // x64, x86, arm64, or empty for all
	Active     bool              `json:"active"`
}

// AutoTaskService manages automatic task rules for new agents.
type AutoTaskService struct {
	db    *database.Database
	am    *agent.Manager
	rules []*AutoTaskRule
	mu    sync.RWMutex
}

// NewAutoTaskService creates an auto-task service and loads rules from the DB.
func NewAutoTaskService(db *database.Database, am *agent.Manager) *AutoTaskService {
	ats := &AutoTaskService{
		db:    db,
		am:    am,
		rules: make([]*AutoTaskRule, 0),
	}
	ats.loadFromDB()
	return ats
}

func (ats *AutoTaskService) loadFromDB() {
	records, err := ats.db.GetAutoTasks()
	if err != nil {
		log.Warnf("Failed to load auto-tasks: %v", err)
		return
	}
	ats.mu.Lock()
	ats.rules = make([]*AutoTaskRule, 0, len(records))
	for _, r := range records {
		var params map[string]string
		_ = json.Unmarshal([]byte(r.Params), &params)
		if params == nil {
			params = make(map[string]string)
		}
		ats.rules = append(ats.rules, &AutoTaskRule{
			ID: r.ID, Name: r.Name, TaskType: r.TaskType,
			Data: r.Data, Params: params,
			OSFilter: r.OSFilter, ArchFilter: r.ArchFilter, Active: r.Active,
		})
	}
	ats.mu.Unlock()
}

// OnAgentRegistered queues matching auto-tasks for a newly registered agent.
func (ats *AutoTaskService) OnAgentRegistered(agentID, osType, arch string) {
	ats.mu.RLock()
	defer ats.mu.RUnlock()

	osLower := strings.ToLower(osType)
	archLower := strings.ToLower(arch)

	for _, rule := range ats.rules {
		if !rule.Active {
			continue
		}
		// Check OS filter
		if rule.OSFilter != "" && !strings.Contains(osLower, strings.ToLower(rule.OSFilter)) {
			continue
		}
		// Check arch filter
		if rule.ArchFilter != "" && !strings.EqualFold(rule.ArchFilter, archLower) {
			continue
		}

		// Decode base64 data
		data := []byte(rule.Data)
		params := rule.Params
		if params == nil {
			params = make(map[string]string)
		}

		_, err := ats.am.QueueTask(agentID, rule.TaskType, data, params)
		if err != nil {
			log.Warnf("Auto-task %s failed for agent %s: %v", rule.Name, agentID, err)
		} else {
			log.Infof("Auto-task '%s' queued for agent %s", rule.Name, agentID)
		}
	}
}

// ===================== HTTP Handlers =====================

// RegisterAutoTaskRoutes registers auto-task API endpoints.
func RegisterAutoTaskRoutes(mux *http.ServeMux, ats *AutoTaskService, authMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/autotasks", authMiddleware(ats.handleAutoTasks))
	mux.HandleFunc("/api/v1/autotasks/", authMiddleware(ats.handleAutoTaskByID))
}

func (ats *AutoTaskService) handleAutoTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ats.mu.RLock()
		rules := ats.rules
		ats.mu.RUnlock()
		if rules == nil {
			rules = []*AutoTaskRule{}
		}
		jsonResponse(w, map[string]interface{}{"auto_tasks": rules})

	case http.MethodPost:
		var req AutoTaskRule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req.ID = uuid.New().String()[:8]
		req.Active = true
		if req.Params == nil {
			req.Params = make(map[string]string)
		}

		paramsJSON, _ := json.Marshal(req.Params)
		if err := ats.db.SaveAutoTask(req.ID, req.Name, req.TaskType, req.Data, string(paramsJSON), req.OSFilter, req.ArchFilter, req.Active); err != nil {
			jsonError(w, "failed to save auto-task", http.StatusInternalServerError)
			return
		}

		ats.mu.Lock()
		ats.rules = append(ats.rules, &req)
		ats.mu.Unlock()

		jsonResponse(w, req)

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ats *AutoTaskService) handleAutoTaskByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/autotasks/")

	switch r.Method {
	case http.MethodPut:
		var req struct {
			Active *bool `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		ats.mu.Lock()
		for _, rule := range ats.rules {
			if rule.ID == id && req.Active != nil {
				rule.Active = *req.Active
				_ = ats.db.UpdateAutoTaskActive(id, *req.Active)
			}
		}
		ats.mu.Unlock()

		jsonResponse(w, map[string]interface{}{"status": "ok"})

	case http.MethodDelete:
		if err := ats.db.DeleteAutoTask(id); err != nil {
			jsonError(w, "auto-task not found", http.StatusNotFound)
			return
		}

		ats.mu.Lock()
		for i, rule := range ats.rules {
			if rule.ID == id {
				ats.rules = append(ats.rules[:i], ats.rules[i+1:]...)
				break
			}
		}
		ats.mu.Unlock()

		jsonResponse(w, map[string]interface{}{"status": "ok"})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
