package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redteamleaders/rtlc2/teamserver/internal/database"
)

// ===================== Campaigns =====================

// handleCampaigns handles GET (list) and POST (create) for /api/v1/campaigns.
func (h *HTTPAPIServer) handleCampaigns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listCampaigns(w)
	case http.MethodPost:
		h.createCampaign(w, r)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) listCampaigns(w http.ResponseWriter) {
	campaigns, err := h.db.GetCampaigns()
	if err != nil {
		jsonError(w, "failed to get campaigns", http.StatusInternalServerError)
		return
	}

	var result []map[string]interface{}
	for _, c := range campaigns {
		count, _ := h.db.GetCampaignAgentCount(c.ID)
		result = append(result, map[string]interface{}{
			"id":          c.ID,
			"name":        c.Name,
			"description": c.Description,
			"status":      c.Status,
			"agent_count": count,
			"created_at":  c.CreatedAt.Format("2006-01-02 15:04:05"),
			"updated_at":  c.UpdatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"campaigns": result})
}

func (h *HTTPAPIServer) createCampaign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}

	now := time.Now()
	record := &database.CampaignRecord{
		ID:          uuid.New().String()[:8],
		Name:        req.Name,
		Description: req.Description,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := h.db.CreateCampaign(record); err != nil {
		jsonError(w, fmt.Sprintf("failed to create campaign: %v", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"id":          record.ID,
		"name":        record.Name,
		"description": record.Description,
		"status":      record.Status,
		"agent_count": 0,
		"created_at":  record.CreatedAt.Format("2006-01-02 15:04:05"),
		"updated_at":  record.UpdatedAt.Format("2006-01-02 15:04:05"),
	})
}

// handleCampaignByID handles routes under /api/v1/campaigns/{id}
func (h *HTTPAPIServer) handleCampaignByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/campaigns/")
	parts := strings.SplitN(path, "/", 2)
	campaignID := parts[0]

	if campaignID == "" {
		jsonError(w, "campaign ID required", http.StatusBadRequest)
		return
	}

	// Handle sub-routes: /api/v1/campaigns/{id}/agents
	if len(parts) == 2 && parts[1] == "agents" {
		h.handleCampaignAgents(w, r, campaignID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getCampaign(w, campaignID)
	case http.MethodPut:
		h.updateCampaign(w, r, campaignID)
	case http.MethodDelete:
		h.deleteCampaign(w, campaignID)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) getCampaign(w http.ResponseWriter, id string) {
	c, err := h.db.GetCampaignByID(id)
	if err != nil {
		jsonError(w, "campaign not found", http.StatusNotFound)
		return
	}

	agents, _ := h.db.GetCampaignAgents(id)
	if agents == nil {
		agents = []string{}
	}

	jsonResponse(w, map[string]interface{}{
		"id":          c.ID,
		"name":        c.Name,
		"description": c.Description,
		"status":      c.Status,
		"agents":      agents,
		"created_at":  c.CreatedAt.Format("2006-01-02 15:04:05"),
		"updated_at":  c.UpdatedAt.Format("2006-01-02 15:04:05"),
	})
}

func (h *HTTPAPIServer) updateCampaign(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Status      string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate status if provided
	if req.Status != "" {
		validStatuses := map[string]bool{"active": true, "completed": true, "archived": true}
		if !validStatuses[req.Status] {
			jsonError(w, "invalid status: must be active, completed, or archived", http.StatusBadRequest)
			return
		}
	}

	// Get existing campaign to fill defaults
	existing, err := h.db.GetCampaignByID(id)
	if err != nil {
		jsonError(w, "campaign not found", http.StatusNotFound)
		return
	}

	name := existing.Name
	desc := existing.Description
	status := existing.Status
	if req.Name != "" {
		name = req.Name
	}
	if req.Description != "" {
		desc = req.Description
	}
	if req.Status != "" {
		status = req.Status
	}

	if err := h.db.UpdateCampaign(id, name, desc, status); err != nil {
		jsonError(w, fmt.Sprintf("failed to update campaign: %v", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{"status": "ok", "id": id})
}

func (h *HTTPAPIServer) deleteCampaign(w http.ResponseWriter, id string) {
	if err := h.db.DeleteCampaign(id); err != nil {
		jsonError(w, fmt.Sprintf("failed to delete campaign: %v", err), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

// handleCampaignAgents handles POST (add) and DELETE (remove) agents from a campaign.
func (h *HTTPAPIServer) handleCampaignAgents(w http.ResponseWriter, r *http.Request, campaignID string) {
	switch r.Method {
	case http.MethodGet:
		agents, err := h.db.GetCampaignAgents(campaignID)
		if err != nil {
			jsonError(w, "failed to get campaign agents", http.StatusInternalServerError)
			return
		}
		if agents == nil {
			agents = []string{}
		}
		jsonResponse(w, map[string]interface{}{"agents": agents})

	case http.MethodPost:
		var req struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			jsonError(w, "agent_id is required", http.StatusBadRequest)
			return
		}
		if err := h.db.AddAgentToCampaign(campaignID, req.AgentID); err != nil {
			jsonError(w, "failed to add agent to campaign", http.StatusInternalServerError)
			return
		}
		jsonResponse(w, map[string]interface{}{"status": "ok"})

	case http.MethodDelete:
		var req struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			jsonError(w, "agent_id is required", http.StatusBadRequest)
			return
		}
		if err := h.db.RemoveAgentFromCampaign(campaignID, req.AgentID); err != nil {
			jsonError(w, "failed to remove agent from campaign", http.StatusInternalServerError)
			return
		}
		jsonResponse(w, map[string]interface{}{"status": "ok"})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
