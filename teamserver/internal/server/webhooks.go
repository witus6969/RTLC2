package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redteamleaders/rtlc2/teamserver/internal/database"
	log "github.com/sirupsen/logrus"
)

// WebhookConfig holds the configuration for a single webhook.
type WebhookConfig struct {
	ID     string   `json:"id"`
	Type   string   `json:"type"`   // slack, discord, telegram, generic
	Name   string   `json:"name"`
	URL    string   `json:"url"`
	Events []string `json:"events"` // agent_new, agent_dead, task_complete, credential_found
	Active bool     `json:"active"`
}

// WebhookService manages webhook notifications.
type WebhookService struct {
	db       *database.Database
	webhooks []*WebhookConfig
	mu       sync.RWMutex
	client   *http.Client
}

// NewWebhookService creates a webhook service and loads existing webhooks from DB.
func NewWebhookService(db *database.Database) *WebhookService {
	ws := &WebhookService{
		db:       db,
		webhooks: make([]*WebhookConfig, 0),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
	ws.loadFromDB()
	return ws
}

func (ws *WebhookService) loadFromDB() {
	records, err := ws.db.GetWebhooks()
	if err != nil {
		log.Warnf("Failed to load webhooks: %v", err)
		return
	}
	ws.mu.Lock()
	ws.webhooks = make([]*WebhookConfig, 0, len(records))
	for _, r := range records {
		ws.webhooks = append(ws.webhooks, &WebhookConfig{
			ID:     r.ID,
			Name:   r.Name,
			Type:   r.Type,
			URL:    r.URL,
			Events: strings.Split(r.Events, ","),
			Active: r.Active,
		})
	}
	ws.mu.Unlock()
}

// NotifyEvent sends notifications to all matching webhooks for the given event type.
func (ws *WebhookService) NotifyEvent(eventType string, data map[string]interface{}) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()

	for _, wh := range ws.webhooks {
		if !wh.Active {
			continue
		}
		for _, evt := range wh.Events {
			if evt == eventType || evt == "*" {
				go ws.dispatch(wh, eventType, data)
				break
			}
		}
	}
}

func (ws *WebhookService) dispatch(wh *WebhookConfig, eventType string, data map[string]interface{}) {
	var err error
	switch wh.Type {
	case "slack":
		err = ws.notifySlack(wh, eventType, data)
	case "discord":
		err = ws.notifyDiscord(wh, eventType, data)
	case "telegram":
		err = ws.notifyTelegram(wh, eventType, data)
	default:
		err = ws.notifyGeneric(wh, eventType, data)
	}
	if err != nil {
		log.Warnf("Webhook %s (%s) failed: %v", wh.Name, wh.Type, err)
	}
}

func (ws *WebhookService) notifySlack(wh *WebhookConfig, eventType string, data map[string]interface{}) error {
	emoji := ":information_source:"
	switch eventType {
	case "agent_new":
		emoji = ":new:"
	case "agent_dead":
		emoji = ":skull:"
	case "task_complete":
		emoji = ":white_check_mark:"
	case "credential_found":
		emoji = ":key:"
	}

	text := fmt.Sprintf("%s *[RTLC2]* `%s`", emoji, eventType)
	if msg, ok := data["message"].(string); ok {
		text += "\n" + msg
	}
	if aid, ok := data["agent_id"].(string); ok {
		text += fmt.Sprintf("\nAgent: `%s`", aid)
	}

	payload := map[string]interface{}{
		"text": text,
		"blocks": []map[string]interface{}{
			{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": text}},
		},
	}
	return ws.postJSON(wh.URL, payload)
}

func (ws *WebhookService) notifyDiscord(wh *WebhookConfig, eventType string, data map[string]interface{}) error {
	color := 0x808080
	switch eventType {
	case "agent_new":
		color = 0x00CC00
	case "agent_dead":
		color = 0xCC0000
	case "task_complete":
		color = 0x0088CC
	case "credential_found":
		color = 0xCC8800
	}

	desc := eventType
	if msg, ok := data["message"].(string); ok {
		desc = msg
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("RTLC2 — %s", eventType),
				"description": desc,
				"color":       color,
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
				"footer":      map[string]string{"text": "RTLC2 Team Server"},
			},
		},
	}
	return ws.postJSON(wh.URL, payload)
}

func (ws *WebhookService) notifyTelegram(wh *WebhookConfig, eventType string, data map[string]interface{}) error {
	// URL format: https://api.telegram.org/bot<TOKEN>/sendMessage
	// Extract chat_id from webhook URL query or data
	text := fmt.Sprintf("🔔 *RTLC2* — `%s`", eventType)
	if msg, ok := data["message"].(string); ok {
		text += "\n" + msg
	}

	// Expect URL like: https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>
	parts := strings.SplitN(wh.URL, "?chat_id=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("telegram URL must include ?chat_id=<id>")
	}

	payload := map[string]interface{}{
		"chat_id":    parts[1],
		"text":       text,
		"parse_mode": "Markdown",
	}
	return ws.postJSON(parts[0], payload)
}

func (ws *WebhookService) notifyGeneric(wh *WebhookConfig, eventType string, data map[string]interface{}) error {
	payload := map[string]interface{}{
		"event":     eventType,
		"data":      data,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"source":    "rtlc2",
	}
	return ws.postJSON(wh.URL, payload)
}

func (ws *WebhookService) postJSON(url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := ws.client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// ===================== HTTP Handlers =====================

// RegisterWebhookRoutes registers webhook API endpoints.
func RegisterWebhookRoutes(mux *http.ServeMux, ws *WebhookService, authMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/webhooks", authMiddleware(ws.handleWebhooks))
	mux.HandleFunc("/api/v1/webhooks/test", authMiddleware(ws.handleTestWebhook))
	mux.HandleFunc("/api/v1/webhooks/", authMiddleware(ws.handleWebhookByID))
}

func (ws *WebhookService) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ws.mu.RLock()
		hooks := ws.webhooks
		ws.mu.RUnlock()
		if hooks == nil {
			hooks = []*WebhookConfig{}
		}
		jsonResponse(w, map[string]interface{}{"webhooks": hooks})

	case http.MethodPost:
		var req WebhookConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		req.ID = uuid.New().String()[:8]
		if req.Type == "" {
			req.Type = "generic"
		}
		if req.Events == nil {
			req.Events = []string{"*"}
		}
		req.Active = true

		eventsStr := strings.Join(req.Events, ",")
		if err := ws.db.SaveWebhook(req.ID, req.Name, req.Type, req.URL, eventsStr, req.Active); err != nil {
			jsonError(w, "failed to save webhook", http.StatusInternalServerError)
			return
		}

		ws.mu.Lock()
		ws.webhooks = append(ws.webhooks, &req)
		ws.mu.Unlock()

		jsonResponse(w, req)

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ws *WebhookService) handleWebhookByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/webhooks/")
	if r.Method != http.MethodDelete {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ws.db.DeleteWebhook(id); err != nil {
		jsonError(w, "webhook not found", http.StatusNotFound)
		return
	}

	ws.mu.Lock()
	for i, wh := range ws.webhooks {
		if wh.ID == id {
			ws.webhooks = append(ws.webhooks[:i], ws.webhooks[i+1:]...)
			break
		}
	}
	ws.mu.Unlock()

	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

func (ws *WebhookService) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ws.mu.RLock()
	var target *WebhookConfig
	for _, wh := range ws.webhooks {
		if wh.ID == req.ID {
			target = wh
			break
		}
	}
	ws.mu.RUnlock()

	if target == nil {
		jsonError(w, "webhook not found", http.StatusNotFound)
		return
	}

	testData := map[string]interface{}{
		"message":  "This is a test notification from RTLC2 Team Server",
		"agent_id": "test-0000",
	}
	ws.dispatch(target, "test", testData)

	jsonResponse(w, map[string]interface{}{"status": "ok", "message": "test notification sent"})
}
