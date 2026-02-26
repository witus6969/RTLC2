package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redteamleaders/rtlc2/teamserver/internal/database"
	log "github.com/sirupsen/logrus"
)

// ===================== Chat Data Types =====================

// ChatMessage represents a single operator chat message.
type ChatMessage struct {
	ID           string    `json:"id"`
	OperatorID   string    `json:"operator_id"`
	OperatorName string    `json:"operator_name"`
	WorkspaceID  string    `json:"workspace_id"`
	Message      string    `json:"message"`
	Timestamp    time.Time `json:"timestamp"`
}

// ===================== Chat Service =====================

// ChatService manages operator chat messages with database persistence
// and real-time broadcasting via WebSocket.
type ChatService struct {
	db       *database.Database
	rawDB    *sql.DB
	wsHub    *WSHub
	messages []*ChatMessage
	mu       sync.RWMutex
}

// NewChatService creates a new ChatService, initializes the chat_messages
// database table, and loads recent messages into memory.
func NewChatService(db *database.Database, hub *WSHub) *ChatService {
	cs := &ChatService{
		db:       db,
		rawDB:    db.RawDB(),
		wsHub:    hub,
		messages: make([]*ChatMessage, 0),
	}

	// Create the chat_messages table if it does not exist.
	if err := cs.migrateChat(); err != nil {
		log.Errorf("Failed to create chat_messages table: %v", err)
	}

	// Pre-load recent messages into memory for fast access.
	if msgs, err := cs.queryMessages("", 200); err == nil {
		cs.messages = msgs
	}

	return cs
}

// migrateChat creates the chat_messages table in the database.
func (cs *ChatService) migrateChat() error {
	schema := `
	CREATE TABLE IF NOT EXISTS chat_messages (
		id TEXT PRIMARY KEY,
		operator_id TEXT NOT NULL,
		operator_name TEXT NOT NULL,
		workspace_id TEXT NOT NULL DEFAULT 'general',
		message TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_chat_workspace ON chat_messages(workspace_id);
	CREATE INDEX IF NOT EXISTS idx_chat_timestamp ON chat_messages(timestamp);
	`
	_, err := cs.rawDB.Exec(schema)
	return err
}

// SendMessage creates a new chat message, persists it to the database,
// caches it in memory, and broadcasts it to all WebSocket clients.
func (cs *ChatService) SendMessage(operatorID, operatorName, workspaceID, message string) (*ChatMessage, error) {
	if workspaceID == "" {
		workspaceID = "general"
	}

	msg := &ChatMessage{
		ID:           uuid.New().String()[:8],
		OperatorID:   operatorID,
		OperatorName: operatorName,
		WorkspaceID:  workspaceID,
		Message:      message,
		Timestamp:    time.Now(),
	}

	// Persist to database.
	_, err := cs.rawDB.Exec(
		"INSERT INTO chat_messages (id, operator_id, operator_name, workspace_id, message, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
		msg.ID, msg.OperatorID, msg.OperatorName, msg.WorkspaceID, msg.Message, msg.Timestamp,
	)
	if err != nil {
		return nil, err
	}

	// Cache in memory.
	cs.mu.Lock()
	cs.messages = append(cs.messages, msg)
	// Keep only the last 1000 messages in memory.
	if len(cs.messages) > 1000 {
		cs.messages = cs.messages[len(cs.messages)-1000:]
	}
	cs.mu.Unlock()

	// Broadcast via WebSocket.
	if cs.wsHub != nil {
		cs.wsHub.Broadcast(WSEvent{
			Type:      EventChatMessage,
			Data:      msg,
			Timestamp: msg.Timestamp,
		})
	}

	log.Debugf("Chat message from %s in workspace %s: %s", operatorName, workspaceID, message)

	return msg, nil
}

// GetMessages returns the most recent messages for a specific workspace.
// If limit is 0, it defaults to 50.
func (cs *ChatService) GetMessages(workspaceID string, limit int) ([]*ChatMessage, error) {
	if limit <= 0 {
		limit = 50
	}

	// Try memory cache first for recent messages.
	cs.mu.RLock()
	cached := cs.filterCached(workspaceID, limit)
	cs.mu.RUnlock()

	if len(cached) > 0 {
		return cached, nil
	}

	// Fall back to database query.
	return cs.queryMessages(workspaceID, limit)
}

// GetAllMessages returns the most recent messages across all workspaces.
// If limit is 0, it defaults to 50.
func (cs *ChatService) GetAllMessages(limit int) ([]*ChatMessage, error) {
	if limit <= 0 {
		limit = 50
	}

	cs.mu.RLock()
	cached := cs.filterCached("", limit)
	cs.mu.RUnlock()

	if len(cached) > 0 {
		return cached, nil
	}

	return cs.queryMessages("", limit)
}

// filterCached returns messages from the in-memory cache matching the workspace.
// An empty workspaceID matches all messages. Results are ordered oldest to newest.
func (cs *ChatService) filterCached(workspaceID string, limit int) []*ChatMessage {
	var filtered []*ChatMessage
	for _, msg := range cs.messages {
		if workspaceID == "" || msg.WorkspaceID == workspaceID {
			filtered = append(filtered, msg)
		}
	}

	if len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}
	return filtered
}

// queryMessages loads chat messages from the database, optionally filtered by workspace.
func (cs *ChatService) queryMessages(workspaceID string, limit int) ([]*ChatMessage, error) {
	var rows *sql.Rows
	var err error

	if workspaceID != "" {
		rows, err = cs.rawDB.Query(
			"SELECT id, operator_id, operator_name, workspace_id, message, timestamp FROM chat_messages WHERE workspace_id = ? ORDER BY timestamp DESC LIMIT ?",
			workspaceID, limit,
		)
	} else {
		rows, err = cs.rawDB.Query(
			"SELECT id, operator_id, operator_name, workspace_id, message, timestamp FROM chat_messages ORDER BY timestamp DESC LIMIT ?",
			limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*ChatMessage
	for rows.Next() {
		msg := &ChatMessage{}
		if err := rows.Scan(&msg.ID, &msg.OperatorID, &msg.OperatorName, &msg.WorkspaceID, &msg.Message, &msg.Timestamp); err != nil {
			continue
		}
		messages = append(messages, msg)
	}

	// Reverse to get oldest-first ordering (query returns newest-first).
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, nil
}

// ===================== HTTP Handlers =====================

// RegisterChatRoutes registers the chat API endpoints on the provided ServeMux.
// The authMiddleware wraps handlers to require authentication.
func RegisterChatRoutes(mux *http.ServeMux, cs *ChatService, authMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/chat", authMiddleware(cs.handleChat))
	mux.HandleFunc("/api/v1/chat/messages", authMiddleware(cs.handleChatMessages))
}

// handleChat dispatches chat requests based on HTTP method.
func (cs *ChatService) handleChat(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		cs.handleSendMessage(w, r)
	case http.MethodGet:
		cs.handleGetMessages(w, r)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleChatMessages handles GET requests for chat message retrieval with filters.
func (cs *ChatService) handleChatMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cs.handleGetMessages(w, r)
}

// handleSendMessage processes POST /api/v1/chat to send a new message.
func (cs *ChatService) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OperatorID   string `json:"operator_id"`
		OperatorName string `json:"operator_name"`
		WorkspaceID  string `json:"workspace_id"`
		Message      string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		jsonError(w, "message cannot be empty", http.StatusBadRequest)
		return
	}
	if req.OperatorID == "" || req.OperatorName == "" {
		jsonError(w, "operator_id and operator_name are required", http.StatusBadRequest)
		return
	}

	msg, err := cs.SendMessage(req.OperatorID, req.OperatorName, req.WorkspaceID, req.Message)
	if err != nil {
		jsonError(w, "failed to send message: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"message": msg,
	})
}

// handleGetMessages processes GET /api/v1/chat?workspace_id=&limit= to retrieve messages.
func (cs *ChatService) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	workspaceID := r.URL.Query().Get("workspace_id")
	limitStr := r.URL.Query().Get("limit")

	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	var messages []*ChatMessage
	var err error

	if workspaceID != "" {
		messages, err = cs.GetMessages(workspaceID, limit)
	} else {
		messages, err = cs.GetAllMessages(limit)
	}

	if err != nil {
		jsonError(w, "failed to get messages: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if messages == nil {
		messages = []*ChatMessage{}
	}

	jsonResponse(w, map[string]interface{}{
		"messages": messages,
	})
}
