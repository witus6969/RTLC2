package server

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

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

type TeamServer struct {
	Config          *config.Config
	DB              *database.Database
	Cipher          *crypto.AESCipher
	AgentManager    *agent.Manager
	ListenerManager *listener.Manager
	HTTPServer      *HTTPAPIServer
	WSHub           *WSHub
	ChatService     *ChatService
	WebhookService  *WebhookService
	AutoTaskService *AutoTaskService
	HostedFiles     *HostedFileService
	BlobStore       *storage.BlobStore
}

func New(cfg *config.Config) (*TeamServer, error) {
	// --- Logging: always show on terminal + optional file ---
	level, err := log.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = log.InfoLevel
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		ForceColors:    true,
	})

	// Dual output: stdout + log file
	if cfg.Logging.File != "" {
		os.MkdirAll("data", 0700)
		logFile, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			mw := io.MultiWriter(os.Stdout, logFile)
			log.SetOutput(mw)
		}
	} else {
		log.SetOutput(os.Stdout)
	}

	// --- Database ---
	os.MkdirAll("data", 0700)
	db, err := database.New(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("database init failed: %w", err)
	}

	// --- Crypto keys ---
	if cfg.Crypto.AESKey == "" {
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("key generation failed: %w", err)
		}
		cfg.Crypto.AESKey = key
		log.Info("Generated new AES master key")
	}

	cipher, err := crypto.NewAESCipher(cfg.Crypto.AESKey)
	if err != nil {
		return nil, fmt.Errorf("cipher init failed: %w", err)
	}

	agentMgr := agent.NewManager(db, cipher)
	listenerMgr := listener.NewManager(db, agentMgr, cipher)
	listenerMgr.RestoreListeners()
	tokens := make(map[string]string)

	// WebSocket hub for real-time events
	wsHub := NewWSHub()
	go wsHub.Run()

	// Chat service
	chatSvc := NewChatService(db, wsHub)

	// Webhook, auto-task, and hosted file services
	webhookSvc := NewWebhookService(db)
	autoTaskSvc := NewAutoTaskService(db, agentMgr)
	hostedFiles := NewHostedFileService()

	// Initialize blob storage
	blobStore, err := storage.NewBlobStore("data/blobs")
	if err != nil {
		log.Warnf("BlobStore init failed: %v", err)
	}

	httpSrv := NewHTTPAPIServer(cfg, db, agentMgr, listenerMgr, cipher, tokens)
	httpSrv.SetWSHub(wsHub)
	httpSrv.SetChatService(chatSvc)
	httpSrv.SetWebhookService(webhookSvc)
	httpSrv.SetAutoTaskService(autoTaskSvc)
	httpSrv.SetHostedFileService(hostedFiles)
	httpSrv.SetBlobStore(blobStore)

	ts := &TeamServer{
		Config:          cfg,
		DB:              db,
		Cipher:          cipher,
		AgentManager:    agentMgr,
		ListenerManager: listenerMgr,
		HTTPServer:      httpSrv,
		WSHub:           wsHub,
		ChatService:     chatSvc,
		WebhookService:  webhookSvc,
		AutoTaskService: autoTaskSvc,
		HostedFiles:     hostedFiles,
		BlobStore:       blobStore,
	}

	return ts, nil
}

func (ts *TeamServer) Start() error {
	fmt.Println()
	log.Info("============================================")
	log.Info("  RTLC2 Team Server v0.7.0")
	log.Info("  Red Team Leaders - Command & Control")
	log.Info("============================================")
	fmt.Println()

	// --- Sync operators from config ---
	ts.syncOperatorsFromConfig()

	// --- Show keys ---
	log.Infof("Master AES Key : %s", ts.Config.Crypto.AESKey)
	if ts.Config.Crypto.XORKey != "" {
		log.Infof("XOR Key        : %s", ts.Config.Crypto.XORKey)
	}
	fmt.Println()

	// --- Start HTTP REST API + Web UI ---
	errCh := make(chan error, 1)
	go func() {
		if err := ts.HTTPServer.Start(); err != nil {
			errCh <- fmt.Errorf("HTTP API server: %w", err)
		}
	}()

	// Check if either failed immediately
	select {
	case err := <-errCh:
		return fmt.Errorf("server failed to start: %w", err)
	default:
	}

	log.Infof("HTTP REST API + Web UI listening on %s:%d", ts.Config.Server.Host, ts.Config.Server.Port)
	fmt.Println()
	log.Info("Team server is ready. Waiting for operators and agents...")
	log.Info("Press Ctrl+C to shutdown")
	fmt.Println()

	// --- Event logger ---
	go ts.eventLogger()

	// --- Wait for shutdown ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		fmt.Println()
		log.Info("Received shutdown signal...")
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	ts.Shutdown()
	return nil
}

func (ts *TeamServer) Shutdown() {
	ts.ListenerManager.StopAll()
	ts.HTTPServer.Stop()
	ts.DB.Close()
	log.Info("Team server stopped. Goodbye.")
}

// syncOperatorsFromConfig creates/updates operators defined in the config file.
func (ts *TeamServer) syncOperatorsFromConfig() {
	operators := ts.Config.Operators
	if len(operators) == 0 {
		// No operators in config — create default admin with random password
		ts.createDefaultAdmin()
		return
	}

	for _, op := range operators {
		if op.Username == "" {
			continue
		}

		// Check if operator already exists (simple count query — avoids NULL scan issues)
		if ts.DB.OperatorExists(op.Username) {
			log.Debugf("Operator already exists, skipping: %s", op.Username)
			continue
		}

		// Generate password if not set
		password := op.Password
		if password == "" {
			passBytes, _ := crypto.GenerateNonce(16)
			password = hex.EncodeToString(passBytes)
		}

		role := op.Role
		if role == "" {
			role = "operator"
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Errorf("Failed to hash password for %s: %v", op.Username, err)
			continue
		}

		record := &database.OperatorRecord{
			ID:           uuid.New().String()[:8],
			Username:     op.Username,
			PasswordHash: string(hash),
			Role:         role,
		}

		if err := ts.DB.CreateOperator(record); err != nil {
			log.Errorf("Failed to create operator %s: %v", op.Username, err)
			continue
		}

		if op.Password != "" {
			log.Infof("Operator created: %s (role: %s) - password from config", op.Username, role)
		} else {
			log.Infof("Operator created: %s (role: %s)", op.Username, role)
			log.Infof("  Generated password: %s", password)
		}
	}
}

func (ts *TeamServer) createDefaultAdmin() {
	existing, _ := ts.DB.GetAllOperators()
	if len(existing) > 0 {
		return
	}

	passBytes, _ := crypto.GenerateNonce(16)
	password := hex.EncodeToString(passBytes)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Errorf("Failed to create default admin: %v", err)
		return
	}

	record := &database.OperatorRecord{
		ID:           uuid.New().String()[:8],
		Username:     "admin",
		PasswordHash: string(hash),
		Role:         "admin",
	}

	if err := ts.DB.CreateOperator(record); err != nil {
		log.Errorf("Failed to create default admin: %v", err)
		return
	}

	log.Warn("========================================")
	log.Warnf("  Default admin operator created")
	log.Warnf("  Username : admin")
	log.Warnf("  Password : %s", password)
	log.Warn("  CHANGE THIS PASSWORD!")
	log.Warn("========================================")
}

// AddOperator creates a new operator (called from CLI --add-operator).
func (ts *TeamServer) AddOperator(username, password, role string) error {
	if ts.DB.OperatorExists(username) {
		return fmt.Errorf("operator '%s' already exists", username)
	}

	if role == "" {
		role = "operator"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	record := &database.OperatorRecord{
		ID:           uuid.New().String()[:8],
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
	}

	return ts.DB.CreateOperator(record)
}

// ListOperators prints all operators.
func (ts *TeamServer) ListOperators() error {
	operators, err := ts.DB.GetAllOperators()
	if err != nil {
		return err
	}

	if len(operators) == 0 {
		fmt.Println("No operators found.")
		return nil
	}

	fmt.Printf("\n%-10s %-20s %-12s %s\n", "ID", "USERNAME", "ROLE", "LAST LOGIN")
	fmt.Println("---------- -------------------- ------------ -------------------")
	for _, op := range operators {
		lastLogin := "-"
		if !op.LastLogin.IsZero() {
			lastLogin = op.LastLogin.Format("2006-01-02 15:04")
		}
		fmt.Printf("%-10s %-20s %-12s %s\n", op.ID, op.Username, op.Role, lastLogin)
	}
	fmt.Println()
	return nil
}

func (ts *TeamServer) eventLogger() {
	for event := range ts.AgentManager.Events() {
		log.WithFields(log.Fields{
			"type":  event.Type,
			"agent": event.AgentID,
		}).Info(event.Message)

		// Broadcast to WebSocket clients
		if ts.WSHub != nil {
			wsEventType := ""
			switch event.Type {
			case "agent_registered":
				wsEventType = EventAgentNew
			case "agent_checkin":
				wsEventType = EventAgentCheckin
			case "agent_lost":
				wsEventType = EventAgentDead
			case "task_complete":
				wsEventType = EventTaskComplete
			case "task_queued":
				wsEventType = EventTaskNew
			}
			if wsEventType != "" {
				ts.WSHub.Broadcast(WSEvent{
					Type: wsEventType,
					Data: map[string]string{
						"agent_id": event.AgentID,
						"message":  event.Message,
					},
				})
			}
		}

		// Webhook notifications
		if ts.WebhookService != nil {
			whEventType := ""
			switch event.Type {
			case "agent_registered":
				whEventType = "agent_new"
			case "agent_lost":
				whEventType = "agent_dead"
			case "task_complete":
				whEventType = "task_complete"
			}
			if whEventType != "" {
				ts.WebhookService.NotifyEvent(whEventType, map[string]interface{}{
					"agent_id": event.AgentID,
					"message":  event.Message,
				})
			}
		}

		// Auto-tasks on new agent registration
		if ts.AutoTaskService != nil && event.Type == "agent_registered" {
			if a, err := ts.AgentManager.GetAgent(event.AgentID); err == nil {
				ts.AutoTaskService.OnAgentRegistered(event.AgentID, a.OS, a.Arch)
			}
		}
	}
}
