package listener

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/redteamleaders/rtlc2/teamserver/internal/agent"
	"github.com/redteamleaders/rtlc2/teamserver/internal/crypto"
	"github.com/redteamleaders/rtlc2/teamserver/internal/database"
	log "github.com/sirupsen/logrus"
)

// Protocol types
const (
	ProtoHTTP  = 0
	ProtoHTTPS = 1
	ProtoTCP   = 2
	ProtoSMB   = 3
	ProtoDNS   = 4
)

// Listener is the interface all listener types must implement.
type Listener interface {
	Start() error
	Stop() error
	ID() string
	Name() string
	Protocol() int
	Address() string
}

// Config holds listener configuration.
type Config struct {
	ID       string
	Name     string
	Protocol int
	BindHost string
	BindPort int
	TLS      bool
	CertFile string
	KeyFile  string
	Options  map[string]string
	Profile  *MalleableProfile
}

// MalleableProfile defines traffic shaping options.
type MalleableProfile struct {
	Name            string            `json:"name"`
	UserAgent       string            `json:"user_agent"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	URIs            []string          `json:"uris"`
	BodyTransform   string            `json:"body_transform"` // base64, xor, prepend, append, custom
}

// DefaultProfile returns a default malleable profile.
func DefaultProfile() *MalleableProfile {
	return &MalleableProfile{
		Name:      "default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		RequestHeaders: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate",
		},
		ResponseHeaders: map[string]string{
			"Content-Type":           "text/html; charset=utf-8",
			"Server":                 "Microsoft-IIS/10.0",
			"X-Powered-By":          "ASP.NET",
			"Cache-Control":         "no-cache",
		},
		URIs: []string{
			"/api/v1/status",
			"/content/update",
			"/assets/js/main.js",
			"/portal/login",
			"/feed/rss",
		},
		BodyTransform: "base64",
	}
}

// Manager manages all active listeners.
type Manager struct {
	db           *database.Database
	agentManager *agent.Manager
	cipher       *crypto.AESCipher
	listeners    map[string]Listener
	mu           sync.RWMutex
}

func NewManager(db *database.Database, agentManager *agent.Manager, cipher *crypto.AESCipher) *Manager {
	return &Manager{
		db:           db,
		agentManager: agentManager,
		cipher:       cipher,
		listeners:    make(map[string]Listener),
	}
}

// Create creates and starts a new listener.
func (m *Manager) Create(cfg *Config) (Listener, error) {
	if cfg.ID == "" {
		cfg.ID = uuid.New().String()[:8]
	}
	if cfg.Profile == nil {
		cfg.Profile = DefaultProfile()
	}

	var l Listener
	switch cfg.Protocol {
	case ProtoHTTP, ProtoHTTPS:
		l = NewHTTPListener(cfg, m.agentManager, m.cipher)
	case ProtoTCP:
		l = NewTCPListener(cfg, m.agentManager, m.cipher)
	case ProtoSMB:
		l = NewSMBListener(cfg, m.agentManager, m.cipher)
	case ProtoDNS:
		l = NewDNSListener(cfg, m.agentManager, m.cipher)
	default:
		return nil, fmt.Errorf("unsupported protocol: %d", cfg.Protocol)
	}

	if err := l.Start(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.listeners[cfg.ID] = l
	m.mu.Unlock()

	// Save to database
	record := &database.ListenerRecord{
		ID:       cfg.ID,
		Name:     cfg.Name,
		Protocol: cfg.Protocol,
		BindHost: cfg.BindHost,
		BindPort: cfg.BindPort,
		Active:   true,
	}
	if err := m.db.CreateListener(record); err != nil {
		log.Warnf("Failed to save listener to database: %v", err)
	}

	log.WithFields(log.Fields{
		"id":       cfg.ID,
		"name":     cfg.Name,
		"protocol": cfg.Protocol,
		"address":  l.Address(),
	}).Info("Listener started")

	return l, nil
}

// Stop stops a listener by ID.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	l, exists := m.listeners[id]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("listener not found: %s", id)
	}
	delete(m.listeners, id)
	m.mu.Unlock()

	if err := l.Stop(); err != nil {
		return err
	}

	_ = m.db.StopListener(id)
	log.Infof("Listener stopped: %s", id)
	return nil
}

// Get returns a listener by ID.
func (m *Manager) Get(id string) (Listener, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.listeners[id]
	return l, ok
}

// GetAll returns all active listeners.
func (m *Manager) GetAll() []Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Listener, 0, len(m.listeners))
	for _, l := range m.listeners {
		result = append(result, l)
	}
	return result
}

// StopAll stops all listeners.
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, l := range m.listeners {
		if err := l.Stop(); err != nil {
			log.Warnf("Failed to stop listener %s: %v", id, err)
		}
		_ = m.db.StopListener(id)
	}
	m.listeners = make(map[string]Listener)
}

// RestoreListeners restores previously active listeners from the database.
// This should be called after the manager is created to resume listeners on restart.
func (m *Manager) RestoreListeners() {
	records, err := m.db.GetAllListeners()
	if err != nil {
		log.Warnf("Failed to load listeners from database: %v", err)
		return
	}

	for _, r := range records {
		if !r.Active {
			continue
		}

		// Check if already running (shouldn't be on fresh start, but be safe)
		if _, exists := m.Get(r.ID); exists {
			continue
		}

		cfg := &Config{
			ID:       r.ID,
			Name:     r.Name,
			Protocol: r.Protocol,
			BindHost: r.BindHost,
			BindPort: r.BindPort,
		}

		if cfg.Profile == nil {
			cfg.Profile = DefaultProfile()
		}

		var l Listener
		switch cfg.Protocol {
		case ProtoHTTP, ProtoHTTPS:
			l = NewHTTPListener(cfg, m.agentManager, m.cipher)
		case ProtoTCP:
			l = NewTCPListener(cfg, m.agentManager, m.cipher)
		case ProtoSMB:
			l = NewSMBListener(cfg, m.agentManager, m.cipher)
		case ProtoDNS:
			l = NewDNSListener(cfg, m.agentManager, m.cipher)
		default:
			log.Warnf("Failed to restore listener %s: unsupported protocol %d", r.Name, r.Protocol)
			continue
		}

		if err := l.Start(); err != nil {
			log.Warnf("Failed to restore listener %s: %v", r.Name, err)
			continue
		}

		m.mu.Lock()
		m.listeners[cfg.ID] = l
		m.mu.Unlock()

		log.Infof("Restored listener: %s (%d on %s:%d)", r.Name, r.Protocol, r.BindHost, r.BindPort)
	}
}
