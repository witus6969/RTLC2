package listener

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/redteamleaders/rtlc2/teamserver/internal/agent"
	"github.com/redteamleaders/rtlc2/teamserver/internal/crypto"
	log "github.com/sirupsen/logrus"
)

// HTTPListener implements an HTTP/HTTPS C2 listener.
type HTTPListener struct {
	config       *Config
	agentManager *agent.Manager
	cipher       *crypto.AESCipher
	server       *http.Server
	mux          *http.ServeMux
}

func NewHTTPListener(cfg *Config, am *agent.Manager, cipher *crypto.AESCipher) *HTTPListener {
	l := &HTTPListener{
		config:       cfg,
		agentManager: am,
		cipher:       cipher,
		mux:          http.NewServeMux(),
	}

	// Register routes based on malleable profile URIs
	profile := cfg.Profile
	if profile == nil {
		profile = DefaultProfile()
	}

	// Registration endpoint (first check-in)
	l.mux.HandleFunc("/register", l.handleRegister)

	// Check-in endpoint (subsequent)
	l.mux.HandleFunc("/checkin", l.handleCheckin)

	// Register profile URIs as aliases (these look like normal web traffic)
	for _, uri := range profile.URIs {
		l.mux.HandleFunc(uri, l.handleCheckin)
	}

	// Default handler returns a decoy page
	l.mux.HandleFunc("/", l.handleDecoy)

	return l
}

func (l *HTTPListener) Start() error {
	addr := fmt.Sprintf("%s:%d", l.config.BindHost, l.config.BindPort)
	l.server = &http.Server{
		Addr:         addr,
		Handler:      l.applyMiddleware(l.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Pre-bind the listener to detect port conflicts immediately
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind %s: %w", addr, err)
	}

	go func() {
		var err error
		if l.config.TLS && l.config.CertFile != "" && l.config.KeyFile != "" {
			log.Infof("HTTPS listener starting on %s", addr)
			err = l.server.ServeTLS(ln, l.config.CertFile, l.config.KeyFile)
		} else {
			log.Infof("HTTP listener starting on %s", addr)
			err = l.server.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			log.Errorf("Listener error: %v", err)
		}
	}()

	return nil
}

func (l *HTTPListener) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return l.server.Shutdown(ctx)
}

func (l *HTTPListener) ID() string       { return l.config.ID }
func (l *HTTPListener) Name() string     { return l.config.Name }
func (l *HTTPListener) Protocol() int    { return l.config.Protocol }
func (l *HTTPListener) Address() string {
	return fmt.Sprintf("%s:%d", l.config.BindHost, l.config.BindPort)
}

// applyMiddleware adds malleable profile headers and logging.
func (l *HTTPListener) applyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply response headers from malleable profile
		if l.config.Profile != nil {
			for k, v := range l.config.Profile.ResponseHeaders {
				w.Header().Set(k, v)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleRegister processes initial agent registration.
func (l *HTTPListener) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		l.handleDecoy(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// Decrypt with master key
	decrypted, err := l.cipher.Decrypt(body)
	if err != nil {
		log.Warnf("Failed to decrypt agent registration from %s (%d bytes): %v", extractIP(r), len(body), err)
		l.handleDecoy(w, r)
		return
	}

	var req agent.RegistrationRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		log.Debugf("Failed to unmarshal registration: %v", err)
		l.handleDecoy(w, r)
		return
	}

	// Get client IP
	clientIP := extractIP(r)

	resp, err := l.agentManager.Register(&req, clientIP, l.config.ID)
	if err != nil {
		log.Errorf("Agent registration failed: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Encrypt response with master key
	respData, _ := json.Marshal(resp)
	encrypted, err := l.cipher.Encrypt(respData)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(encrypted)
}

// handleCheckin processes agent check-ins and returns pending tasks.
func (l *HTTPListener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		l.handleDecoy(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// Try to decode the body transform
	data := body
	if l.config.Profile != nil && l.config.Profile.BodyTransform == "base64" {
		if decoded, err := base64.StdEncoding.DecodeString(string(body)); err == nil {
			data = decoded
		}
	}

	// The first 8 bytes are the agent ID (used to find the session key)
	if len(data) < 9 {
		l.handleDecoy(w, r)
		return
	}

	agentID := string(data[:8])
	encryptedPayload := data[8:]

	// Get session cipher for this agent
	sessionCipher, err := l.agentManager.GetSessionCipher(agentID)
	if err != nil {
		log.Warnf("Unknown agent ID in checkin: %s", agentID)
		l.handleDecoy(w, r)
		return
	}

	// Decrypt with session key
	decrypted, err := sessionCipher.Decrypt(encryptedPayload)
	if err != nil {
		log.Warnf("Failed to decrypt checkin from %s: %v", agentID, err)
		l.handleDecoy(w, r)
		return
	}

	var req agent.CheckinRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		log.Warnf("Failed to unmarshal checkin: %v", err)
		l.handleDecoy(w, r)
		return
	}
	req.AgentID = agentID

	clientIP := extractIP(r)
	resp, err := l.agentManager.Checkin(&req, clientIP)
	if err != nil {
		log.Errorf("Agent checkin failed: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Encrypt response with session key
	respData, _ := json.Marshal(resp)
	encrypted, err := sessionCipher.Encrypt(respData)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	// Apply body transform
	var output []byte
	if l.config.Profile != nil && l.config.Profile.BodyTransform == "base64" {
		output = []byte(base64.StdEncoding.EncodeToString(encrypted))
	} else {
		output = encrypted
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(output)
}

// handleDecoy returns a convincing fake webpage.
func (l *HTTPListener) handleDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body>
<h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>`))
}

func extractIP(r *http.Request) string {
	// Check forwarded headers
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
