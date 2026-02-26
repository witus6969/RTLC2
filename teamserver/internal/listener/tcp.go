package listener

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/redteamleaders/rtlc2/teamserver/internal/agent"
	"github.com/redteamleaders/rtlc2/teamserver/internal/crypto"
	log "github.com/sirupsen/logrus"
)

// Frame header size: 4-byte big-endian length prefix.
const frameHeaderSize = 4

// Maximum frame payload size (10 MB).
const maxFrameSize = 10 << 20

// Packet type bytes prepended to the payload after the length header.
const (
	pktTypeRegister byte = 0x01
	pktTypeCheckin  byte = 0x02
)

// TCPListener implements a raw TCP C2 listener with length-prefixed framing.
//
// Wire format:
//
//	[4 bytes: payload length (big-endian)][1 byte: packet type][payload...]
//
// The listener optionally wraps connections in TLS when configured with a
// certificate and key.
type TCPListener struct {
	config       *Config
	agentManager *agent.Manager
	cipher       *crypto.AESCipher

	bindAddr string
	port     int
	useTLS   bool

	listener net.Listener
	running  bool

	// conns tracks active connections for clean shutdown.
	conns map[net.Conn]struct{}
	mu    sync.RWMutex

	// done signals the accept loop to stop.
	done chan struct{}
}

// NewTCPListener creates a new raw TCP C2 listener.
func NewTCPListener(cfg *Config, am *agent.Manager, cipher *crypto.AESCipher) *TCPListener {
	bindAddr := cfg.BindHost
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	port := cfg.BindPort
	if port == 0 {
		port = 4444
	}

	return &TCPListener{
		config:       cfg,
		agentManager: am,
		cipher:       cipher,
		bindAddr:     bindAddr,
		port:         port,
		useTLS:       cfg.TLS,
		conns:        make(map[net.Conn]struct{}),
		done:         make(chan struct{}),
	}
}

func (l *TCPListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("TCP listener %s is already running", l.config.ID)
	}

	addr := fmt.Sprintf("%s:%d", l.bindAddr, l.port)

	var ln net.Listener
	var err error

	if l.useTLS && l.config.CertFile != "" && l.config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(l.config.CertFile, l.config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		ln, err = tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("failed to bind TLS %s: %w", addr, err)
		}
		log.Infof("TCP/TLS listener starting on %s", addr)
	} else {
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to bind TCP %s: %w", addr, err)
		}
		log.Infof("TCP listener starting on %s", addr)
	}

	l.listener = ln
	l.running = true
	l.done = make(chan struct{})

	go l.acceptLoop()

	return nil
}

func (l *TCPListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return fmt.Errorf("TCP listener %s is not running", l.config.ID)
	}

	// Signal the accept loop to stop
	close(l.done)

	// Close the listener socket
	if err := l.listener.Close(); err != nil {
		log.Warnf("Error closing TCP listener: %v", err)
	}

	// Close all active connections
	for conn := range l.conns {
		conn.Close()
	}
	l.conns = make(map[net.Conn]struct{})

	l.running = false
	log.Infof("TCP listener stopped: %s", l.config.ID)
	return nil
}

func (l *TCPListener) ID() string       { return l.config.ID }
func (l *TCPListener) Name() string     { return l.config.Name }
func (l *TCPListener) Protocol() int    { return ProtoTCP }
func (l *TCPListener) Address() string {
	return fmt.Sprintf("%s:%d", l.bindAddr, l.port)
}

// acceptLoop continuously accepts new TCP connections.
func (l *TCPListener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.done:
				// Expected: listener was closed during shutdown
				return
			default:
				log.Warnf("TCP accept error: %v", err)
				continue
			}
		}

		l.mu.Lock()
		l.conns[conn] = struct{}{}
		l.mu.Unlock()

		go l.handleConnection(conn)
	}
}

// handleConnection reads framed messages from a single TCP connection and
// dispatches them to the appropriate handler.
func (l *TCPListener) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		l.mu.Lock()
		delete(l.conns, conn)
		l.mu.Unlock()
	}()

	clientIP := extractTCPClientIP(conn)

	log.WithFields(log.Fields{
		"listener": l.config.ID,
		"remote":   conn.RemoteAddr().String(),
	}).Debug("TCP connection accepted")

	for {
		// Set a generous read deadline; the agent may hold the connection
		// open across multiple check-ins.
		conn.SetReadDeadline(time.Now().Add(120 * time.Second))

		// Read the frame
		payload, err := l.readFrame(conn)
		if err != nil {
			if err != io.EOF {
				log.Debugf("TCP read error from %s: %v", clientIP, err)
			}
			return
		}

		if len(payload) < 1 {
			continue
		}

		// First byte is the packet type
		pktType := payload[0]
		pktData := payload[1:]

		var response []byte
		var handleErr error

		switch pktType {
		case pktTypeRegister:
			response, handleErr = l.handleRegister(pktData, clientIP)
		case pktTypeCheckin:
			response, handleErr = l.handleCheckin(pktData, clientIP)
		default:
			log.Warnf("TCP: unknown packet type 0x%02x from %s", pktType, clientIP)
			continue
		}

		if handleErr != nil {
			log.Warnf("TCP handler error from %s: %v", clientIP, handleErr)
			// Send an empty error frame so the agent knows something went wrong.
			l.writeFrame(conn, []byte{})
			continue
		}

		// Write the response frame
		if err := l.writeFrame(conn, response); err != nil {
			log.Debugf("TCP write error to %s: %v", clientIP, err)
			return
		}
	}
}

// handleRegister processes an agent registration received over TCP.
func (l *TCPListener) handleRegister(encryptedData []byte, clientIP string) ([]byte, error) {
	decrypted, err := l.cipher.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TCP registration from %s: %w", clientIP, err)
	}

	var req agent.RegistrationRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TCP registration: %w", err)
	}

	resp, err := l.agentManager.Register(&req, clientIP, l.config.ID)
	if err != nil {
		return nil, fmt.Errorf("TCP agent registration failed: %w", err)
	}

	log.WithFields(log.Fields{
		"agent_id": resp.AgentID,
		"hostname": req.Hostname,
		"ip":       clientIP,
	}).Info("TCP agent registered")

	respData, _ := json.Marshal(resp)
	encrypted, err := l.cipher.Encrypt(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TCP registration response: %w", err)
	}

	return encrypted, nil
}

// handleCheckin processes an agent check-in received over TCP.
func (l *TCPListener) handleCheckin(data []byte, clientIP string) ([]byte, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("TCP checkin data too short (%d bytes)", len(data))
	}

	agentID := string(data[:8])
	encryptedPayload := data[8:]

	sessionCipher, err := l.agentManager.GetSessionCipher(agentID)
	if err != nil {
		return nil, fmt.Errorf("unknown agent %s in TCP checkin: %w", agentID, err)
	}

	decrypted, err := sessionCipher.Decrypt(encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TCP checkin from %s: %w", agentID, err)
	}

	var req agent.CheckinRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TCP checkin: %w", err)
	}
	req.AgentID = agentID

	resp, err := l.agentManager.Checkin(&req, clientIP)
	if err != nil {
		return nil, fmt.Errorf("TCP agent checkin failed: %w", err)
	}

	respData, _ := json.Marshal(resp)
	encrypted, err := sessionCipher.Encrypt(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt TCP checkin response: %w", err)
	}

	return encrypted, nil
}

// readFrame reads a single length-prefixed frame from the connection.
// Wire format: [4 bytes big-endian length][payload]
func (l *TCPListener) readFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header)
	if length == 0 {
		return []byte{}, nil
	}
	if length > maxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes (max %d)", length, maxFrameSize)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("failed to read frame payload: %w", err)
	}

	return payload, nil
}

// writeFrame writes a single length-prefixed frame to the connection.
func (l *TCPListener) writeFrame(conn net.Conn, data []byte) error {
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	header := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(data)))

	if _, err := conn.Write(header); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := conn.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// extractTCPClientIP extracts the remote IP from a net.Conn.
func extractTCPClientIP(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
