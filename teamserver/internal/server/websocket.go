package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// ===================== Event Types =====================

const (
	EventAgentNew        = "agent_new"
	EventAgentDead       = "agent_dead"
	EventAgentCheckin    = "agent_checkin"
	EventTaskComplete    = "task_complete"
	EventTaskNew         = "task_new"
	EventListenerNew     = "listener_new"
	EventListenerStopped = "listener_stopped"
	EventOperatorJoin    = "operator_join"
	EventOperatorLeave   = "operator_leave"
	EventChatMessage     = "chat_message"
)

// WSEvent represents a real-time event broadcast to all connected WebSocket clients.
type WSEvent struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// ===================== WebSocket Client =====================

const (
	// Time allowed to write a message to the peer.
	wsWriteWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	wsPongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	wsPingPeriod = (wsPongWait * 9) / 10

	// Maximum message size allowed from peer.
	wsMaxMessageSize = 4096

	// Send channel buffer size per client.
	wsSendBufferSize = 256
)

// WSClient represents a single WebSocket connection from an operator.
type WSClient struct {
	hub  *WSHub
	conn *websocket.Conn
	send chan []byte

	// OperatorID is set after authentication on the WebSocket.
	OperatorID string
	Username   string
}

// ReadPump pumps messages from the WebSocket connection to the hub.
// It reads incoming messages (e.g. pings, subscription commands) and handles
// connection lifecycle. Each client runs ReadPump in its own goroutine.
func (c *WSClient) ReadPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(wsMaxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(wsPongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Warnf("WebSocket read error (client %s): %v", c.OperatorID, err)
			}
			break
		}

		// Handle incoming client messages (e.g. auth, subscribe to specific events).
		c.handleMessage(message)
	}
}

// handleMessage processes an incoming message from a WebSocket client.
// Currently supports an "auth" message type for setting the operator identity.
func (c *WSClient) handleMessage(data []byte) {
	var msg struct {
		Type       string `json:"type"`
		OperatorID string `json:"operator_id,omitempty"`
		Username   string `json:"username,omitempty"`
	}
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}

	switch msg.Type {
	case "auth":
		c.OperatorID = msg.OperatorID
		c.Username = msg.Username
		log.Debugf("WebSocket client authenticated: %s (%s)", msg.Username, msg.OperatorID)

		// Broadcast operator_join event to all clients
		c.hub.Broadcast(WSEvent{
			Type: EventOperatorJoin,
			Data: map[string]string{
				"operator_id": msg.OperatorID,
				"username":    msg.Username,
			},
			Timestamp: time.Now(),
		})
	}
}

// WritePump pumps messages from the hub to the WebSocket connection.
// A goroutine running WritePump is started for each connection. The hub
// sends messages on the client's send channel. WritePump also sends
// periodic ping messages to detect dead connections.
func (c *WSClient) WritePump() {
	ticker := time.NewTicker(wsPingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Drain queued messages into the current write buffer to reduce
			// the number of write syscalls.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte("\n"))
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ===================== WebSocket Hub =====================

// WSHub maintains the set of active WebSocket clients and broadcasts
// events to all of them.
type WSHub struct {
	// Registered clients.
	clients map[*WSClient]bool

	// Inbound events to broadcast to all clients.
	broadcast chan []byte

	// Register requests from new clients.
	register chan *WSClient

	// Unregister requests from disconnecting clients.
	unregister chan *WSClient

	// Mutex protects the clients map for read access from Broadcast().
	mu sync.RWMutex
}

// NewWSHub creates and returns a new WebSocket hub.
func NewWSHub() *WSHub {
	return &WSHub{
		clients:    make(map[*WSClient]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *WSClient),
		unregister: make(chan *WSClient),
	}
}

// Run starts the hub's main event loop. It should be launched as a goroutine.
// It handles client registration, unregistration, and message broadcasting.
func (h *WSHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Debugf("WebSocket client connected (total: %d)", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)

				// Broadcast operator_leave if the client was authenticated
				if client.OperatorID != "" {
					h.mu.Unlock()
					h.Broadcast(WSEvent{
						Type: EventOperatorLeave,
						Data: map[string]string{
							"operator_id": client.OperatorID,
							"username":    client.Username,
						},
						Timestamp: time.Now(),
					})
				} else {
					h.mu.Unlock()
				}
				log.Debugf("WebSocket client disconnected (total: %d)", len(h.clients))
			} else {
				h.mu.Unlock()
			}

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					// Client send buffer full; disconnect it.
					go func(c *WSClient) {
						h.unregister <- c
					}(client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast serializes a WSEvent to JSON and sends it to all connected clients.
func (h *WSHub) Broadcast(event WSEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Warnf("Failed to marshal WebSocket event: %v", err)
		return
	}

	select {
	case h.broadcast <- data:
	default:
		log.Warn("WebSocket broadcast channel full, dropping event")
	}
}

// ClientCount returns the number of currently connected WebSocket clients.
func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ConnectedOperators returns a list of authenticated operator usernames.
func (h *WSHub) ConnectedOperators() []map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var operators []map[string]string
	seen := make(map[string]bool)
	for client := range h.clients {
		if client.OperatorID != "" && !seen[client.OperatorID] {
			seen[client.OperatorID] = true
			operators = append(operators, map[string]string{
				"operator_id": client.OperatorID,
				"username":    client.Username,
			})
		}
	}
	return operators
}

// ===================== HTTP Handler =====================

// wsUpgrader configures the WebSocket upgrade with origin validation.
// Non-browser clients (curl, agents) that omit the Origin header are allowed.
// Browser-based connections must originate from localhost or 127.0.0.1.
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Non-browser clients (curl, agents)
		}
		allowed := []string{
			"http://localhost", "https://localhost",
			"http://127.0.0.1", "https://127.0.0.1",
		}
		for _, a := range allowed {
			if strings.HasPrefix(origin, a) {
				return true
			}
		}
		log.Warnf("WebSocket connection rejected: origin %s not allowed", origin)
		return false
	},
}

// HandleWebSocket returns an http.HandlerFunc that upgrades HTTP connections
// to WebSocket and registers the client with the hub.
func HandleWebSocket(hub *WSHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Warnf("WebSocket upgrade failed: %v", err)
			return
		}

		client := &WSClient{
			hub:  hub,
			conn: conn,
			send: make(chan []byte, wsSendBufferSize),
		}

		hub.register <- client

		// Start read and write pumps in separate goroutines.
		go client.WritePump()
		go client.ReadPump()
	}
}
