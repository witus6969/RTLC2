package server

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// statusWriter wraps http.ResponseWriter to capture the HTTP status code
// written by downstream handlers, enabling audit logging of response status.
type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code and delegates to the wrapped ResponseWriter.
func (sw *statusWriter) WriteHeader(code int) {
	sw.statusCode = code
	sw.ResponseWriter.WriteHeader(code)
}

// auditMiddleware returns an http.Handler that logs every request to the audit log.
// It records the operator (extracted from the auth token), HTTP method, path,
// response status code, and request duration.
func (h *HTTPAPIServer) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Determine which operator is making the request
		operator := "anonymous"
		operatorID := ""
		token := r.Header.Get("Authorization")
		if token != "" {
			h.tokensMu.RLock()
			info, ok := h.tokens[token]
			h.tokensMu.RUnlock()
			if ok {
				operator = info.Username
				operatorID = info.OperatorID
			}
		}

		// Wrap the ResponseWriter to capture status code
		sw := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(sw, r)

		// Calculate duration
		duration := time.Since(start)

		// Log the request to the audit trail
		details := fmt.Sprintf("%s %s %s -> %d (%s)",
			operator, r.Method, r.URL.Path, sw.statusCode, duration.Round(time.Millisecond))

		if err := h.db.AuditLog(operatorID, "http_request", r.URL.Path, details); err != nil {
			log.Warnf("Failed to write audit log: %v", err)
		}
	})
}
