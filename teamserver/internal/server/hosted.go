package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// HostedFile represents a file served via HTTP listener.
type HostedFile struct {
	ID           string    `json:"id"`
	Filename     string    `json:"filename"`
	URI          string    `json:"uri"`
	ContentType  string    `json:"content_type"`
	Size         int64     `json:"size"`
	Downloads    int       `json:"downloads"`
	MaxDownloads int       `json:"max_downloads"` // 0 = unlimited
	ExpiresAt    time.Time `json:"expires_at"`    // zero = never
	CreatedAt    time.Time `json:"created_at"`
	Data         []byte    `json:"-"`
}

// HostedFileService manages files served through the teamserver.
type HostedFileService struct {
	files map[string]*HostedFile
	mu    sync.RWMutex
}

// NewHostedFileService creates a new hosted file service.
func NewHostedFileService() *HostedFileService {
	return &HostedFileService{
		files: make(map[string]*HostedFile),
	}
}

// AddFile stores a new file for serving.
func (hfs *HostedFileService) AddFile(filename string, data []byte, contentType string, maxDownloads int, expiresIn time.Duration) *HostedFile {
	hfs.mu.Lock()
	defer hfs.mu.Unlock()

	id := uuid.New().String()[:8]
	uri := "/download/" + id + "/" + filename

	var expiresAt time.Time
	if expiresIn > 0 {
		expiresAt = time.Now().Add(expiresIn)
	}

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	f := &HostedFile{
		ID:           id,
		Filename:     filename,
		URI:          uri,
		ContentType:  contentType,
		Size:         int64(len(data)),
		Downloads:    0,
		MaxDownloads: maxDownloads,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		Data:         data,
	}

	hfs.files[id] = f
	log.Infof("Hosted file added: %s (%s, %d bytes)", filename, id, len(data))
	return f
}

// ServeFile writes the file content to the response writer and tracks downloads.
func (hfs *HostedFileService) ServeFile(id string, w http.ResponseWriter, r *http.Request) bool {
	hfs.mu.Lock()
	defer hfs.mu.Unlock()

	f, ok := hfs.files[id]
	if !ok {
		return false
	}

	// Check expiry
	if !f.ExpiresAt.IsZero() && time.Now().After(f.ExpiresAt) {
		delete(hfs.files, id)
		return false
	}

	// Check max downloads
	if f.MaxDownloads > 0 && f.Downloads >= f.MaxDownloads {
		delete(hfs.files, id)
		return false
	}

	f.Downloads++

	w.Header().Set("Content-Type", f.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", f.Filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", f.Size))
	w.Write(f.Data)

	log.Infof("Hosted file downloaded: %s (%s) by %s [%d/%d]",
		f.Filename, id, r.RemoteAddr, f.Downloads, f.MaxDownloads)

	return true
}

// RemoveFile deletes a hosted file.
func (hfs *HostedFileService) RemoveFile(id string) bool {
	hfs.mu.Lock()
	defer hfs.mu.Unlock()
	_, ok := hfs.files[id]
	if ok {
		delete(hfs.files, id)
	}
	return ok
}

// ListFiles returns all hosted files (without data).
func (hfs *HostedFileService) ListFiles() []*HostedFile {
	hfs.mu.RLock()
	defer hfs.mu.RUnlock()

	list := make([]*HostedFile, 0, len(hfs.files))
	for _, f := range hfs.files {
		list = append(list, f)
	}
	return list
}

// ===================== HTTP Handlers =====================

// RegisterHostedRoutes registers hosted file API endpoints.
func RegisterHostedRoutes(mux *http.ServeMux, hfs *HostedFileService, authMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/hosted", authMiddleware(hfs.handleHostedFiles))
	mux.HandleFunc("/api/v1/hosted/", authMiddleware(hfs.handleHostedFileByID))
	// Public download endpoint (no auth required for payload delivery)
	mux.HandleFunc("/download/", hfs.handleServeHosted)
}

func (hfs *HostedFileService) handleHostedFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		files := hfs.ListFiles()
		jsonResponse(w, map[string]interface{}{"hosted_files": files})

	case http.MethodPost:
		var req struct {
			Filename     string `json:"filename"`
			Data         string `json:"data"` // base64
			ContentType  string `json:"content_type"`
			MaxDownloads int    `json:"max_downloads"`
			ExpiresHours int    `json:"expires_hours"` // 0 = never
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid request body", http.StatusBadRequest)
			return
		}

		data, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			jsonError(w, "invalid base64 data", http.StatusBadRequest)
			return
		}

		var expiry time.Duration
		if req.ExpiresHours > 0 {
			expiry = time.Duration(req.ExpiresHours) * time.Hour
		}

		f := hfs.AddFile(req.Filename, data, req.ContentType, req.MaxDownloads, expiry)
		jsonResponse(w, f)

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (hfs *HostedFileService) handleHostedFileByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/hosted/")
	if r.Method != http.MethodDelete {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !hfs.RemoveFile(id) {
		jsonError(w, "file not found", http.StatusNotFound)
		return
	}
	jsonResponse(w, map[string]interface{}{"status": "ok"})
}

func (hfs *HostedFileService) handleServeHosted(w http.ResponseWriter, r *http.Request) {
	// URL format: /download/{id}/{filename}
	path := strings.TrimPrefix(r.URL.Path, "/download/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	id := parts[0]
	if !hfs.ServeFile(id, w, r) {
		http.NotFound(w, r)
	}
}
