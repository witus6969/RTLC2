package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// BOFMetadata represents the metadata for a BOF object file.
type BOFMetadata struct {
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Author      string    `json:"author"`
	Description string    `json:"description"`
	Source      string    `json:"source,omitempty"`
	Args        []BOFArg  `json:"args"`
	Platforms   []string  `json:"platforms"`
	Opsec       string    `json:"opsec,omitempty"`
}

// BOFArg represents a single argument for a BOF.
type BOFArg struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// handleBOFs handles GET /api/v1/bofs - lists all available BOFs with metadata.
func (h *HTTPAPIServer) handleBOFs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bofsDir := findBOFsDir()
	if bofsDir == "" {
		jsonResponse(w, map[string]interface{}{"bofs": []interface{}{}})
		return
	}

	var bofs []map[string]interface{}

	categories := []string{"persistence", "credential", "recon", "lateral", "evasion", "dotnet"}
	for _, cat := range categories {
		catDir := filepath.Join(bofsDir, cat)
		entries, err := os.ReadDir(catDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}

			data, err := os.ReadFile(filepath.Join(catDir, entry.Name()))
			if err != nil {
				log.Warnf("Failed to read BOF metadata %s: %v", entry.Name(), err)
				continue
			}

			var meta map[string]interface{}
			if err := json.Unmarshal(data, &meta); err != nil {
				log.Warnf("Failed to parse BOF metadata %s: %v", entry.Name(), err)
				continue
			}

			// Check if corresponding .o file exists
			objName := strings.TrimSuffix(entry.Name(), ".json") + ".o"
			objPath := filepath.Join(catDir, objName)
			_, objErr := os.Stat(objPath)
			meta["compiled"] = (objErr == nil)
			meta["file"] = objName

			bofs = append(bofs, meta)
		}
	}

	if bofs == nil {
		bofs = []map[string]interface{}{}
	}

	jsonResponse(w, map[string]interface{}{"bofs": bofs})
}

// handleBOFExecute handles POST /api/v1/bofs/execute - executes a BOF on a target agent.
func (h *HTTPAPIServer) handleBOFExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID  string            `json:"agent_id"`
		BOFName  string            `json:"bof_name"`
		Category string            `json:"category"`
		Args     map[string]string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	bofsDir := findBOFsDir()
	if bofsDir == "" {
		jsonError(w, "BOFs directory not found", http.StatusInternalServerError)
		return
	}

	// Find the BOF object file
	objName := strings.ToLower(strings.ReplaceAll(req.BOFName, " ", "_")) + ".o"
	objPath := filepath.Join(bofsDir, req.Category, objName)

	bofData, err := os.ReadFile(objPath)
	if err != nil {
		// Try without category
		found := false
		categories := []string{"persistence", "credential", "recon", "lateral", "evasion", "dotnet"}
		for _, cat := range categories {
			objPath = filepath.Join(bofsDir, cat, objName)
			bofData, err = os.ReadFile(objPath)
			if err == nil {
				found = true
				break
			}
		}
		if !found {
			jsonError(w, fmt.Sprintf("BOF object file not found: %s", objName), http.StatusNotFound)
			return
		}
	}

	// Queue as BOF task (type 7 = BOF)
	if req.Args == nil {
		req.Args = make(map[string]string)
	}
	req.Args["bof_name"] = req.BOFName

	taskID, err := h.agentManager.QueueTask(req.AgentID, 7, bofData, req.Args)
	if err != nil {
		jsonError(w, fmt.Sprintf("failed to queue BOF task: %v", err), http.StatusInternalServerError)
		return
	}

	log.Infof("BOF task queued: %s -> agent %s (BOF: %s)", taskID, req.AgentID, req.BOFName)

	jsonResponse(w, map[string]interface{}{
		"task_id":  taskID,
		"agent_id": req.AgentID,
		"bof_name": req.BOFName,
	})
}

// handleBOFUpload handles POST /api/v1/bofs/upload - uploads a new BOF.
func (h *HTTPAPIServer) handleBOFUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		Data     string `json:"data"` // base64 encoded .o file
		Metadata string `json:"metadata"` // JSON metadata
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	bofsDir := findBOFsDir()
	if bofsDir == "" {
		bofsDir = "bofs"
	}

	catDir := filepath.Join(bofsDir, filepath.Base(req.Category))
	if err := os.MkdirAll(catDir, 0755); err != nil {
		jsonError(w, "failed to create category directory", http.StatusInternalServerError)
		return
	}

	// Save .o file
	safeName := strings.ToLower(strings.ReplaceAll(filepath.Base(req.Name), " ", "_"))
	objPath := filepath.Join(catDir, safeName+".o")

	decoded, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		jsonError(w, "invalid base64 data", http.StatusBadRequest)
		return
	}

	if err := os.WriteFile(objPath, decoded, 0644); err != nil {
		jsonError(w, "failed to save BOF file", http.StatusInternalServerError)
		return
	}

	// Save metadata if provided
	if req.Metadata != "" {
		metaPath := filepath.Join(catDir, safeName+".json")
		if err := os.WriteFile(metaPath, []byte(req.Metadata), 0644); err != nil {
			log.Warnf("Failed to save BOF metadata: %v", err)
		}
	}

	log.Infof("BOF uploaded: %s/%s (%d bytes)", req.Category, safeName, len(decoded))

	jsonResponse(w, map[string]interface{}{
		"status": "ok",
		"name":   req.Name,
		"path":   objPath,
	})
}

// findBOFsDir locates the BOFs directory.
func findBOFsDir() string {
	candidates := []string{
		"./bofs",
		"../bofs",
		filepath.Join(filepath.Dir(os.Args[0]), "..", "bofs"),
		"/opt/RTLC2/teamserver/bofs",
	}

	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			absDir, err := filepath.Abs(dir)
			if err != nil {
				return dir
			}
			return absDir
		}
	}
	return ""
}
