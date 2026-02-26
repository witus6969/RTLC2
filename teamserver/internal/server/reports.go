package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ===================== Report Types =====================

// ReportRequest is the JSON body for POST /api/v1/reports/generate.
type ReportRequest struct {
	Template string   `json:"template"`
	Format   string   `json:"format"` // json, csv, markdown
	DateFrom string   `json:"date_from"`
	DateTo   string   `json:"date_to"`
	AgentIDs []string `json:"agent_ids"`
}

// ReportResponse is returned from report generation.
type ReportResponse struct {
	Template  string `json:"template"`
	Format    string `json:"format"`
	Data      string `json:"data"`
	Generated string `json:"generated"`
}

// ReportTemplate describes an available report template.
type ReportTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Formats     []string `json:"formats"`
}

// ===================== Report Templates =====================

var reportTemplates = []ReportTemplate{
	{
		ID:          "session_summary",
		Name:        "Session Summary",
		Description: "Overview of agents, tasks, and credentials within a date range",
		Formats:     []string{"json", "csv", "markdown"},
	},
	{
		ID:          "agent_inventory",
		Name:        "Agent Inventory",
		Description: "Detailed table of all agents with hostname, user, OS, arch, IP, and status",
		Formats:     []string{"json", "csv", "markdown"},
	},
	{
		ID:          "credentials",
		Name:        "Credentials Report",
		Description: "All harvested credentials with type, username, domain, source, and timestamp",
		Formats:     []string{"json", "csv", "markdown"},
	},
	{
		ID:          "activity_timeline",
		Name:        "Activity Timeline",
		Description: "Tasks executed within a date range with timestamps, agent, type, and status",
		Formats:     []string{"json", "csv", "markdown"},
	},
	{
		ID:          "mitre_attack",
		Name:        "MITRE ATT&CK Mapping",
		Description: "Map executed tasks to MITRE ATT&CK techniques for reporting",
		Formats:     []string{"json", "csv", "markdown"},
	},
}

// ===================== Handlers =====================

// handleReportTemplates returns the list of available report templates.
func (h *HTTPAPIServer) handleReportTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, map[string]interface{}{"templates": reportTemplates})
}

// handleGenerateReport generates a report based on the given template and format.
func (h *HTTPAPIServer) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Format == "" {
		req.Format = "json"
	}
	if req.Format != "json" && req.Format != "csv" && req.Format != "markdown" {
		jsonError(w, "invalid format: must be json, csv, or markdown", http.StatusBadRequest)
		return
	}

	// Parse date range
	var dateFrom, dateTo time.Time
	var err error
	if req.DateFrom != "" {
		dateFrom, err = time.Parse("2006-01-02", req.DateFrom)
		if err != nil {
			jsonError(w, "invalid date_from format (use YYYY-MM-DD)", http.StatusBadRequest)
			return
		}
	} else {
		dateFrom = time.Now().AddDate(0, -1, 0) // default: 1 month ago
	}
	if req.DateTo != "" {
		dateTo, err = time.Parse("2006-01-02", req.DateTo)
		if err != nil {
			jsonError(w, "invalid date_to format (use YYYY-MM-DD)", http.StatusBadRequest)
			return
		}
		// Include the full end day
		dateTo = dateTo.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
	} else {
		dateTo = time.Now()
	}

	var data string
	switch req.Template {
	case "session_summary":
		data, err = h.generateSessionSummary(req.Format, dateFrom, dateTo)
	case "agent_inventory":
		data, err = h.generateAgentInventory(req.Format)
	case "credentials":
		data, err = h.generateCredentialsReport(req.Format)
	case "activity_timeline":
		data, err = h.generateActivityTimeline(req.Format, dateFrom, dateTo)
	case "mitre_attack":
		data, err = h.generateMitreMapping(req.Format, dateFrom, dateTo)
	default:
		jsonError(w, "unknown template: "+req.Template, http.StatusBadRequest)
		return
	}

	if err != nil {
		jsonError(w, fmt.Sprintf("report generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	resp := ReportResponse{
		Template:  req.Template,
		Format:    req.Format,
		Data:      data,
		Generated: time.Now().Format(time.RFC3339),
	}
	jsonResponse(w, resp)
}

// ===================== Report Generators =====================

func (h *HTTPAPIServer) generateSessionSummary(format string, from, to time.Time) (string, error) {
	agents, err := h.db.GetAllAgents()
	if err != nil {
		return "", err
	}

	alive := 0
	dead := 0
	for _, a := range agents {
		if a.Alive {
			alive++
		} else {
			dead++
		}
	}

	tasks, err := h.db.GetTasksByDateRange(from, to)
	if err != nil {
		return "", err
	}

	creds, err := h.db.GetCredentials()
	if err != nil {
		return "", err
	}

	summary := map[string]interface{}{
		"total_agents":    len(agents),
		"alive_agents":    alive,
		"dead_agents":     dead,
		"total_tasks":     len(tasks),
		"credential_count": len(creds),
		"date_from":       from.Format("2006-01-02"),
		"date_to":         to.Format("2006-01-02"),
	}

	switch format {
	case "json":
		b, _ := json.MarshalIndent(summary, "", "  ")
		return string(b), nil

	case "csv":
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Write([]string{"Metric", "Value"})
		w.Write([]string{"Total Agents", fmt.Sprintf("%d", len(agents))})
		w.Write([]string{"Alive Agents", fmt.Sprintf("%d", alive)})
		w.Write([]string{"Dead Agents", fmt.Sprintf("%d", dead)})
		w.Write([]string{"Total Tasks", fmt.Sprintf("%d", len(tasks))})
		w.Write([]string{"Credentials", fmt.Sprintf("%d", len(creds))})
		w.Write([]string{"Date From", from.Format("2006-01-02")})
		w.Write([]string{"Date To", to.Format("2006-01-02")})
		w.Flush()
		return sb.String(), nil

	case "markdown":
		var sb strings.Builder
		sb.WriteString("# Session Summary\n\n")
		sb.WriteString(fmt.Sprintf("**Date Range:** %s to %s\n\n", from.Format("2006-01-02"), to.Format("2006-01-02")))
		sb.WriteString("| Metric | Value |\n")
		sb.WriteString("|--------|-------|\n")
		sb.WriteString(fmt.Sprintf("| Total Agents | %d |\n", len(agents)))
		sb.WriteString(fmt.Sprintf("| Alive Agents | %d |\n", alive))
		sb.WriteString(fmt.Sprintf("| Dead Agents | %d |\n", dead))
		sb.WriteString(fmt.Sprintf("| Total Tasks | %d |\n", len(tasks)))
		sb.WriteString(fmt.Sprintf("| Credentials | %d |\n", len(creds)))
		return sb.String(), nil
	}
	return "", fmt.Errorf("unsupported format")
}

func (h *HTTPAPIServer) generateAgentInventory(format string) (string, error) {
	agents, err := h.db.GetAllAgents()
	if err != nil {
		return "", err
	}

	type agentRow struct {
		ID         string `json:"id"`
		Hostname   string `json:"hostname"`
		Username   string `json:"username"`
		OS         string `json:"os"`
		Arch       string `json:"arch"`
		InternalIP string `json:"internal_ip"`
		ExternalIP string `json:"external_ip"`
		LastSeen   string `json:"last_seen"`
		Status     string `json:"status"`
		Integrity  string `json:"integrity"`
	}

	rows := make([]agentRow, 0, len(agents))
	for _, a := range agents {
		status := "ALIVE"
		if !a.Alive {
			status = "DEAD"
		}
		rows = append(rows, agentRow{
			ID:         a.ID,
			Hostname:   a.Hostname,
			Username:   a.Username,
			OS:         a.OS,
			Arch:       a.Arch,
			InternalIP: a.InternalIP,
			ExternalIP: a.ExternalIP,
			LastSeen:   a.LastSeen.Format("2006-01-02 15:04:05"),
			Status:     status,
			Integrity:  a.Integrity,
		})
	}

	switch format {
	case "json":
		b, _ := json.MarshalIndent(rows, "", "  ")
		return string(b), nil

	case "csv":
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Write([]string{"ID", "Hostname", "Username", "OS", "Arch", "Internal IP", "External IP", "Last Seen", "Status", "Integrity"})
		for _, r := range rows {
			w.Write([]string{r.ID, r.Hostname, r.Username, r.OS, r.Arch, r.InternalIP, r.ExternalIP, r.LastSeen, r.Status, r.Integrity})
		}
		w.Flush()
		return sb.String(), nil

	case "markdown":
		var sb strings.Builder
		sb.WriteString("# Agent Inventory\n\n")
		sb.WriteString("| ID | Hostname | Username | OS | Arch | Internal IP | External IP | Last Seen | Status | Integrity |\n")
		sb.WriteString("|-----|----------|----------|-----|------|-------------|-------------|-----------|--------|----------|\n")
		for _, r := range rows {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				r.ID[:8], r.Hostname, r.Username, r.OS, r.Arch, r.InternalIP, r.ExternalIP, r.LastSeen, r.Status, r.Integrity))
		}
		return sb.String(), nil
	}
	return "", fmt.Errorf("unsupported format")
}

func (h *HTTPAPIServer) generateCredentialsReport(format string) (string, error) {
	creds, err := h.db.GetCredentials()
	if err != nil {
		return "", err
	}

	switch format {
	case "json":
		b, _ := json.MarshalIndent(creds, "", "  ")
		return string(b), nil

	case "csv":
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Write([]string{"ID", "Type", "Username", "Domain", "Value", "Source Agent ID", "Source Hostname", "Note", "Timestamp"})
		for _, c := range creds {
			w.Write([]string{
				fmt.Sprintf("%v", c["id"]),
				fmt.Sprintf("%v", c["type"]),
				fmt.Sprintf("%v", c["username"]),
				fmt.Sprintf("%v", c["domain"]),
				fmt.Sprintf("%v", c["value"]),
				fmt.Sprintf("%v", c["source_agent_id"]),
				fmt.Sprintf("%v", c["source_agent_hostname"]),
				fmt.Sprintf("%v", c["note"]),
				fmt.Sprintf("%v", c["timestamp"]),
			})
		}
		w.Flush()
		return sb.String(), nil

	case "markdown":
		var sb strings.Builder
		sb.WriteString("# Credentials Report\n\n")
		sb.WriteString("| Type | Username | Domain | Source | Timestamp |\n")
		sb.WriteString("|------|----------|--------|--------|----------|\n")
		for _, c := range creds {
			sb.WriteString(fmt.Sprintf("| %v | %v | %v | %v | %v |\n",
				c["type"], c["username"], c["domain"], c["source_agent_hostname"], c["timestamp"]))
		}
		return sb.String(), nil
	}
	return "", fmt.Errorf("unsupported format")
}

func (h *HTTPAPIServer) generateActivityTimeline(format string, from, to time.Time) (string, error) {
	tasks, err := h.db.GetTasksByDateRange(from, to)
	if err != nil {
		return "", err
	}

	type taskRow struct {
		TaskID    string `json:"task_id"`
		AgentID   string `json:"agent_id"`
		Type      int    `json:"type"`
		TypeName  string `json:"type_name"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}

	rows := make([]taskRow, 0, len(tasks))
	for _, t := range tasks {
		statusStr := "pending"
		switch t.Status {
		case 1:
			statusStr = "running"
		case 2:
			statusStr = "complete"
		case 3:
			statusStr = "error"
		}
		rows = append(rows, taskRow{
			TaskID:    t.ID,
			AgentID:   t.AgentID,
			Type:      t.Type,
			TypeName:  taskTypeName(t.Type),
			Status:    statusStr,
			CreatedAt: t.CreatedAt.Format("2006-01-02 15:04:05"),
			UpdatedAt: t.UpdatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	switch format {
	case "json":
		b, _ := json.MarshalIndent(rows, "", "  ")
		return string(b), nil

	case "csv":
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Write([]string{"Task ID", "Agent ID", "Type", "Type Name", "Status", "Created At", "Updated At"})
		for _, r := range rows {
			w.Write([]string{r.TaskID, r.AgentID, fmt.Sprintf("%d", r.Type), r.TypeName, r.Status, r.CreatedAt, r.UpdatedAt})
		}
		w.Flush()
		return sb.String(), nil

	case "markdown":
		var sb strings.Builder
		sb.WriteString("# Activity Timeline\n\n")
		sb.WriteString(fmt.Sprintf("**Date Range:** %s to %s\n\n", from.Format("2006-01-02"), to.Format("2006-01-02")))
		sb.WriteString("| Timestamp | Agent ID | Task Type | Status |\n")
		sb.WriteString("|-----------|----------|-----------|--------|\n")
		for _, r := range rows {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", r.CreatedAt, r.AgentID[:8], r.TypeName, r.Status))
		}
		return sb.String(), nil
	}
	return "", fmt.Errorf("unsupported format")
}

func (h *HTTPAPIServer) generateMitreMapping(format string, from, to time.Time) (string, error) {
	taskCounts, err := h.db.GetTaskCountByType()
	if err != nil {
		return "", err
	}

	// Map task types to MITRE ATT&CK techniques
	mitreMap := map[int]struct {
		Technique   string
		TechniqueID string
		Tactic      string
	}{
		1:  {"Command and Scripting Interpreter", "T1059", "Execution"},
		2:  {"Ingress Tool Transfer", "T1105", "Command and Control"},
		3:  {"Data from Local System", "T1005", "Collection"},
		6:  {"Process Injection", "T1055", "Defense Evasion"},
		7:  {"Native API", "T1106", "Execution"},
		8:  {"Reflective Code Loading", "T1620", "Defense Evasion"},
		9:  {"Screen Capture", "T1113", "Collection"},
		10: {"Input Capture: Keylogging", "T1056.001", "Collection"},
		11: {"Process Discovery", "T1057", "Discovery"},
		12: {"File and Directory Discovery", "T1083", "Discovery"},
		15: {"System Owner/User Discovery", "T1033", "Discovery"},
		16: {"System Network Configuration Discovery", "T1016", "Discovery"},
		17: {"OS Credential Dumping", "T1003", "Credential Access"},
		18: {"Access Token Manipulation", "T1134", "Defense Evasion"},
		19: {"Remote Services", "T1021", "Lateral Movement"},
		20: {"Network Service Discovery", "T1046", "Discovery"},
		21: {"Proxy", "T1090", "Command and Control"},
		22: {"Indicator Removal", "T1070", "Defense Evasion"},
		24: {"Clipboard Data", "T1115", "Collection"},
		25: {"Modify Registry", "T1112", "Defense Evasion"},
		26: {"System Services", "T1569", "Execution"},
	}

	type mitreRow struct {
		TaskType    int    `json:"task_type"`
		TypeName    string `json:"type_name"`
		TechniqueID string `json:"technique_id"`
		Technique   string `json:"technique"`
		Tactic      string `json:"tactic"`
		Count       int    `json:"count"`
	}

	var rows []mitreRow
	for taskType, count := range taskCounts {
		if mapping, ok := mitreMap[taskType]; ok {
			rows = append(rows, mitreRow{
				TaskType:    taskType,
				TypeName:    taskTypeName(taskType),
				TechniqueID: mapping.TechniqueID,
				Technique:   mapping.Technique,
				Tactic:      mapping.Tactic,
				Count:       count,
			})
		} else {
			rows = append(rows, mitreRow{
				TaskType:    taskType,
				TypeName:    taskTypeName(taskType),
				TechniqueID: "N/A",
				Technique:   "Unmapped",
				Tactic:      "Unknown",
				Count:       count,
			})
		}
	}

	switch format {
	case "json":
		b, _ := json.MarshalIndent(rows, "", "  ")
		return string(b), nil

	case "csv":
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Write([]string{"Task Type", "Type Name", "Technique ID", "Technique", "Tactic", "Count"})
		for _, r := range rows {
			w.Write([]string{fmt.Sprintf("%d", r.TaskType), r.TypeName, r.TechniqueID, r.Technique, r.Tactic, fmt.Sprintf("%d", r.Count)})
		}
		w.Flush()
		return sb.String(), nil

	case "markdown":
		var sb strings.Builder
		sb.WriteString("# MITRE ATT&CK Mapping\n\n")
		sb.WriteString("| Technique ID | Technique | Tactic | Task Type | Count |\n")
		sb.WriteString("|-------------|-----------|--------|-----------|-------|\n")
		for _, r := range rows {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d |\n",
				r.TechniqueID, r.Technique, r.Tactic, r.TypeName, r.Count))
		}
		return sb.String(), nil
	}
	return "", fmt.Errorf("unsupported format")
}

// ===================== Helpers =====================

func taskTypeName(t int) string {
	names := map[int]string{
		0:  "Unknown",
		1:  "Shell",
		2:  "Upload",
		3:  "Download",
		4:  "Sleep",
		5:  "Exit",
		6:  "Inject",
		7:  "BOF",
		8:  "Assembly",
		9:  "Screenshot",
		10: "Keylog",
		11: "Process List",
		12: "List Dir",
		13: "Change Dir",
		14: "Print WD",
		15: "Whoami",
		16: "Ipconfig",
		17: "Hashdump",
		18: "Token",
		19: "Pivot",
		20: "Port Scan",
		21: "SOCKS",
		22: "Self-Destruct",
		23: "Module",
		24: "Clipboard",
		25: "Reg Write",
		26: "Service Ctl",
		27: "Jobs",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("Type-%d", t)
}
