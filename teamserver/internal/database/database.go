package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

type Database struct {
	db *sql.DB
}

type AgentRecord struct {
	ID            string
	Hostname      string
	Username      string
	OS            string
	Arch          string
	ProcessName   string
	PID           int
	InternalIP    string
	ExternalIP    string
	SleepInterval int
	Jitter        int
	FirstSeen     time.Time
	LastSeen      time.Time
	ListenerID    string
	Integrity     string
	Alive         bool
	Note          string
	AESKey        string
}

type OperatorRecord struct {
	ID           string
	Username     string
	PasswordHash string
	Role         string
	LastLogin    time.Time
}

type TaskRecord struct {
	ID        string
	AgentID   string
	Type      int
	Data      []byte
	Params    string // JSON
	Status    int    // 0=pending, 1=running, 2=complete, 3=error
	Output    []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ListenerRecord struct {
	ID        string
	Name      string
	Protocol  int
	BindHost  string
	BindPort  int
	Config    string // JSON
	Active    bool
	StartedAt time.Time
}

func New(path string) (*Database, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}

	d := &Database{db: db}
	if err := d.migrate(); err != nil {
		return nil, err
	}
	if err := d.migrateCampaigns(); err != nil {
		return nil, err
	}

	log.Info("Database initialized: ", path)
	return d, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

// RawDB returns the underlying *sql.DB for direct access by services
// that manage their own schema (e.g. chat, blob metadata).
func (d *Database) RawDB() *sql.DB {
	return d.db
}

func (d *Database) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS operators (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'operator',
		last_login DATETIME
	);

	CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY,
		hostname TEXT,
		username TEXT,
		os TEXT,
		arch TEXT,
		process_name TEXT,
		pid INTEGER,
		internal_ip TEXT,
		external_ip TEXT,
		sleep_interval INTEGER DEFAULT 5,
		jitter INTEGER DEFAULT 10,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		listener_id TEXT,
		integrity TEXT DEFAULT 'medium',
		alive INTEGER DEFAULT 1,
		note TEXT DEFAULT '',
		aes_key TEXT
	);

	CREATE TABLE IF NOT EXISTS tasks (
		id TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL,
		type INTEGER NOT NULL,
		data BLOB,
		params TEXT DEFAULT '{}',
		status INTEGER DEFAULT 0,
		output BLOB,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (agent_id) REFERENCES agents(id)
	);

	CREATE TABLE IF NOT EXISTS listeners (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		protocol INTEGER NOT NULL,
		bind_host TEXT NOT NULL,
		bind_port INTEGER NOT NULL,
		config TEXT DEFAULT '{}',
		active INTEGER DEFAULT 1,
		started_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		operator_id TEXT,
		action TEXT NOT NULL,
		target TEXT,
		details TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL DEFAULT 'plaintext',
		username TEXT NOT NULL DEFAULT '',
		domain TEXT DEFAULT '',
		value TEXT NOT NULL DEFAULT '',
		source_agent_id TEXT DEFAULT '',
		source_agent_hostname TEXT DEFAULT '',
		note TEXT DEFAULT '',
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS chat_messages (
		id TEXT PRIMARY KEY,
		operator_id TEXT NOT NULL DEFAULT '',
		operator_name TEXT NOT NULL DEFAULT '',
		workspace_id TEXT DEFAULT '',
		message TEXT NOT NULL DEFAULT '',
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS webhooks (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL DEFAULT '',
		type TEXT NOT NULL DEFAULT 'generic',
		url TEXT NOT NULL,
		events TEXT DEFAULT '*',
		active INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS auto_tasks (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL DEFAULT '',
		task_type INTEGER NOT NULL DEFAULT 1,
		data TEXT DEFAULT '',
		params TEXT DEFAULT '{}',
		os_filter TEXT DEFAULT '',
		arch_filter TEXT DEFAULT '',
		active INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS agent_tags (
		agent_id TEXT NOT NULL,
		tag TEXT NOT NULL,
		PRIMARY KEY (agent_id, tag)
	);

	CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(agent_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_agents_alive ON agents(alive);
	CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);
	CREATE INDEX IF NOT EXISTS idx_chat_workspace ON chat_messages(workspace_id);
	`
	_, err := d.db.Exec(schema)
	return err
}

// ===================== Operator Operations =====================

func (d *Database) OperatorExists(username string) bool {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM operators WHERE username = ?", username).Scan(&count)
	return err == nil && count > 0
}

func (d *Database) CreateOperator(op *OperatorRecord) error {
	_, err := d.db.Exec(
		"INSERT INTO operators (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
		op.ID, op.Username, op.PasswordHash, op.Role,
	)
	return err
}

func (d *Database) GetOperatorByUsername(username string) (*OperatorRecord, error) {
	op := &OperatorRecord{}
	var lastLogin sql.NullTime
	err := d.db.QueryRow(
		"SELECT id, username, password_hash, role, last_login FROM operators WHERE username = ?",
		username,
	).Scan(&op.ID, &op.Username, &op.PasswordHash, &op.Role, &lastLogin)
	if err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		op.LastLogin = lastLogin.Time
	}
	return op, nil
}

func (d *Database) UpdateOperatorLogin(id string) error {
	_, err := d.db.Exec("UPDATE operators SET last_login = ? WHERE id = ?", time.Now(), id)
	return err
}

// GetOperatorByID retrieves a single operator by ID.
func (d *Database) GetOperatorByID(id string) (*OperatorRecord, error) {
	op := &OperatorRecord{}
	var lastLogin sql.NullTime
	err := d.db.QueryRow(
		"SELECT id, username, password_hash, role, last_login FROM operators WHERE id = ?",
		id,
	).Scan(&op.ID, &op.Username, &op.PasswordHash, &op.Role, &lastLogin)
	if err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		op.LastLogin = lastLogin.Time
	}
	return op, nil
}

// UpdateOperatorPassword updates the password hash for an operator.
func (d *Database) UpdateOperatorPassword(id, passwordHash string) error {
	result, err := d.db.Exec("UPDATE operators SET password_hash = ? WHERE id = ?", passwordHash, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("operator not found")
	}
	return nil
}

// UpdateOperatorRole updates the role for an operator.
func (d *Database) UpdateOperatorRole(id, role string) error {
	result, err := d.db.Exec("UPDATE operators SET role = ? WHERE id = ?", role, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("operator not found")
	}
	return nil
}

// DeleteOperator removes an operator by ID.
func (d *Database) DeleteOperator(id string) error {
	result, err := d.db.Exec("DELETE FROM operators WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("operator not found")
	}
	return nil
}

func (d *Database) GetAllOperators() ([]*OperatorRecord, error) {
	rows, err := d.db.Query("SELECT id, username, password_hash, role, last_login FROM operators")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var operators []*OperatorRecord
	for rows.Next() {
		op := &OperatorRecord{}
		var lastLogin sql.NullTime
		if err := rows.Scan(&op.ID, &op.Username, &op.PasswordHash, &op.Role, &lastLogin); err != nil {
			continue
		}
		if lastLogin.Valid {
			op.LastLogin = lastLogin.Time
		}
		operators = append(operators, op)
	}
	return operators, nil
}

// ===================== Agent Operations =====================

func (d *Database) RegisterAgent(agent *AgentRecord) error {
	_, err := d.db.Exec(
		`INSERT INTO agents (id, hostname, username, os, arch, process_name, pid, internal_ip, external_ip,
		 sleep_interval, jitter, first_seen, last_seen, listener_id, integrity, alive, aes_key)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		agent.ID, agent.Hostname, agent.Username, agent.OS, agent.Arch, agent.ProcessName, agent.PID,
		agent.InternalIP, agent.ExternalIP, agent.SleepInterval, agent.Jitter,
		agent.FirstSeen, agent.LastSeen, agent.ListenerID, agent.Integrity, agent.Alive, agent.AESKey,
	)
	return err
}

func (d *Database) GetAgent(id string) (*AgentRecord, error) {
	a := &AgentRecord{}
	err := d.db.QueryRow(
		`SELECT id, hostname, username, os, arch, process_name, pid, internal_ip, external_ip,
		 sleep_interval, jitter, first_seen, last_seen, listener_id, integrity, alive, note, aes_key
		 FROM agents WHERE id = ?`, id,
	).Scan(&a.ID, &a.Hostname, &a.Username, &a.OS, &a.Arch, &a.ProcessName, &a.PID,
		&a.InternalIP, &a.ExternalIP, &a.SleepInterval, &a.Jitter,
		&a.FirstSeen, &a.LastSeen, &a.ListenerID, &a.Integrity, &a.Alive, &a.Note, &a.AESKey)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (d *Database) GetAllAgents() ([]*AgentRecord, error) {
	rows, err := d.db.Query(
		`SELECT id, hostname, username, os, arch, process_name, pid, internal_ip, external_ip,
		 sleep_interval, jitter, first_seen, last_seen, listener_id, integrity, alive, note, aes_key
		 FROM agents ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*AgentRecord
	for rows.Next() {
		a := &AgentRecord{}
		if err := rows.Scan(&a.ID, &a.Hostname, &a.Username, &a.OS, &a.Arch, &a.ProcessName, &a.PID,
			&a.InternalIP, &a.ExternalIP, &a.SleepInterval, &a.Jitter,
			&a.FirstSeen, &a.LastSeen, &a.ListenerID, &a.Integrity, &a.Alive, &a.Note, &a.AESKey); err != nil {
			continue
		}
		agents = append(agents, a)
	}
	return agents, nil
}

func (d *Database) UpdateAgentCheckin(id, externalIP string) error {
	_, err := d.db.Exec("UPDATE agents SET last_seen = ?, external_ip = ? WHERE id = ?",
		time.Now(), externalIP, id)
	return err
}

func (d *Database) SetAgentAlive(id string, alive bool) error {
	_, err := d.db.Exec("UPDATE agents SET alive = ? WHERE id = ?", alive, id)
	return err
}

func (d *Database) RemoveAgent(id string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM tasks WHERE agent_id = ?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM agent_tags WHERE agent_id = ?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM campaign_agents WHERE agent_id = ?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM agents WHERE id = ?", id); err != nil {
		return err
	}
	return tx.Commit()
}

// ===================== Task Operations =====================

func (d *Database) CreateTask(task *TaskRecord) error {
	_, err := d.db.Exec(
		"INSERT INTO tasks (id, agent_id, type, data, params, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		task.ID, task.AgentID, task.Type, task.Data, task.Params, task.Status, task.CreatedAt,
	)
	return err
}

func (d *Database) GetPendingTasks(agentID string) ([]*TaskRecord, error) {
	rows, err := d.db.Query(
		"SELECT id, agent_id, type, data, params, status, created_at FROM tasks WHERE agent_id = ? AND status = 0 ORDER BY created_at ASC",
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*TaskRecord
	for rows.Next() {
		t := &TaskRecord{}
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Type, &t.Data, &t.Params, &t.Status, &t.CreatedAt); err != nil {
			continue
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

func (d *Database) UpdateTaskStatus(id string, status int) error {
	_, err := d.db.Exec("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
		status, time.Now(), id)
	return err
}

func (d *Database) SetTaskResult(id string, output []byte) error {
	_, err := d.db.Exec("UPDATE tasks SET status = 2, output = ?, updated_at = ? WHERE id = ?",
		output, time.Now(), id)
	return err
}

func (d *Database) SetTaskError(id string, output []byte) error {
	_, err := d.db.Exec("UPDATE tasks SET status = 3, output = ?, updated_at = ? WHERE id = ?",
		output, time.Now(), id)
	return err
}

func (d *Database) GetAgentTasks(agentID string) ([]*TaskRecord, error) {
	rows, err := d.db.Query(
		"SELECT id, agent_id, type, data, params, status, output, created_at, updated_at FROM tasks WHERE agent_id = ? ORDER BY created_at DESC",
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*TaskRecord
	for rows.Next() {
		t := &TaskRecord{}
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Type, &t.Data, &t.Params, &t.Status, &t.Output, &t.CreatedAt, &t.UpdatedAt); err != nil {
			continue
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

func (d *Database) GetTask(id string) (*TaskRecord, error) {
	t := &TaskRecord{}
	err := d.db.QueryRow(
		"SELECT id, agent_id, type, data, params, status, output, created_at, updated_at FROM tasks WHERE id = ?", id,
	).Scan(&t.ID, &t.AgentID, &t.Type, &t.Data, &t.Params, &t.Status, &t.Output, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// CancelTask cancels a pending task by setting its status to 4 (cancelled).
func (d *Database) CancelTask(id string) error {
	result, err := d.db.Exec("UPDATE tasks SET status = 4, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 0", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("task not found or not pending")
	}
	return nil
}

// ===================== Listener Operations =====================

func (d *Database) CreateListener(l *ListenerRecord) error {
	_, err := d.db.Exec(
		"INSERT INTO listeners (id, name, protocol, bind_host, bind_port, config, active, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		l.ID, l.Name, l.Protocol, l.BindHost, l.BindPort, l.Config, l.Active, l.StartedAt,
	)
	return err
}

func (d *Database) GetAllListeners() ([]*ListenerRecord, error) {
	rows, err := d.db.Query("SELECT id, name, protocol, bind_host, bind_port, config, active, started_at FROM listeners")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var listeners []*ListenerRecord
	for rows.Next() {
		l := &ListenerRecord{}
		if err := rows.Scan(&l.ID, &l.Name, &l.Protocol, &l.BindHost, &l.BindPort, &l.Config, &l.Active, &l.StartedAt); err != nil {
			continue
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

func (d *Database) StopListener(id string) error {
	_, err := d.db.Exec("UPDATE listeners SET active = 0 WHERE id = ?", id)
	return err
}

func (d *Database) DeleteListener(id string) error {
	_, err := d.db.Exec("DELETE FROM listeners WHERE id = ?", id)
	return err
}

// ===================== Audit Log =====================

func (d *Database) AuditLog(operatorID, action, target, details string) error {
	_, err := d.db.Exec(
		"INSERT INTO audit_log (operator_id, action, target, details) VALUES (?, ?, ?, ?)",
		operatorID, action, target, details,
	)
	return err
}

// AuditLogRecord represents a single audit log entry.
type AuditLogRecord struct {
	ID         int
	OperatorID string
	Action     string
	Target     string
	Details    string
	Timestamp  time.Time
}

// GetRecentAuditLog retrieves the most recent audit log entries.
func (d *Database) GetRecentAuditLog(limit int) ([]*AuditLogRecord, error) {
	rows, err := d.db.Query(
		"SELECT id, operator_id, action, target, details, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*AuditLogRecord
	for rows.Next() {
		r := &AuditLogRecord{}
		var operatorID, target, details sql.NullString
		if err := rows.Scan(&r.ID, &operatorID, &r.Action, &target, &details, &r.Timestamp); err != nil {
			continue
		}
		if operatorID.Valid {
			r.OperatorID = operatorID.String
		}
		if target.Valid {
			r.Target = target.String
		}
		if details.Valid {
			r.Details = details.String
		}
		records = append(records, r)
	}
	return records, nil
}

// QueryAuditLog retrieves audit log entries with optional filters.
func (d *Database) QueryAuditLog(operatorID, action string, since time.Time, limit, offset int) ([]*AuditLogRecord, error) {
	query := "SELECT id, operator_id, action, target, details, timestamp FROM audit_log WHERE 1=1"
	args := []interface{}{}
	if operatorID != "" {
		query += " AND operator_id = ?"
		args = append(args, operatorID)
	}
	if action != "" {
		query += " AND action LIKE ?"
		args = append(args, "%"+action+"%")
	}
	if !since.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, since)
	}
	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*AuditLogRecord
	for rows.Next() {
		r := &AuditLogRecord{}
		var operatorID, target, details sql.NullString
		if err := rows.Scan(&r.ID, &operatorID, &r.Action, &target, &details, &r.Timestamp); err != nil {
			continue
		}
		if operatorID.Valid {
			r.OperatorID = operatorID.String
		}
		if target.Valid {
			r.Target = target.String
		}
		if details.Valid {
			r.Details = details.String
		}
		records = append(records, r)
	}
	return records, nil
}

// ===================== Credentials =====================

func (d *Database) GetCredentials() ([]map[string]interface{}, error) {
	rows, err := d.db.Query("SELECT id, type, username, domain, value, source_agent_id, source_agent_hostname, note, timestamp FROM credentials ORDER BY timestamp DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []map[string]interface{}
	for rows.Next() {
		var id, ctype, username, domain, value, sourceID, sourceHost, note string
		var ts time.Time
		if err := rows.Scan(&id, &ctype, &username, &domain, &value, &sourceID, &sourceHost, &note, &ts); err != nil {
			continue
		}
		creds = append(creds, map[string]interface{}{
			"id":                    id,
			"type":                  ctype,
			"username":              username,
			"domain":                domain,
			"value":                 value,
			"source_agent_id":       sourceID,
			"source_agent_hostname": sourceHost,
			"note":                  note,
			"timestamp":             ts.Format("2006-01-02 15:04:05"),
		})
	}
	return creds, nil
}

func (d *Database) SaveCredential(cred map[string]interface{}) error {
	_, err := d.db.Exec(
		"INSERT INTO credentials (id, type, username, domain, value, source_agent_id, source_agent_hostname, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		cred["id"], cred["type"], cred["username"], cred["domain"], cred["value"],
		cred["source_agent_id"], cred["source_agent_hostname"], cred["note"],
	)
	return err
}

func (d *Database) DeleteCredential(id string) error {
	result, err := d.db.Exec("DELETE FROM credentials WHERE id = ?", id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

// ===================== Chat Messages =====================

func (d *Database) SaveChatMessage(id, operatorID, operatorName, workspaceID, message string) error {
	_, err := d.db.Exec(
		"INSERT INTO chat_messages (id, operator_id, operator_name, workspace_id, message) VALUES (?, ?, ?, ?, ?)",
		id, operatorID, operatorName, workspaceID, message,
	)
	return err
}

func (d *Database) GetChatMessages(workspaceID string, limit int) ([]map[string]interface{}, error) {
	var rows *sql.Rows
	var err error
	if workspaceID == "" {
		rows, err = d.db.Query("SELECT id, operator_id, operator_name, workspace_id, message, timestamp FROM chat_messages ORDER BY timestamp DESC LIMIT ?", limit)
	} else {
		rows, err = d.db.Query("SELECT id, operator_id, operator_name, workspace_id, message, timestamp FROM chat_messages WHERE workspace_id = ? ORDER BY timestamp DESC LIMIT ?", workspaceID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []map[string]interface{}
	for rows.Next() {
		var id, opID, opName, wsID, msg string
		var ts time.Time
		if err := rows.Scan(&id, &opID, &opName, &wsID, &msg, &ts); err != nil {
			continue
		}
		msgs = append(msgs, map[string]interface{}{
			"id":            id,
			"operator_id":   opID,
			"operator_name": opName,
			"workspace_id":  wsID,
			"message":       msg,
			"timestamp":     ts.Format("2006-01-02 15:04:05"),
		})
	}
	// Reverse to get oldest first
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
	return msgs, nil
}

// ===================== Webhooks =====================

func (d *Database) GetWebhooks() ([]*WebhookRecord, error) {
	rows, err := d.db.Query("SELECT id, name, type, url, events, active FROM webhooks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hooks []*WebhookRecord
	for rows.Next() {
		h := &WebhookRecord{}
		var events string
		var active int
		if err := rows.Scan(&h.ID, &h.Name, &h.Type, &h.URL, &events, &active); err != nil {
			continue
		}
		h.Events = events
		h.Active = active == 1
		hooks = append(hooks, h)
	}
	return hooks, nil
}

func (d *Database) SaveWebhook(id, name, whType, url, events string, active bool) error {
	activeInt := 0
	if active {
		activeInt = 1
	}
	_, err := d.db.Exec("INSERT INTO webhooks (id, name, type, url, events, active) VALUES (?, ?, ?, ?, ?, ?)",
		id, name, whType, url, events, activeInt)
	return err
}

func (d *Database) DeleteWebhook(id string) error {
	result, err := d.db.Exec("DELETE FROM webhooks WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("webhook not found")
	}
	return nil
}

type WebhookRecord struct {
	ID     string
	Name   string
	Type   string
	URL    string
	Events string // comma-separated
	Active bool
}

// ===================== Auto Tasks =====================

func (d *Database) GetAutoTasks() ([]*AutoTaskRecord, error) {
	rows, err := d.db.Query("SELECT id, name, task_type, data, params, os_filter, arch_filter, active FROM auto_tasks")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*AutoTaskRecord
	for rows.Next() {
		r := &AutoTaskRecord{}
		var active int
		if err := rows.Scan(&r.ID, &r.Name, &r.TaskType, &r.Data, &r.Params, &r.OSFilter, &r.ArchFilter, &active); err != nil {
			continue
		}
		r.Active = active == 1
		rules = append(rules, r)
	}
	return rules, nil
}

func (d *Database) SaveAutoTask(id, name string, taskType int, data, params, osFilter, archFilter string, active bool) error {
	activeInt := 0
	if active {
		activeInt = 1
	}
	_, err := d.db.Exec("INSERT INTO auto_tasks (id, name, task_type, data, params, os_filter, arch_filter, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id, name, taskType, data, params, osFilter, archFilter, activeInt)
	return err
}

func (d *Database) UpdateAutoTaskActive(id string, active bool) error {
	activeInt := 0
	if active {
		activeInt = 1
	}
	_, err := d.db.Exec("UPDATE auto_tasks SET active = ? WHERE id = ?", activeInt, id)
	return err
}

func (d *Database) DeleteAutoTask(id string) error {
	result, err := d.db.Exec("DELETE FROM auto_tasks WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("auto-task not found")
	}
	return nil
}

type AutoTaskRecord struct {
	ID         string
	Name       string
	TaskType   int
	Data       string
	Params     string
	OSFilter   string
	ArchFilter string
	Active     bool
}

// ===================== Agent Tags =====================

func (d *Database) GetAgentTags(agentID string) ([]string, error) {
	rows, err := d.db.Query("SELECT tag FROM agent_tags WHERE agent_id = ?", agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []string
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			continue
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

func (d *Database) SetAgentTags(agentID string, tags []string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	tx.Exec("DELETE FROM agent_tags WHERE agent_id = ?", agentID)
	for _, tag := range tags {
		tx.Exec("INSERT OR IGNORE INTO agent_tags (agent_id, tag) VALUES (?, ?)", agentID, tag)
	}
	return tx.Commit()
}

func (d *Database) GetAllAgentTags() (map[string][]string, error) {
	rows, err := d.db.Query("SELECT agent_id, tag FROM agent_tags ORDER BY agent_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var agentID, tag string
		if err := rows.Scan(&agentID, &tag); err != nil {
			continue
		}
		result[agentID] = append(result[agentID], tag)
	}
	return result, nil
}

func (d *Database) UpdateAgentNote(agentID, note string) error {
	_, err := d.db.Exec("UPDATE agents SET note = ? WHERE id = ?", note, agentID)
	return err
}

// ===================== Report Queries =====================

// GetTasksByDateRange retrieves all tasks created within the given date range.
func (d *Database) GetTasksByDateRange(from, to time.Time) ([]*TaskRecord, error) {
	rows, err := d.db.Query(
		"SELECT id, agent_id, type, data, params, status, output, created_at, updated_at FROM tasks WHERE created_at >= ? AND created_at <= ? ORDER BY created_at ASC",
		from, to,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*TaskRecord
	for rows.Next() {
		t := &TaskRecord{}
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Type, &t.Data, &t.Params, &t.Status, &t.Output, &t.CreatedAt, &t.UpdatedAt); err != nil {
			continue
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

// GetTaskCountByType returns a map of task type to count of tasks of that type.
func (d *Database) GetTaskCountByType() (map[int]int, error) {
	rows, err := d.db.Query("SELECT type, COUNT(*) FROM tasks GROUP BY type")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[int]int)
	for rows.Next() {
		var taskType, count int
		if err := rows.Scan(&taskType, &count); err != nil {
			continue
		}
		result[taskType] = count
	}
	return result, nil
}

// ===================== Campaigns =====================

type CampaignRecord struct {
	ID          string
	Name        string
	Description string
	Status      string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (d *Database) migrateCampaigns() error {
	schema := `
	CREATE TABLE IF NOT EXISTS campaigns (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		status TEXT DEFAULT 'active',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS campaign_agents (
		campaign_id TEXT NOT NULL,
		agent_id TEXT NOT NULL,
		added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (campaign_id, agent_id)
	);
	`
	_, err := d.db.Exec(schema)
	return err
}

func (d *Database) CreateCampaign(c *CampaignRecord) error {
	_, err := d.db.Exec(
		"INSERT INTO campaigns (id, name, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		c.ID, c.Name, c.Description, c.Status, c.CreatedAt, c.UpdatedAt,
	)
	return err
}

func (d *Database) GetCampaigns() ([]*CampaignRecord, error) {
	rows, err := d.db.Query("SELECT id, name, description, status, created_at, updated_at FROM campaigns ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var campaigns []*CampaignRecord
	for rows.Next() {
		c := &CampaignRecord{}
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Status, &c.CreatedAt, &c.UpdatedAt); err != nil {
			continue
		}
		campaigns = append(campaigns, c)
	}
	return campaigns, nil
}

func (d *Database) GetCampaignByID(id string) (*CampaignRecord, error) {
	c := &CampaignRecord{}
	err := d.db.QueryRow(
		"SELECT id, name, description, status, created_at, updated_at FROM campaigns WHERE id = ?", id,
	).Scan(&c.ID, &c.Name, &c.Description, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (d *Database) UpdateCampaign(id, name, description, status string) error {
	result, err := d.db.Exec(
		"UPDATE campaigns SET name = ?, description = ?, status = ?, updated_at = ? WHERE id = ?",
		name, description, status, time.Now(), id,
	)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("campaign not found")
	}
	return nil
}

func (d *Database) DeleteCampaign(id string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tx.Exec("DELETE FROM campaign_agents WHERE campaign_id = ?", id)
	result, err := tx.Exec("DELETE FROM campaigns WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("campaign not found")
	}
	return tx.Commit()
}

func (d *Database) AddAgentToCampaign(campaignID, agentID string) error {
	_, err := d.db.Exec(
		"INSERT OR IGNORE INTO campaign_agents (campaign_id, agent_id) VALUES (?, ?)",
		campaignID, agentID,
	)
	return err
}

func (d *Database) RemoveAgentFromCampaign(campaignID, agentID string) error {
	_, err := d.db.Exec(
		"DELETE FROM campaign_agents WHERE campaign_id = ? AND agent_id = ?",
		campaignID, agentID,
	)
	return err
}

func (d *Database) GetCampaignAgents(campaignID string) ([]string, error) {
	rows, err := d.db.Query("SELECT agent_id FROM campaign_agents WHERE campaign_id = ?", campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []string
	for rows.Next() {
		var agentID string
		if err := rows.Scan(&agentID); err != nil {
			continue
		}
		agents = append(agents, agentID)
	}
	return agents, nil
}

func (d *Database) GetCampaignAgentCount(campaignID string) (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM campaign_agents WHERE campaign_id = ?", campaignID).Scan(&count)
	return count, err
}
