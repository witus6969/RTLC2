# RTLC2 Team Server Documentation

The RTLC2 team server is a Go application that serves as the central command-and-control hub. It manages listeners, processes agent communications, queues tasks, stores operational data, and provides both a REST API and WebSocket interface for the web UI.

---

## 1. Configuration

The server is configured via a YAML file (default: `configs/teamserver.yaml`).

### Configuration Schema

```yaml
server:
  host: "0.0.0.0"          # Bind address
  port: 54321               # HTTP API + Web UI port
  tls: false                # Enable TLS
  cert_file: ""             # Path to TLS certificate
  key_file: ""              # Path to TLS private key
  rate_limit: 100           # Max requests per minute per IP

database:
  driver: "sqlite"          # Database driver (only sqlite supported)
  path: "data/rtlc2.db"    # SQLite database file path

crypto:
  aes_key: ""               # AES-256 master key (64 hex chars). Auto-generated if empty.
  xor_key: ""               # XOR key for lightweight obfuscation
  server_cert: ""           # Optional: server certificate for agent TLS verification
  server_key: ""            # Optional: server key

logging:
  level: "info"             # Log level: debug, info, warn, error
  file: "data/rtlc2.log"   # Log file path. Empty = terminal only.

operators:
  - username: "admin"       # Operator username
    password: "changeme123" # Plaintext password (hashed with bcrypt on first run)
    role: "admin"           # Role: admin, operator, viewer
```

### Configuration Validation

The server validates configuration on startup:

- Server port must be 1-65535
- TLS requires both `cert_file` and `key_file` to be set
- AES key, if provided, must be exactly 64 hex characters (32 bytes)
- Database path must not be empty

### Auto-Generation

On first run with an empty `aes_key`, the server:

1. Generates a random 32-byte AES key
2. Displays the key in the terminal
3. Creates the SQLite database and all tables
4. Hashes operator passwords with bcrypt and creates operator records
5. If any operator has an empty password, generates a random one and displays it

---

## 2. Role-Based Access Control (RBAC)

Three roles with hierarchical permissions:

### Role Hierarchy

```
admin > operator > viewer
```

The `admin` role implicitly has all permissions. The `requireRole` middleware checks if the operator's role is in the allowed set, with admin always passing.

### Permission Matrix

| Action | admin | operator | viewer |
|--------|:-----:|:--------:|:------:|
| View agents, tasks, events | Yes | Yes | Yes |
| View credentials, profiles, BOFs | Yes | Yes | Yes |
| Queue tasks | Yes | Yes | No |
| Create/stop listeners | Yes | Yes | No |
| Manage webhooks | Yes | Yes | No |
| Manage auto-tasks | Yes | Yes | No |
| Manage campaigns | Yes | Yes | No |
| Generate payloads | Yes | Yes | Yes |
| Manage operators | Yes | No | No |
| View audit log | Yes | No | No |
| Manage operator sessions | Yes | No | No |

---

## 3. REST API Reference

All API endpoints are prefixed with `/api/v1/`. Responses are JSON. Authentication is via a bearer token in the `Authorization` header (obtained from login).

### 3.1 Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/auth/login` | None | Authenticate and receive a token |
| POST | `/api/v1/auth/logout` | Required | Invalidate the current token |

**Login request:**
```json
{ "username": "admin", "password": "changeme123" }
```

**Login response:**
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "operator": { "id": "abc12345", "username": "admin", "role": "admin" }
}
```

### 3.2 Agents

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/agents` | Required | List all agents |
| POST | `/api/v1/agents/remove` | Required | Remove an agent by ID |
| GET | `/api/v1/agents/{id}` | Required | Get agent details |
| GET | `/api/v1/agents/{id}/tasks` | Required | List tasks for an agent |
| GET | `/api/v1/agents/{id}/tags` | Required | Get agent tags |
| PUT | `/api/v1/agents/{id}/tags` | Required | Set agent tags |
| PUT | `/api/v1/agents/{id}/note` | Required | Update agent note |
| GET | `/api/v1/agents/tags` | Required | Get all agent tags across all agents |

**Agent object:**
```json
{
  "id": "a1b2c3d4",
  "hostname": "WORKSTATION-01",
  "username": "CORP\\jsmith",
  "os": "windows",
  "arch": "x64",
  "process_name": "RuntimeBroker.exe",
  "pid": 4832,
  "internal_ip": "10.0.0.15",
  "external_ip": "203.0.113.50",
  "sleep_interval": 5,
  "jitter": 10,
  "first_seen": "2025-03-15 14:30:00",
  "last_seen": "2025-03-15 14:35:12",
  "listener_id": "lst-001",
  "integrity": "high",
  "alive": true,
  "note": "Domain controller"
}
```

### 3.3 Tasks

| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| POST | `/api/v1/tasks` | Required | admin, operator | Queue a new task |
| GET | `/api/v1/tasks/catalog` | Required | Any | Get task type catalog |
| GET | `/api/v1/tasks/{id}` | Required | Any | Get task details and output |
| DELETE | `/api/v1/tasks/{id}` | Required | Any | Cancel a pending task |

**Task request:**
```json
{
  "agent_id": "a1b2c3d4",
  "type": 1,
  "data": "d2hvYW1p",
  "params": {}
}
```

**Task status codes:** 0=pending, 1=running, 2=complete, 3=error

### 3.4 Listeners

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/listeners` | Required | List all active listeners |
| POST | `/api/v1/listeners` | Required | Create a new listener |
| POST | `/api/v1/listeners/stop` | Required | Stop a listener by ID |
| GET | `/api/v1/listeners/{id}` | Required | Get listener details |
| PUT | `/api/v1/listeners/{id}` | Required | Update (restart) a listener |
| DELETE | `/api/v1/listeners/{id}` | Required | Stop and delete a listener |

**Listener protocols:** 0=HTTP, 1=HTTPS, 2=TCP, 3=SMB, 4=DNS

**Create listener request:**
```json
{
  "name": "HTTPS Listener",
  "protocol": 1,
  "bind_host": "0.0.0.0",
  "bind_port": 443,
  "secure": true,
  "cert_path": "/path/to/cert.pem",
  "key_path": "/path/to/key.pem"
}
```

### 3.5 Payloads

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/payloads/generate` | Required | Generate an agent payload |
| POST | `/api/v1/payloads/shellcode` | Required | Generate shellcode |
| GET | `/api/v1/payloads/formats` | Required | List available payload formats |

**Supported platforms:** windows, linux, macos

**Supported architectures:** x64, x86, arm64

**Payload formats:** exe, dll, shellcode, loader

### 3.6 BOFs

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/bofs` | Required | List all available BOFs with metadata |
| POST | `/api/v1/bofs/execute` | Required | Execute a BOF on a target agent |
| POST | `/api/v1/bofs/upload` | Required | Upload a custom BOF |

**Execute BOF request:**
```json
{
  "agent_id": "a1b2c3d4",
  "bof_name": "Port Scanner",
  "category": "recon",
  "args": { "target": "10.0.0.0/24", "ports": "445,3389,22", "timeout": "1000" }
}
```

### 3.7 Profiles

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/profiles` | Required | List all malleable profiles |
| POST | `/api/v1/profiles` | Required | Create/upload a new profile |
| POST | `/api/v1/profiles/upload` | Required | Upload a new profile (alias) |
| GET | `/api/v1/profiles/{name}` | Required | Get profile by name |
| DELETE | `/api/v1/profiles/{name}` | Required | Delete a custom profile |

### 3.8 Operators

| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| GET | `/api/v1/operators` | Required | admin | List all operators |
| POST | `/api/v1/operators` | Required | admin | Create a new operator |
| GET | `/api/v1/operators/{id}` | Required | admin | Get operator details |
| PUT | `/api/v1/operators/{id}` | Required | admin | Update operator password/role |
| DELETE | `/api/v1/operators/{id}` | Required | admin | Delete an operator |
| GET | `/api/v1/operators/sessions` | Required | admin | List active sessions |
| DELETE | `/api/v1/operators/sessions` | Required | admin | Revoke a session token |

**Create operator request:**
```json
{ "username": "operator1", "password": "SecureP@ss", "role": "operator" }
```

### 3.9 Credentials

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/credentials` | Required | List all credentials |
| POST | `/api/v1/credentials` | Required | Add a credential manually |
| DELETE | `/api/v1/credentials/{id}` | Required | Delete a credential |

**Credential types:** `ntlm`, `plaintext`, `ticket`, `certificate`, `ssh_key`

### 3.10 Events and Audit

| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| GET | `/api/v1/events` | Required | Any | Get recent events (query param: `limit`) |
| GET | `/api/v1/audit` | Required | admin | Query audit log (params: `operator`, `action`, `since`, `limit`, `offset`) |

### 3.11 WebSocket

| Endpoint | Auth | Description |
|----------|------|-------------|
| `/api/v1/ws/events` | Token (query param or Authorization header) | Real-time event stream |

Connect via WebSocket with the auth token:
```
ws://server:54321/api/v1/ws/events?token=<auth-token>
```

After connection, send an auth message to identify the operator:
```json
{ "type": "auth", "operator_id": "abc12345", "username": "admin" }
```

### 3.12 Chat

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/chat/messages` | Required | Get recent chat messages |
| POST | `/api/v1/chat/messages` | Required | Send a chat message |

### 3.13 Webhooks

| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| GET | `/api/v1/webhooks` | Required | admin, operator | List webhooks |
| POST | `/api/v1/webhooks` | Required | admin, operator | Create a webhook |
| PUT | `/api/v1/webhooks/{id}` | Required | admin, operator | Update a webhook |
| DELETE | `/api/v1/webhooks/{id}` | Required | admin, operator | Delete a webhook |

**Webhook types:** `slack`, `discord`, `telegram`, `generic`

**Subscribable events:** `agent_new`, `agent_dead`, `task_complete`, `credential_found`, `listener_new`, `listener_stopped`

### 3.14 Auto-Tasks

| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| GET | `/api/v1/autotasks` | Required | admin, operator | List auto-task rules |
| POST | `/api/v1/autotasks` | Required | admin, operator | Create an auto-task rule |
| PUT | `/api/v1/autotasks/{id}` | Required | admin, operator | Update a rule |
| DELETE | `/api/v1/autotasks/{id}` | Required | admin, operator | Delete a rule |

Auto-tasks automatically execute tasks on newly registered agents that match OS and architecture filters.

### 3.15 Download Cradles

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/cradles/generate` | Required | Generate a download cradle |
| GET | `/api/v1/cradles/formats` | Required | List available cradle formats |

**12 cradle formats:**

| Format | Platform | Description |
|--------|----------|-------------|
| `powershell` | Windows | WebClient download + execute (or IEX for scripts). Proxy support. |
| `powershell_iwr` | Windows | Invoke-WebRequest (PowerShell 3.0+) |
| `certutil` | Windows | `certutil -urlcache -split -f` LOLBin |
| `curl` | Linux/macOS | `curl -k -s -o` with proxy support |
| `wget` | Linux/macOS | `wget --no-check-certificate` with proxy support |
| `bitsadmin` | Windows | BITS background transfer |
| `python` | Cross-platform | Python 3 `urllib.request` download + execute |
| `mshta` | Windows | mshta LOLBin launching PowerShell |
| `regsvr32` | Windows | regsvr32 scriptlet execution |
| `rundll32` | Windows | rundll32 with JavaScript |
| `bash` | Linux | curl download + background execute |
| `perl` | Linux/macOS | LWP::Simple download + execute |

### 3.16 Hosted Files

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/hosted` | Required | List hosted files |
| POST | `/api/v1/hosted` | Required | Upload a file for hosting |
| DELETE | `/api/v1/hosted/{id}` | Required | Remove a hosted file |

Hosted files support max download limits and expiration times.

### 3.17 Blob Storage

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/blobs` | Required | List blobs (query: `category`, `agent_id`) |
| GET | `/api/v1/blobs/{id}` | Required | Download a blob (binary) |
| DELETE | `/api/v1/blobs/{id}` | Required | Delete a blob |

### 3.18 Campaigns

| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| GET | `/api/v1/campaigns` | Required | Any | List campaigns |
| POST | `/api/v1/campaigns` | Required | admin, operator | Create a campaign |
| GET | `/api/v1/campaigns/{id}` | Required | admin, operator | Get campaign details |
| PUT | `/api/v1/campaigns/{id}` | Required | admin, operator | Update a campaign |
| DELETE | `/api/v1/campaigns/{id}` | Required | admin, operator | Delete a campaign |

### 3.19 Reports

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/reports/templates` | Required | List report templates |
| POST | `/api/v1/reports/generate` | Required | Generate a report |

### 3.20 Plugins

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/plugins` | Required | List loaded plugins |
| POST | `/api/v1/plugins/load` | Required | Upload and load a plugin |
| POST | `/api/v1/plugins/imgpayload/embed` | Required | Embed shellcode into image (LSB steganography) |
| POST | `/api/v1/plugins/imgpayload/extract` | Required | Extract shellcode from steganized image |

### 3.21 Server Info

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/server/info` | Required | Server version, hostname, OS, counts |

---

## 4. WebSocket Events

Events are broadcast to all connected WebSocket clients as JSON:

```json
{
  "type": "agent_checkin",
  "data": { "agent_id": "a1b2c3d4", "hostname": "WORKSTATION-01" },
  "timestamp": "2025-03-15T14:35:12Z"
}
```

| Event Type | Data | Trigger |
|------------|------|---------|
| `agent_new` | Agent object | New agent registers |
| `agent_dead` | `{agent_id, hostname}` | Agent times out |
| `agent_checkin` | `{agent_id}` | Agent checks in |
| `task_complete` | Task result object | Task finishes |
| `task_new` | `{task_id, agent_id, type}` | Task queued |
| `listener_new` | Listener object | Listener created |
| `listener_stopped` | `{listener_id}` | Listener stopped |
| `operator_join` | `{operator_id, username}` | Operator connects to WebSocket |
| `operator_leave` | `{operator_id, username}` | Operator disconnects |
| `chat_message` | Chat message object | Team chat message |
| `credential_added` | Credential object | New credential stored |

---

## 5. Webhook Notifications

The webhook service sends HTTP POST requests to configured endpoints when subscribed events occur.

### Webhook Types

| Type | Payload Format |
|------|---------------|
| `slack` | Slack-compatible JSON: `{"text": "...", "attachments": [...]}` |
| `discord` | Discord-compatible JSON: `{"content": "...", "embeds": [...]}` |
| `telegram` | Telegram Bot API: `{"chat_id": "...", "text": "..."}` |
| `generic` | Raw JSON event: `{"event": "...", "data": {...}, "timestamp": "..."}` |

---

## 6. Payload Generation

The server can generate agent payloads via the API or web UI. The generation pipeline:

1. Resolve the target listener's connection details
2. Apply compile-time agent settings (host, port, key, sleep, jitter)
3. Apply evasion options from the payload configuration
4. Invoke CMake/compiler to build the agent
5. Return the compiled binary (or shellcode extract)

### Evasion Categories

The payload generator supports four evasion categories, each with multiple toggleable techniques:

| Category | Techniques |
|----------|-----------|
| Execution | In-memory, no disk, staged chunks, delay exec, env keying, time stomp, polymorphic, metamorphic, JIT compile, thread pool |
| AppLocker bypass | DLL sideload, MSBuild exec, InstallUtil exec, RegSvr exec, RunDLL32 exec, MShta, CMSTP, whitelist bypass, trusted folder, alternate data stream |
| Trusted path | System dir, Program Files, Windows Apps, temp signed, Recycle Bin, WinSxS, Driver Store, Global Assembly, COM surrogate, Print Spooler |
| Memory loaders | Reflective DLL, manual map, module overload, transacted hollow, ghostly hollow, phantom DLL, doppelganging, herpaderping, process hollow, memory module |

---

## 7. Go Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/google/uuid` | v1.6.0 | UUID generation for tokens, IDs |
| `github.com/gorilla/websocket` | v1.5.3 | WebSocket server implementation |
| `github.com/mattn/go-sqlite3` | v1.14.22 | SQLite driver (CGO) |
| `github.com/miekg/dns` | v1.1.72 | DNS listener and record handling |
| `github.com/sirupsen/logrus` | v1.9.3 | Structured logging |
| `golang.org/x/crypto` | v0.46.0 | bcrypt password hashing |
| `gopkg.in/yaml.v3` | v3.0.1 | YAML configuration parsing |

---

## 8. Internal Package Structure

```
teamserver/
  cmd/teamserver/
    main.go                  Entry point, CLI flags, initialization

  internal/
    config/
      config.go              Config structs, loader, validation, defaults

    crypto/
      crypto.go              AES-256-GCM cipher implementation

    database/
      database.go            SQLite schema, migrations, CRUD operations

    agent/
      manager.go             Agent lifecycle: registration, check-in, task queue

    listener/
      listener.go            Listener interface and manager
      http.go                HTTP/HTTPS listener
      tcp.go                 TCP raw socket listener
      smb.go                 SMB named pipe listener
      dns.go                 DNS listener
      profiles.go            Malleable profile manager

    server/
      server.go              Server orchestration and startup
      http_api.go            REST API routes, middleware, handlers
      websocket.go           WebSocket hub, client read/write pumps
      bof_api.go             BOF listing, execution, upload endpoints
      payload.go             Payload generation logic, evasion structs
      chat.go                Operator team chat service
      webhooks.go            Webhook management and notification dispatch
      autotasks.go           Auto-task rule engine
      cradles.go             Download cradle generation (12 formats)
      hosted.go              Hosted file service
      ratelimit.go           Token bucket rate limiter
      audit.go               Audit log query handler
      reports.go             Report template and generation service
      campaigns.go           Campaign CRUD

    storage/
      blob.go                Blob store (disk-based with metadata in SQLite)
```

---

## 9. Server Startup Sequence

1. Parse command-line flags (`-config` path)
2. Load and validate YAML configuration
3. Initialize AES cipher (auto-generate key if empty)
4. Open SQLite database, run migrations
5. Create and provision operators (hash passwords, skip existing)
6. Initialize agent manager
7. Initialize listener manager and profile manager (load profiles from `profiles/` directory)
8. Initialize services: WebSocket hub, chat, webhooks, auto-tasks, hosted files, blob store
9. Start the WebSocket hub goroutine
10. Start the HTTP API server with middleware stack
11. Begin serving (TLS or plain HTTP based on config)
12. Log startup banner with version, bind address, operator count
