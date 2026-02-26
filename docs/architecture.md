# RTLC2 Architecture

This document describes the internal architecture of the RTLC2 framework, covering its three-component design, communication protocols, data storage, and extensibility mechanisms.

---

## 1. High-Level Overview

RTLC2 follows a classic three-tier command-and-control architecture:

```
+-------------------+       +----------------------+       +-------------------+
|                   | HTTP/ |                      | REST/ |                   |
|   Agent (C++17)   |<----->|  Team Server (Go)    |<----->|  Web UI (React)   |
|   Target host     | TLS   |  Operator server     | WS    |  Browser client   |
+-------------------+       +----------------------+       +-------------------+
                             |                      |
                             |  SQLite Database      |
                             |  Blob Storage         |
                             +----------------------+
```

- **Agent**: Compiled C++17 implant deployed on target systems. Communicates with the team server through configurable transport channels.
- **Team Server**: Go application that manages agents, listeners, tasks, operators, and all server-side logic. Exposes a REST API and WebSocket endpoint for the web UI.
- **Web UI**: React/TypeScript single-page application served by the team server. Provides the operator interface for managing the entire operation.

---

## 2. Component Details

### 2.1 Agent (C++17)

The agent is a statically compiled binary with all configuration embedded at compile time through CMake definitions. It supports Windows (primary target), Linux, and macOS.

**Key subsystems:**

| Subsystem | Directory | Purpose |
|-----------|-----------|---------|
| Core | `src/core/` | Agent loop, task dispatcher, job manager |
| Transport | `src/transport/` | HTTP, TCP, DNS, DoH, SMB, P2P channels |
| Crypto | `src/crypto/` | AES-256-GCM, XOR, string obfuscation, shellcode encoding |
| Evasion | `src/evasion/` | AMSI, ETW, unhooking, sleep masking, injection, sandbox checks |
| Syscalls | `src/syscalls/` | Hell's Gate / Halo's Gate resolver, assembly gates (x64/x86/ARM64) |
| Execution | `src/execution/` | .NET CLR hosting, reflective PE loader, shellcode executor, PowerShell |
| Modules | `src/modules/` | Shell, filesystem, credentials, tokens, keylogger, lateral movement, persistence, etc. |
| BOF | `src/bof/` | COFF parser, Beacon API implementation, in-memory BOF execution |

**Runtime lifecycle:**

1. `main()` reads compile-time config, creates `Agent` instance
2. Agent gathers system information (`SystemInfo`)
3. Agent creates transport via factory (`CreateTransport()`)
4. Agent registers with the team server
5. Agent enters main loop: sleep -> check-in -> execute tasks -> report results

### 2.2 Team Server (Go)

The team server is the central hub. It coordinates listeners, manages agent state, queues tasks, stores data, and serves the web UI.

**Internal packages:**

| Package | Purpose |
|---------|---------|
| `config` | YAML configuration loading and validation |
| `crypto` | AES-256-GCM cipher for agent communication |
| `database` | SQLite database (agents, tasks, listeners, operators, credentials, events, campaigns) |
| `agent` | Agent manager: registration, check-in processing, task queuing |
| `listener` | Listener manager: HTTP/HTTPS, TCP, SMB, DNS listeners with malleable profile support |
| `server` | HTTP REST API, WebSocket hub, chat, webhooks, auto-tasks, cradles, hosted files, reports, campaigns, audit, payload generation, BOF API, rate limiting |
| `storage` | Blob store for screenshots, downloads, and other binary data |

### 2.3 Web UI (React/TypeScript)

A single-page application built with React 19, TypeScript 5.9, Vite 7, and Zustand 5 for state management. The team server serves the compiled `web/dist` directory as static files with SPA routing support.

---

## 3. Communication Flow

### 3.1 Agent Registration

When an agent starts for the first time, it registers with the team server:

```
Agent                          Listener (Team Server)
  |                                  |
  |  POST /register                  |
  |  Body: AES-GCM(master_key, {     |
  |    hostname, username, os, arch,  |
  |    process_name, pid, internal_ip,|
  |    integrity                      |
  |  })                              |
  |--------------------------------->|
  |                                  |  - Decrypt with master key
  |                                  |  - Generate agent_id (8 chars)
  |                                  |  - Generate session_key (32 bytes)
  |                                  |  - Store agent in database
  |  AES-GCM(master_key, {           |
  |    agent_id, session_key         |
  |  })                              |
  |<---------------------------------|
  |                                  |
  |  Agent stores agent_id +         |
  |  session_key for future use      |
```

**Key points:**
- The master AES key is embedded in the agent at compile time and configured in `teamserver.yaml`
- On first run, if `aes_key` is empty, the server auto-generates one and displays it
- The session key is unique per agent and used for all subsequent communication

### 3.2 Agent Check-In

After registration, the agent periodically checks in to retrieve pending tasks and deliver results:

```
Agent                          Listener (Team Server)
  |                                  |
  |  POST /checkin                   |
  |  Body: agent_id (8 bytes) ||     |
  |        AES-GCM(session_key, {    |
  |          results: [...],         |
  |          sysinfo_update: {...}   |
  |        })                        |
  |--------------------------------->|
  |                                  |  - Look up agent by ID
  |                                  |  - Decrypt with session key
  |                                  |  - Process task results
  |                                  |  - Update last_seen timestamp
  |                                  |  - Fetch pending tasks
  |  AES-GCM(session_key, {          |
  |    tasks: [                      |
  |      {task_id, type, data, params}|
  |    ]                             |
  |  })                              |
  |<---------------------------------|
  |                                  |
  |  Agent executes tasks locally    |
  |  Results queued for next check-in|
```

**Wire format:** The first 8 bytes of the check-in body are the plaintext `agent_id` (used to look up the session key). The remainder is an AES-256-GCM encrypted JSON payload.

### 3.3 Web UI Communication

The web UI communicates with the team server over two channels:

1. **REST API** (`/api/v1/*`): All CRUD operations use JSON over HTTP with bearer token authentication.
2. **WebSocket** (`/api/v1/ws/events`): Real-time event streaming for live updates (agent check-ins, task completions, operator presence, chat messages).

```
Browser (Web UI)              Team Server
  |                                |
  |  POST /api/v1/auth/login       |
  |  {username, password}          |
  |------------------------------->|
  |  {token, operator}             |
  |<-------------------------------|
  |                                |
  |  WS /api/v1/ws/events?token=.. |
  |<==============================>|
  |                                |
  |  GET /api/v1/agents            |
  |  Authorization: <token>        |
  |------------------------------->|
  |  {agents: [...]}               |
  |<-------------------------------|
```

---

## 4. Encryption

### 4.1 Transport Encryption

All agent-server communication is encrypted with **AES-256-GCM**:

- **Key size**: 256 bits (32 bytes), represented as 64 hex characters
- **Nonce**: 12 bytes, randomly generated per message
- **Authentication tag**: 16 bytes, appended to ciphertext
- **Wire format**: `nonce (12 bytes) || ciphertext || tag (16 bytes)`

Two keys are used:

| Key | Purpose | Generation |
|-----|---------|------------|
| Master key | Registration encryption | Auto-generated on first server run, or set in config |
| Session key | All post-registration communication | Generated per agent during registration |

### 4.2 String Obfuscation

Compile-time string obfuscation uses XOR with a random seed generated during the CMake configure step. The `RTLC2_OBFSTR_SEED` variable controls the XOR key. Sensitive strings (API names, C2 URLs, config values) are obfuscated in the binary and decrypted at runtime.

### 4.3 API Hashing

Win32 API function names are resolved at runtime using the **DJB2 hash** algorithm combined with **PEB module resolution**. This avoids storing API names in the binary's import table.

---

## 5. Database Schema

The team server uses **SQLite** with WAL journal mode for concurrent access. The database file is stored at the path specified in `teamserver.yaml` (default: `data/rtlc2.db`).

### Core Tables

| Table | Key Fields | Purpose |
|-------|-----------|---------|
| `agents` | id, hostname, username, os, arch, process_name, pid, internal_ip, external_ip, sleep_interval, jitter, integrity, alive, note, aes_key, first_seen, last_seen, listener_id | Active and historical agent records |
| `tasks` | id, agent_id, type, data, params (JSON), status (0=pending, 1=running, 2=complete, 3=error), output, created_at, updated_at | Task queue and results |
| `listeners` | id, name, protocol, bind_host, bind_port, config (JSON), active, started_at | Listener configuration and state |
| `operators` | id, username, password_hash, role, last_login | Operator accounts |
| `credentials` | id, type, username, domain, value, source_agent_id, source_agent_hostname, note, timestamp | Harvested credentials |
| `events` / `audit_log` | operator_id, action, target_id, details, timestamp | Audit trail for all operator actions |
| `blobs` | id, category, agent_id, filename, size, timestamp | Binary object metadata (data stored on disk) |
| `campaigns` | id, name, description, status, agents (JSON), created_at, updated_at | Operation grouping |
| `agent_tags` | agent_id, tag | Agent tagging for organization |
| `chat_messages` | id, operator, text, timestamp | Team chat messages |
| `webhooks` | id, name, type, url, events (JSON), active | Webhook configurations |
| `auto_tasks` | id, name, task_type, data, params (JSON), os_filter, arch_filter, active | Automatic task rules |
| `hosted_files` | id, filename, content_type, size, download_count, max_downloads, expires_at, url, created_at | Files hosted for download |

---

## 6. WebSocket Hub

The WebSocket hub is the real-time event backbone. It maintains a set of connected clients and broadcasts events to all of them.

### Architecture

```
                    +--------+
                    | WSHub  |
                    +--------+
                   /    |     \
                  /     |      \
          +------+ +------+ +------+
          |Client| |Client| |Client|
          +------+ +------+ +------+
            Op1      Op2      Op3
```

Each WebSocket client runs two goroutines:
- **ReadPump**: Reads incoming messages (auth, subscriptions), handles connection lifecycle, sends pings
- **WritePump**: Writes outbound events from the hub's broadcast channel, batches queued messages

### Event Types

| Event | Trigger |
|-------|---------|
| `agent_new` | New agent registers |
| `agent_dead` | Agent fails to check in within timeout |
| `agent_checkin` | Agent checks in |
| `task_complete` | Task execution finishes |
| `task_new` | New task queued |
| `listener_new` | Listener created |
| `listener_stopped` | Listener stopped |
| `operator_join` | Operator authenticates on WebSocket |
| `operator_leave` | Operator WebSocket disconnects |
| `chat_message` | Team chat message sent |

### Connection Parameters

| Parameter | Value |
|-----------|-------|
| Write timeout | 10 seconds |
| Pong timeout | 60 seconds |
| Ping interval | 54 seconds |
| Max message size | 4096 bytes |
| Send buffer per client | 256 messages |
| Hub broadcast buffer | 256 messages |

---

## 7. Plugin System

RTLC2 supports a file-based plugin system. Plugins are JSON metadata files stored in the `plugins/` directory. The server reads plugin metadata and exposes it through the API.

**Built-in plugins:**

| Plugin | Description |
|--------|-------------|
| ImgPayload | LSB steganography: embed shellcode into PNG/BMP images. Server-side embed and extract operations. |

**Plugin API:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/plugins` | GET | List all loaded plugins |
| `/api/v1/plugins/load` | POST | Upload and register a new plugin |
| `/api/v1/plugins/imgpayload/embed` | POST | Embed shellcode into an image |
| `/api/v1/plugins/imgpayload/extract` | POST | Extract shellcode from a steganized image |

---

## 8. BOF Loading Architecture

The agent includes a full COFF (Common Object File Format) parser for executing Beacon Object Files in-process.

### COFF Parser

The loader processes the following COFF structures:
- **COFF Header**: Machine type, section count, symbol table pointer
- **Section Headers**: .text, .data, .rdata, .bss sections with relocations
- **Symbol Table**: Function and variable symbols with string table
- **Relocations**: Section-relative relocations patched at load time

### Execution Flow

1. Team server sends BOF `.o` file as task data (type 7)
2. Agent's COFF parser allocates RWX memory for each section
3. Sections are loaded and relocated
4. External symbol references are resolved against 58 Beacon API functions
5. The entry function (default: `go`) is called with packed arguments
6. Output is captured via `BeaconOutput`/`BeaconPrintf` and sent back as task result
7. Allocated memory is freed

### Beacon API Compatibility

The agent implements 58 Beacon API functions for Cobalt Strike BOF compatibility:

| Category | Functions |
|----------|-----------|
| Output | `BeaconOutput`, `BeaconPrintf` |
| Data parsing | `BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`, `BeaconDataExtract`, `BeaconDataLength` |
| Token | `BeaconUseToken`, `BeaconRevertToken` |
| Utility | `BeaconIsAdmin`, `BeaconGetSpawnTo`, `BeaconCleanupProcess` |
| Format | `BeaconFormatAlloc`, `BeaconFormatReset`, `BeaconFormatFree`, `BeaconFormatAppend`, `BeaconFormatPrintf`, `BeaconFormatToString`, `BeaconFormatInt` |
| Injection | `BeaconSpawnTemporaryProcess`, `BeaconInjectProcess`, `BeaconInjectTemporaryProcess` |
| Helper | `toWideChar` |

The argument packing format is Cobalt Strike compatible. The `ArgPacker` class provides methods: `AddShort`, `AddInt`, `AddString`, `AddWString`, `AddData`.

---

## 9. Middleware Stack

The HTTP API server applies middleware in the following order (outermost first):

```
Incoming Request
    |
    v
  CORS Middleware          -- Adds Access-Control headers for SPA
    |
    v
  Rate Limiter             -- Token bucket algorithm (configurable rate_limit)
    |
    v
  Audit Middleware         -- Logs all API actions to audit_log table
    |
    v
  Route Handler
    |
    +-- requireAuth()      -- Validates bearer token
    |
    +-- requireRole()      -- Checks operator role (admin > operator > viewer)
    |
    v
  Business Logic
```

**Token lifecycle:**
- Tokens are UUID v4 strings generated on login
- Stored in-memory (map protected by RWMutex)
- Expire after 8 hours (background cleanup every 5 minutes)
- Revoked on logout or operator deletion

---

## 10. Security Model

### Authentication
- Operator passwords are hashed with **bcrypt** (default cost)
- Login returns a UUID token valid for 8 hours
- All API endpoints require the token in the `Authorization` header

### Authorization (RBAC)
Three roles with hierarchical permissions:

| Role | Capabilities |
|------|-------------|
| `admin` | Full access: manage operators, listeners, agents, audit log, all operations |
| `operator` | Interact with agents, create listeners, queue tasks, manage webhooks/auto-tasks |
| `viewer` | Read-only access to agents, tasks, events, credentials |

### Transport Security
- TLS optional but recommended (set `tls: true` in config with cert/key files)
- WebSocket origin validation restricts browser connections to localhost by default
- Rate limiting prevents brute-force attacks (configurable requests per minute)
