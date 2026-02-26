# RTLC2 Deployment Guide

This guide covers installing, building, configuring, and running the RTLC2 framework.

---

## 1. Prerequisites

### Required Software

| Component | Minimum Version | Purpose |
|-----------|----------------|---------|
| Go | 1.24+ | Team server compilation |
| CMake | 3.16+ | Agent build system |
| Node.js | 18+ | Web UI compilation |
| GCC or Clang | C++17 support | Agent compilation |
| OpenSSL | 1.1+ | Agent TLS and crypto (Linux/macOS) |
| libcurl | 7.x+ | Agent HTTP transport (Linux/macOS) |
| SQLite3 | 3.x | Database (bundled via Go driver, but headers needed for CGO) |

### Optional Software

| Component | Purpose |
|-----------|---------|
| x86_64-w64-mingw32 | Windows agent cross-compilation |
| Python 3 | Helper scripts |
| nmap | Deployment verification |

---

## 2. Kali Linux Setup

A setup script is provided for Kali Linux:

```bash
sudo bash scripts/setup_kali.sh
```

This script installs all required packages including Go, CMake, Node.js, MinGW cross-compiler, OpenSSL development headers, and libcurl.

---

## 3. Manual Build

### Step 1: Install Go Dependencies

```bash
make setup
```

This runs `go mod tidy` in the teamserver directory to download and verify all Go module dependencies.

### Step 2: Build the Team Server

```bash
make teamserver
```

Output: `build/rtlc2-teamserver`

The team server is built with CGO enabled (required for the SQLite driver). Build flags include `-s -w` to strip debug information and reduce binary size.

### Step 3: Build the Web UI

```bash
make web
```

This runs `npm install` followed by `npm run build` (which first type-checks with `tsc -b`, then bundles with Vite). Output is written to `web/dist/`.

### Step 4: Build the Agent (Native)

```bash
make agent
```

This invokes CMake to build the agent for the host platform. The agent binary is placed in `build/rtlc2-agent`.

### Step 5: Cross-Compile Agent for Windows

```bash
make agent-windows
```

Requires the `x86_64-w64-mingw32` toolchain. Uses `x86_64-w64-mingw32-cmake` to configure and build a statically linked Windows executable.

### All-in-One Build

```bash
make all        # Builds teamserver + web UI
make install    # Builds everything and installs to /opt/RTLC2
```

### Clean Build Artifacts

```bash
make clean
```

---

## 4. Configuration

### Edit the Configuration File

```bash
vi configs/teamserver.yaml
```

### Minimal Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 54321

database:
  path: "data/rtlc2.db"

operators:
  - username: "admin"
    password: "YourStrongPassword"
    role: "admin"
```

### Full Configuration Reference

```yaml
server:
  host: "0.0.0.0"          # Bind address (0.0.0.0 = all interfaces)
  port: 54321               # API + Web UI port
  tls: false                # Enable TLS
  cert_file: ""             # TLS certificate path
  key_file: ""              # TLS private key path
  rate_limit: 100           # Max API requests per minute per IP

database:
  driver: "sqlite"
  path: "data/rtlc2.db"    # SQLite database file

crypto:
  aes_key: ""               # 64 hex chars (auto-generated if empty)
  xor_key: ""               # XOR key for lightweight obfuscation

logging:
  level: "info"             # debug, info, warn, error
  file: "data/rtlc2.log"   # Empty = terminal only

operators:
  - username: "admin"
    password: "YourStrongPassword"
    role: "admin"

  - username: "operator1"
    password: "OperatorPass!"
    role: "operator"

  - username: "viewer1"
    password: ""            # Empty = auto-generated, shown at startup
    role: "viewer"
```

---

## 5. Running the Team Server

### Start

```bash
./build/rtlc2-teamserver -config configs/teamserver.yaml
```

### First Run Behavior

On first run, the server:

1. Creates the `data/` directory if it does not exist
2. Creates the SQLite database and runs schema migrations
3. If `aes_key` is empty in the config, generates a random 32-byte key and prints it:
   ```
   [*] Generated AES key: a1b2c3d4e5f6...
   [*] Copy this key to your config file and use it when building agents
   ```
4. Hashes operator passwords with bcrypt and creates operator records
5. If any operator has an empty password, generates a random one and displays it:
   ```
   [*] Generated password for viewer1: xK9#mP2$
   ```
6. Starts the HTTP API and begins listening

### Verify

Open a browser and navigate to:
```
http://<server-ip>:54321
```

Log in with the credentials defined in the configuration file.

### Verify from CLI

```bash
curl -s http://localhost:54321/api/v1/server/info | python3 -m json.tool
```

---

## 6. TLS Setup

### Generate a Self-Signed Certificate

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=rtlc2-server"
```

### Configure TLS

```yaml
server:
  tls: true
  cert_file: "/path/to/server.crt"
  key_file: "/path/to/server.key"
```

### Using Let's Encrypt

For production deployments with a domain name:

```bash
certbot certonly --standalone -d c2.yourdomain.com
```

Then set:
```yaml
server:
  tls: true
  cert_file: "/etc/letsencrypt/live/c2.yourdomain.com/fullchain.pem"
  key_file: "/etc/letsencrypt/live/c2.yourdomain.com/privkey.pem"
```

---

## 7. Agent Building

### Build with Custom Settings

```bash
cd agent
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DRTLC2_C2_HOST="192.168.15.14" \
  -DRTLC2_C2_PORT="443" \
  -DRTLC2_AES_KEY="<your-64-hex-char-key>" \
  -DRTLC2_USE_TLS="1" \
  -DRTLC2_SLEEP_INTERVAL="60" \
  -DRTLC2_JITTER="20" \
  -DRTLC2_TRANSPORT_TYPE="http" \
  -DRTLC2_SYSCALL_METHOD="hells_gate" \
  -DRTLC2_AMSI_PATCH="1" \
  -DRTLC2_ETW_PATCH="1" \
  -DRTLC2_UNHOOK_NTDLL="1" \
  -DRTLC2_SLEEP_MASK="1" \
  -DRTLC2_STACK_SPOOF="1" \
  -DRTLC2_HEAP_ENCRYPT="1"
cmake --build build
```

### Build for Windows (Cross-Compile)

```bash
x86_64-w64-mingw32-cmake -B build-win -DCMAKE_BUILD_TYPE=Release \
  -DRTLC2_C2_HOST="192.168.15.14" \
  -DRTLC2_C2_PORT="443" \
  -DRTLC2_AES_KEY="<key>" \
  -DRTLC2_USE_TLS="1"
cmake --build build-win
```

### Build via Web UI

The web UI payload generator provides a graphical interface:

1. Navigate to the Payload Generator panel
2. Select target OS and architecture
3. Select the listener
4. Configure evasion options
5. Click Generate
6. Download the compiled binary

### Build via Scripts

```bash
# Native agent
./scripts/generate_agent.sh -h 192.168.15.14 -k <aes-key> -p 443 \
  --platform linux --arch x64

# PowerShell stager for Windows
./scripts/generate_powershell.sh
```

---

## 8. Cross-Compilation Reference

### Team Server

| Target | Command |
|--------|---------|
| Native (host OS) | `make teamserver` |
| Linux amd64 | `make teamserver-linux` |

Note: The Linux cross-compile uses `CGO_ENABLED=0`, which disables the SQLite driver. For production Linux deployments, build directly on the target platform with CGO enabled.

### Agent

| Target | Toolchain Required | Command |
|--------|-------------------|---------|
| Native | GCC or Clang | `make agent` |
| Windows x64 | x86_64-w64-mingw32 | `make agent-windows` |
| Windows x86 | i686-w64-mingw32 | Custom cmake invocation |

---

## 9. Deployment Architecture

### Single-Server Deployment

The simplest deployment runs everything on one machine:

```
+---------------------------------+
|  Kali Linux (192.168.15.14)     |
|                                 |
|  rtlc2-teamserver               |
|    Port 54321 (API + Web UI)    |
|    Listener: port 443 (HTTPS)   |
|    Listener: port 53 (DNS)      |
|                                 |
|  data/rtlc2.db                  |
|  data/rtlc2.log                 |
+---------------------------------+
```

### Redirector Deployment

For OPSEC-conscious operations, use redirectors:

```
Target --> Redirector (cloud) --> Team Server (internal)
```

Configure redirectors (Apache/Nginx/socat) to forward traffic to the team server's listener port.

---

## 10. Security Hardening

### Change Default Passwords

Always change the default admin password before deployment:

```yaml
operators:
  - username: "admin"
    password: "UniqueStrongPassword!2025"
    role: "admin"
```

### Enable TLS

Always use TLS in production:

```yaml
server:
  tls: true
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
```

### Configure Rate Limiting

Adjust the rate limit to prevent brute-force attacks:

```yaml
server:
  rate_limit: 30    # Requests per minute per IP
```

### Use Non-Default Ports

Change both the API port and listener ports from their defaults:

```yaml
server:
  port: 8443        # Instead of 54321
```

### Restrict Network Access

Use firewall rules to limit access to the API port:

```bash
# Allow only your operator IP
iptables -A INPUT -p tcp --dport 54321 -s 10.0.0.5 -j ACCEPT
iptables -A INPUT -p tcp --dport 54321 -j DROP
```

### Agent AES Key

The AES key is the most critical secret. If compromised, an attacker can decrypt all agent communications.

- Copy the auto-generated key to the config file immediately
- Use the same key when building agents
- Never transmit the key over insecure channels
- Rotate keys by rebuilding agents with a new key

### Backup

Regularly back up the database and configuration:

```bash
cp data/rtlc2.db data/rtlc2.db.bak
cp configs/teamserver.yaml configs/teamserver.yaml.bak
```

---

## 11. Troubleshooting

### Server Fails to Start

| Error | Cause | Fix |
|-------|-------|-----|
| `address already in use` | Port is in use by another process | Change the port or stop the conflicting process |
| `config validation failed: invalid server port` | Port out of range | Set port between 1 and 65535 |
| `TLS enabled but cert_file is empty` | TLS enabled without certificates | Provide cert_file and key_file, or disable TLS |

### Agent Does Not Connect

| Symptom | Possible Cause | Fix |
|---------|---------------|-----|
| No agent appears | AES key mismatch | Verify agent was built with the same AES key as the server |
| No agent appears | Wrong host/port in agent | Rebuild agent with correct RTLC2_C2_HOST and RTLC2_C2_PORT |
| No agent appears | Firewall blocking | Check firewall rules on both server and target |
| Agent registers but tasks fail | Session key issue | Remove agent and let it re-register |

### Web UI Not Loading

| Symptom | Cause | Fix |
|---------|-------|-----|
| Blank page | Web UI not built | Run `make web` |
| 404 on page refresh | SPA routing issue | Ensure `web/dist/` exists and is accessible |
| API errors | CORS or auth issue | Check browser console for specific error messages |

### Database Issues

```bash
# Check database integrity
sqlite3 data/rtlc2.db "PRAGMA integrity_check;"

# Compact database
sqlite3 data/rtlc2.db "VACUUM;"
```
