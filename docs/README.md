# RTLC2 Documentation

**Red Team Leaders C2 Framework** -- Comprehensive documentation for version 0.7.0.

---

## Table of Contents

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System architecture, component design, communication protocols, and data flow |
| [Agent](agent.md) | C++17 agent: task types, transports, evasion, syscalls, BOF loader, persistence, build options |
| [Team Server](teamserver.md) | Go team server: configuration, REST API, WebSocket events, RBAC, payload generation |
| [Web UI](webui.md) | React/TypeScript web interface: components, panels, stores, keyboard shortcuts |
| [Deployment](deployment.md) | Installation guide: prerequisites, building, configuration, cross-compilation, security |
| [C2 Profiles](profiles.md) | Malleable C2 profiles: schema, built-in profiles, creating custom profiles |
| [BOF Arsenal](bofs.md) | Beacon Object File arsenal: categories, OPSEC ratings, loader internals, custom BOFs |

---

## Quick Start

```bash
# 1. Install dependencies
make setup

# 2. Build the team server
make teamserver

# 3. Build the web UI
make web

# 4. Configure
vi configs/teamserver.yaml

# 5. Run
./build/rtlc2-teamserver -config configs/teamserver.yaml
```

Open `http://<server-ip>:54321` in a browser and log in with the credentials defined in `teamserver.yaml`.

---

## Project Structure

```
/opt/RTLC2/
  agent/              C++17 implant (CMake project)
    include/          Header files (agent.h, bof.h, evasion.h, ...)
    src/              Source files organized by subsystem
    loader/           Shellcode loader templates
    CMakeLists.txt    Build configuration with compile-time agent settings

  teamserver/         Go team server
    cmd/teamserver/   Entry point (main.go)
    internal/         Internal packages
      agent/          Agent manager
      config/         YAML configuration loader
      crypto/         AES-256-GCM cipher
      database/       SQLite database layer
      listener/       Listener implementations (HTTP, TCP, SMB, DNS)
      server/         HTTP API, WebSocket hub, services
      storage/        Blob storage

  web/                React/TypeScript web UI (Vite)
    src/
      components/     UI components organized by feature
      store/          Zustand state stores
      hooks/          Custom React hooks
      types/          TypeScript type definitions
      api/            HTTP client

  configs/            Configuration files (teamserver.yaml)
  profiles/           Malleable C2 profile JSON files (23 built-in)
  scripts/            Build and deployment scripts
  plugins/            Server-side plugin directory
  data/               Runtime data (SQLite database, logs)
  docs/               This documentation
```

---

## Version History

| Version | Highlights |
|---------|-----------|
| 0.1.0 | Initial release: HTTP transport, basic agent, web UI shell |
| 0.2.0 | Syscalls (Hell's Gate/Halo's Gate), evasion suite, SMB/DNS/TCP transports, post-exploitation modules, .NET CLR hosting, BOF loader, team operations, obfuscation |
| 0.3.0 | Job system, enhanced evasion (heap encryption, ETW-TI, module stomping, environment keying), webhooks, auto-tasks, download cradles, RBAC, toast notifications, screenshot/keylogger viewers, operational panels, agent pivoting |
| 0.7.0 | Current release. Plugin system, image payload steganography, campaign management, report generation, operator session management, hosted files, audit log, artifacts panel, settings panel |
