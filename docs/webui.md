# RTLC2 Web UI Documentation

The RTLC2 web UI is a single-page application built with React 19, TypeScript 5.9, Vite 7, and Zustand 5. It provides a full-featured operator interface for managing agents, listeners, tasks, and all operational aspects of the C2 framework.

---

## 1. Technology Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| React | 19.2 | UI component framework |
| TypeScript | 5.9 | Type-safe JavaScript |
| Vite | 7.3 | Build tool and dev server |
| Zustand | 5.0 | Lightweight state management |
| React Router DOM | 7.13 | Client-side routing |

### Dev Dependencies

| Package | Purpose |
|---------|---------|
| `@vitejs/plugin-react` | Vite React plugin |
| `eslint` + `typescript-eslint` | Linting |
| `eslint-plugin-react-hooks` | React hooks lint rules |
| `eslint-plugin-react-refresh` | Fast refresh lint rules |

---

## 2. Building

```bash
# Install dependencies
cd web && npm install

# Development server (hot reload)
npm run dev

# Production build
npm run build

# Type checking
npx tsc --noEmit

# Linting
npm run lint

# Preview production build
npm run preview
```

The production build outputs to `web/dist/`, which the team server serves as static files.

---

## 3. Application Structure

```
web/src/
  main.tsx              App entry point, React root
  App.tsx               Router setup, authentication guard

  api/
    client.ts           HTTP client (fetch wrapper with auth token injection)

  types/
    index.ts            All TypeScript interfaces and type definitions

  store/
    authStore.ts        Authentication state (token, operator)
    agentStore.ts       Agent list and selection state
    taskStore.ts        Task queue and results
    listenerStore.ts    Listener management
    credentialStore.ts  Credential storage
    chatStore.ts        Team chat messages
    toastStore.ts       Toast notification queue
    webhookStore.ts     Webhook configurations
    autoTaskStore.ts    Auto-task rules
    reportStore.ts      Report templates and generation
    campaignStore.ts    Campaign management
    operatorStore.ts    Operator CRUD
    artifactStore.ts    Generated payload artifacts
    eventStore.ts       Audit events
    notificationStore.ts  Notification preferences
    uiStore.ts          UI state (sidebar, tabs, theme)

  hooks/
    useWebSocket.ts     WebSocket connection management and event dispatch
    usePolling.ts       Periodic data refresh hook
    useKeyboardShortcuts.ts  Global keyboard shortcuts

  pages/
    LoginPage.tsx       Login form
    MainPage.tsx        Primary layout with sidebar, agent table, bottom tabs

  components/
    layout/
      Sidebar.tsx           Navigation sidebar with lazy-loaded panel links
      BottomTabs.tsx        Tabbed panel container (closeable tabs)
      StatusBar.tsx         Status bar: connection status, agent count, operator name

    dashboard/
      Dashboard.tsx         Metrics cards, agent status chart, recent events timeline

    agents/
      AgentTable.tsx        Live agent table with status icons, filtering, search
      AgentFilterSidebar.tsx  Filter agents by OS, arch, integrity, tags, alive status
      AgentGraph.tsx        Visual agent connectivity graph
      FileBrowser.tsx       Remote file browser for selected agent
      ProcessBrowser.tsx    Remote process browser for selected agent
      ScreenshotViewer.tsx  Screenshot gallery with thumbnail grid and full-size viewer
      KeyloggerViewer.tsx   Keylogger timeline with chronological view, search, export
      AgentTagManager.tsx   Tag management dialog for agents
      SocksManager.tsx      Start/stop/list SOCKS5 proxies on agents
      TokenManager.tsx      List/steal/make/impersonate tokens
      LateralMovementWizard.tsx  Guided lateral movement (PSExec, WMI, SCShell, WinRM, DCOM)

    tasks/
      TaskPanel.tsx         Task output display with auto-scroll
      CommandInput.tsx      Command input with autocomplete, history (up/down arrows)

    listeners/
      ListenerPanel.tsx     Listener list with status indicators
      ListenerCreateDialog.tsx  Listener creation form with protocol selection

    payload/
      PayloadGenerator.tsx  Payload configuration wizard (OS, arch, format, evasion)
      EvasionTabs.tsx       Tabbed evasion option toggles
      payloadData.ts        Payload format/option constants

    bof/
      BOFPanel.tsx          BOF browser with category tabs, search, OPSEC indicators

    assembly/
      AssemblyPanel.tsx     .NET assembly upload, agent selector, runtime version, AMSI bypass toggle

    profiles/
      MalleableProfilePanel.tsx  Profile browser with category tabs (Normal/APT/Crimeware/Custom), editor, import/export

    credentials/
      CredentialPanel.tsx   Credential table (view, add, delete, filter by type)

    chat/
      ChatPanel.tsx         Operator team chat with message history

    webhooks/
      WebhookPanel.tsx      Webhook CRUD (Slack, Discord, Telegram, generic)

    autotasks/
      AutoTaskPanel.tsx     Auto-task rule management

    reports/
      ReportPanel.tsx       Report template selection and generation

    campaigns/
      CampaignPanel.tsx     Campaign management (create, assign agents, track status)

    operators/
      OperatorPanel.tsx     Operator management (create, edit role/password, delete, session list)

    hosted/
      HostedFilesPanel.tsx  Hosted file upload, URL generation, download tracking

    tools/
      DownloadCradleDialog.tsx  Download cradle generator (12 format selector with generated one-liner)

    plugins/
      PluginPanel.tsx       Plugin listing and management
      ImgPayloadPanel.tsx   Image steganography embed/extract interface

    artifacts/
      ArtifactsPanel.tsx    Generated payload artifact list with download

    events/
      EventLog.tsx          Scrollable event/audit log

    settings/
      SettingsPanel.tsx     Application settings

    ui/
      ToastContainer.tsx    Toast notification display component
```

---

## 4. Component Details

### 4.1 Dashboard

The dashboard provides an operational overview:

- **Metrics cards**: Total agents, active agents, total listeners, pending tasks
- **Agent status chart**: Visual breakdown of agent states (active, dormant, dead)
- **Recent events**: Timeline of the latest operational events (agent check-ins, task completions, credential discoveries)

### 4.2 Agent Table

The primary agent management view:

- Live-updating table with columns: status indicator, hostname, username, OS icon, architecture, process, PID, internal IP, external IP, integrity level, sleep interval, last seen, tags
- Color-coded status: green (active), yellow (dormant), red (dead)
- OS icons for Windows, Linux, macOS
- Integrity level badges: Low, Medium, High, SYSTEM
- Search bar with full-text filtering
- Agent filter sidebar for multi-criteria filtering (OS, arch, integrity, tags, alive/dead)
- Right-click context menu for common actions
- Click to open agent interaction tab

### 4.3 Task Console (CommandInput)

The command-line interface for agent interaction:

- Text input with command autocomplete (Tab completion)
- Command history navigation with arrow keys (up/down)
- 42 supported commands mapped to task types
- Auto-detection of command parameters
- Output display with auto-scroll and copy support
- Base64 encoding/decoding for binary data

### 4.4 Listener Manager

- Table of all listeners with status (active/stopped), protocol, bind address, port
- Create dialog with protocol selection (HTTP, HTTPS, TCP, SMB, DNS)
- TLS certificate/key file inputs for HTTPS listeners
- Malleable profile selection dropdown
- Stop/delete controls with confirmation

### 4.5 Payload Generator

Multi-step payload configuration:

1. **Target selection**: OS (Windows, Linux, macOS), Architecture (x64, x86, ARM64)
2. **Connection**: Listener selection, sleep interval, jitter
3. **Format**: exe, dll, shellcode, loader
4. **Evasion**: Tabbed interface with toggleable techniques across 4 categories (Execution, AppLocker, Trusted Path, Memory Loaders)
5. **OPSEC**: Sleep mask, stack spoofing, ETW patch, AMSI patch, unhook NTDLL, heap encryption, syscall method
6. **Build**: Progress indicator, download on completion

### 4.6 BOF Panel

- Category tabs: Recon, Credential, Lateral, Evasion, Persistence, .NET/Execution
- Search bar for filtering BOFs by name or description
- Each BOF card shows: name, description, author, platforms, OPSEC rating
- OPSEC indicators with color coding:
  - **Safe** (green): Minimal detection risk
  - **Moderate** (yellow): Some detection vectors
  - **Noisy** (red): High detection risk
- Click to expand: argument form, agent selector, execute button
- Multi-agent execution support

### 4.7 .NET Assembly Panel

- File upload (drag-and-drop or file picker) for .NET assemblies
- Agent selector dropdown
- Runtime version selector (v2.0, v4.0)
- Execution mode: in-process or fork-and-run
- AMSI bypass toggle
- Arguments text input
- Execute button with output display

### 4.8 Profile Manager

- Category tabs: Normal (8), APT (8), Crimeware (7), Custom
- Profile cards showing: name, user-agent preview, URI paths, body transform
- JSON editor for creating custom profiles
- Import/export buttons
- Apply to listener action

### 4.9 Screenshot Gallery

- Thumbnail grid of captured screenshots (sorted by timestamp)
- Click to open full-size viewer
- Agent and timestamp metadata on each thumbnail
- Download button for individual screenshots

### 4.10 Keylogger Timeline

- Chronological timeline view of keylogger captures
- Grouped by agent and time window
- Full-text search across captured keystrokes
- Export to text file

### 4.11 SOCKS Manager

- List of active SOCKS5 proxies with agent ID, port, and connection count
- Start proxy: select agent, specify port
- Stop proxy button

### 4.12 Token Manager

- Table of available tokens on the selected agent
- Actions: list tokens, steal token (by PID), make token (credentials), impersonate, revert to self
- Token details: username, domain, integrity level, token type

### 4.13 Lateral Movement Wizard

Guided step-by-step lateral movement:

1. Select method: PSExec, WMI, SCShell, WinRM, DCOM
2. Enter target hostname/IP
3. Configure credentials (current token or explicit)
4. Specify payload/command
5. Execute with progress feedback

### 4.14 Webhook Panel

- CRUD interface for webhook configurations
- Type selector: Slack, Discord, Telegram, Generic HTTP
- URL input and event subscription checkboxes
- Enable/disable toggle
- Test button to send a test notification

### 4.15 Auto-Task Panel

- Rule list with name, task type, OS filter, arch filter, active status
- Create/edit form: select task type, set data/params, filter by OS and architecture
- Enable/disable toggle
- Auto-tasks fire when new agents register that match the filters

### 4.16 Toast Notifications

Real-time WebSocket-driven notifications displayed as toast popups:

- Agent check-in notifications
- Task completion notifications
- New credential discovered
- Listener started/stopped
- Operator join/leave
- Auto-dismiss with configurable timeout
- Click to navigate to relevant panel

---

## 5. State Management (Zustand)

Each store is a standalone Zustand store with actions and selectors:

| Store | State | Key Actions |
|-------|-------|-------------|
| `authStore` | token, operator, isAuthenticated | login, logout |
| `agentStore` | agents[], selectedAgentId | fetchAgents, selectAgent, removeAgent |
| `taskStore` | tasks (by agent), taskHistory | fetchTasks, queueTask, cancelTask |
| `listenerStore` | listeners[] | fetchListeners, createListener, stopListener |
| `credentialStore` | credentials[] | fetchCredentials, addCredential, deleteCredential |
| `chatStore` | messages[] | fetchMessages, sendMessage |
| `toastStore` | toasts[] | addToast, removeToast |
| `webhookStore` | webhooks[] | fetchWebhooks, createWebhook, updateWebhook, deleteWebhook |
| `autoTaskStore` | rules[] | fetchRules, createRule, updateRule, deleteRule |
| `reportStore` | templates[], reports[] | fetchTemplates, generateReport |
| `campaignStore` | campaigns[] | fetchCampaigns, createCampaign, updateCampaign |
| `operatorStore` | operators[] | fetchOperators, createOperator, updateOperator, deleteOperator |
| `artifactStore` | artifacts[] | addArtifact, removeArtifact, downloadArtifact |
| `eventStore` | events[] | fetchEvents |
| `notificationStore` | settings | updateSettings |
| `uiStore` | sidebar state, open tabs, theme | toggleSidebar, openTab, closeTab |

---

## 6. WebSocket Integration

The `useWebSocket` hook manages the persistent WebSocket connection:

1. Connects to `/api/v1/ws/events?token=<auth-token>` on mount
2. Sends auth message with operator details
3. Dispatches incoming events to the appropriate Zustand stores
4. Updates agent list on `agent_new`, `agent_checkin`, `agent_dead`
5. Updates task results on `task_complete`
6. Adds chat messages on `chat_message`
7. Triggers toast notifications for key events
8. Handles reconnection with exponential backoff

---

## 7. Polling

The `usePolling` hook provides periodic data refresh as a fallback:

- Configurable interval (default: 5 seconds for agents, 10 seconds for tasks)
- Automatically pauses when the browser tab is not visible
- Supplements WebSocket for data that may be missed during disconnects

---

## 8. Keyboard Shortcuts

The `useKeyboardShortcuts` hook provides global keyboard bindings:

| Shortcut | Action |
|----------|--------|
| Up/Down Arrow (in command input) | Navigate command history |
| Tab (in command input) | Autocomplete command |
| Enter (in command input) | Execute command |

---

## 9. Tab System (BottomTabs)

The bottom panel uses a tab system for managing multiple views:

**Tab types:**

`event-log`, `dashboard`, `listeners`, `plugins`, `artifacts`, `agent`, `payload`, `bof`, `credentials`, `chat`, `webhooks`, `autotasks`, `screenshot`, `keylogger`, `socks`, `tokens`, `lateral`, `reports`, `campaigns`, `operators`, `hosted-files`, `profiles`, `settings`, `assembly`

- Tabs can be opened from the sidebar or by clicking agents
- Agent tabs include the agent ID for per-agent context
- Most tabs are closeable (except the default dashboard/event log)
- Panels are lazy-loaded using `React.lazy()` for performance

---

## 10. Type Definitions

All TypeScript interfaces are defined in `src/types/index.ts`. Key types:

| Type | Description |
|------|-------------|
| `Agent` | Agent record with all metadata fields |
| `TaskRequest` / `TaskResult` | Task queue and result structures |
| `ListenerConfig` / `Listener` | Listener configuration and runtime state |
| `PayloadConfig` / `PayloadResponse` | Payload generation request/response |
| `BOF` / `BOFArg` | BOF metadata and argument definitions |
| `MalleableProfile` | C2 profile configuration |
| `Credential` | Harvested credential record |
| `Webhook` | Webhook configuration |
| `AutoTaskRule` | Auto-task rule definition |
| `Campaign` | Campaign with agent assignments |
| `Operator` / `OperatorSession` | Operator account and session |
| `HostedFile` | Hosted file with download tracking |
| `Plugin` | Server plugin metadata |
| `WSEvent` | WebSocket event envelope |
| `BottomTab` | Tab definition with type, label, closeable flag |

---

## 11. Theme

The web UI uses a dark theme with red accent colors, implemented via CSS custom properties. The color scheme is designed for extended use in low-light environments typical of red team operations.
