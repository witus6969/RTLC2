// ═══════════════════════════════════════════════════════════════
//  RTLC2 TypeScript Type Definitions
// ═══════════════════════════════════════════════════════════════

// Auth
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  operator: Operator;
}

export interface Operator {
  id: string;
  username: string;
  role: string;
  last_login: string;
  online: boolean;
}

// Agent
export interface Agent {
  id: string;
  hostname: string;
  username: string;
  os: string;
  arch: string;
  process_name: string;
  pid: number;
  internal_ip: string;
  external_ip: string;
  sleep_interval: number;
  jitter: number;
  first_seen: string;
  last_seen: string;
  listener_id: string;
  integrity: string;
  alive: boolean;
  note: string;
  tags?: string[];
}

// Task
export const TaskType = {
  UNKNOWN: 0,
  SHELL: 1,
  UPLOAD: 2,
  DOWNLOAD: 3,
  SLEEP: 4,
  EXIT: 5,
  INJECT: 6,
  BOF: 7,
  ASSEMBLY: 8,
  SCREENSHOT: 9,
  KEYLOG: 10,
  PS: 11,
  LS: 12,
  CD: 13,
  PWD: 14,
  WHOAMI: 15,
  IPCONFIG: 16,
  HASHDUMP: 17,
  TOKEN: 18,
  PIVOT: 19,
  PORTSCAN: 20,
  SOCKS: 21,
  SELFDESTRUCT: 22,
  MODULE: 23,
  CLIPBOARD: 24,
  REG_WRITE: 25,
  SERVICE_CTL: 26,
  JOBS: 27,
  PERSIST: 28,
  UNPERSIST: 29,
  PRIVESC: 30,
  FILE_COPY: 31,
  FILE_MOVE: 32,
  FILE_DELETE: 33,
  MKDIR: 34,
  REG_QUERY: 35,
  ENV_VAR: 36,
  RPORTFWD: 37,
  RUN_AS: 38,
  POWERSHELL: 39,
  LOLBAS: 40,
} as const;

export const TaskStatus = {
  PENDING: 0,
  RUNNING: 1,
  COMPLETE: 2,
  ERROR: 3,
} as const;

export interface TaskRequest {
  agent_id: string;
  type: number;
  data: string; // base64
  params: Record<string, string>;
}

export interface TaskResponse {
  task_id: string;
  agent_id: string;
  type: number;
  created_at: string;
}

export interface TaskResult {
  task_id: string;
  agent_id: string;
  type: number;
  status: number;
  output?: string; // base64 (optional, only present when task has output)
  created_at: string;
  updated_at: string;
}

// Listener
export const ListenerProtocol = {
  HTTP: 0,
  HTTPS: 1,
  TCP: 2,
  SMB: 3,
  DNS: 4,
} as const;

export interface ListenerConfig {
  name: string;
  protocol: number;
  bind_host: string;
  bind_port: number;
  secure?: boolean;
  cert_path?: string;
  key_path?: string;
  options?: Record<string, string>;
  profile?: MalleableProfile;
}

export interface MalleableProfile {
  id?: string;
  name: string;
  description?: string;
  user_agent: string;
  request_headers?: Record<string, string>;
  response_headers?: Record<string, string>;
  uri_paths?: string[];
  uris?: string[];
  body_transform: string;
  headers?: Record<string, string>;
}

export interface Listener {
  id: string;
  config: ListenerConfig;
  active: boolean;
  started_at: string;
  agents_connected: number;
}

// Payload
export interface PayloadConfig {
  format: string;
  arch: string;
  os_target: string;
  listener_id: string;
  sleep: number;
  jitter: number;
  shellcode_format: string;
  evasion: Record<string, Record<string, boolean>>;
  encryption: EncryptionConfig;
  opsec: OpsecConfig;
}

export interface EncryptionConfig {
  transport_type: string;
  payload_type: string;
  key: string;
}

export interface OpsecConfig {
  sleep_mask: boolean;
  stack_spoof: boolean;
  module_stomping: boolean;
  etw_patch: boolean;
  unhook_ntdll: boolean;
  thread_stack_spoof: boolean;
  heap_encryption: boolean;
  syscall_method: string;
}

export interface PayloadResponse {
  name: string;
  data: string; // base64
  hash: string;
}

// BOF
export interface BOF {
  name: string;
  category: string;
  author: string;
  description: string;
  platforms: string[];
  args: BOFArg[];
  opsec: string;
  compiled: boolean;
}

export interface BOFArg {
  name: string;
  type: string;
  description: string;
  required?: boolean;
  default_value?: string;
}

// Plugin
export interface Plugin {
  name: string;
  version: string;
  author: string;
  description: string;
  status: string;
  commands?: string[];
  capabilities?: string[];
  category?: string;
  supported_formats?: string[];
}

// Events
export interface AuditEvent {
  id: number;
  operator_id: string;
  action: string;
  target: string;
  details: string;
  timestamp: string;
}

// Server
export interface ServerInfo {
  version: string;
  hostname: string;
  os: string;
  agents_count: number;
  listeners_count: number;
  uptime: string;
  uptime_seconds: number;
}

// Artifact
export interface Artifact {
  id: string;
  name: string;
  listenerName: string;
  os: string;
  arch: string;
  format: string;
  size: number;
  hash: string;
  data: string; // base64
  createdAt: string;
  shellcodeOnly: boolean;
}

// Credential
export const CredentialType = {
  NTLM: 'ntlm',
  PLAINTEXT: 'plaintext',
  TICKET: 'ticket',
  CERTIFICATE: 'certificate',
  SSH_KEY: 'ssh_key',
} as const;

export type CredentialTypeValue = typeof CredentialType[keyof typeof CredentialType];

export interface Credential {
  id: string;
  type: CredentialTypeValue;
  username: string;
  domain: string;
  value: string;
  source_agent_id: string;
  source_agent_hostname: string;
  timestamp: string;
  note: string;
}

// Chat
export interface ChatMessage {
  id: string;
  operator: string;
  text: string;
  timestamp: string;
}

// WebSocket Events
export const WSEventType = {
  AGENT_CHECKIN: 'agent_checkin',
  AGENT_DEAD: 'agent_dead',
  AGENT_TASK_COMPLETE: 'agent_task_complete',
  LISTENER_STARTED: 'listener_started',
  LISTENER_STOPPED: 'listener_stopped',
  CREDENTIAL_ADDED: 'credential_added',
  CHAT_MESSAGE: 'chat_message',
  OPERATOR_JOIN: 'operator_join',
  OPERATOR_LEAVE: 'operator_leave',
} as const;

export interface WSEvent {
  type: string;
  data: unknown;
  timestamp: string;
}

// File Browser
export interface FileEntry {
  name: string;
  size: number;
  modified: string;
  type: 'file' | 'directory';
  permissions: string;
}

// Process Browser
export interface ProcessEntry {
  pid: number;
  name: string;
  user: string;
  arch: string;
  session: number;
  ppid: number;
  path: string;
}

// UI State
export interface BottomTab {
  id: string;
  label: string;
  type: 'event-log' | 'dashboard' | 'listeners' | 'plugins' | 'artifacts' | 'agent' | 'payload' | 'bof' | 'credentials' | 'chat' | 'webhooks' | 'autotasks' | 'screenshot' | 'keylogger' | 'socks' | 'tokens' | 'lateral' | 'reports' | 'campaigns' | 'operators' | 'hosted-files' | 'profiles' | 'settings' | 'assembly';
  closeable: boolean;
  agentId?: string;
}

// Webhook
export interface Webhook {
  id: string;
  name: string;
  type: string;
  url: string;
  events: string[];
  active: boolean;
}

// Auto-Task Rule
export interface AutoTaskRule {
  id: string;
  name: string;
  task_type: string;
  data: string;
  params: Record<string, string>;
  os_filter: string;
  arch_filter: string;
  active: boolean;
}

// Hosted File
export interface HostedFile {
  id: string;
  filename: string;
  content_type: string;
  size: number;
  download_count: number;
  max_downloads: number;
  expires_at: string;
  url: string;
  created_at: string;
}

// Download Cradle
export interface CradleRequest {
  url: string;
  format: string;
  proxy?: string;
}

export interface CradleResponse {
  cradle: string;
  format: string;
}

// Report
export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  formats: string[];
}

export interface ReportRequest {
  template: string;
  format: string;
  date_from: string;
  date_to: string;
  agent_ids?: string[];
}

export interface ReportResponse {
  template: string;
  format: string;
  data: string;
  generated: string;
}

// Campaign
export interface Campaign {
  id: string;
  name: string;
  description: string;
  status: string;
  agent_count: number;
  agents?: string[];
  created_at: string;
  updated_at: string;
}

// Operator Session
export interface OperatorSession {
  token_prefix: string;
  operator_id: string;
  username: string;
  role: string;
}

// BOF Category
export type BOFCategory = 'recon' | 'credential' | 'lateral' | 'evasion' | 'persistence' | 'dotnet';

// Profile Category
export type ProfileCategory = 'normal' | 'apt' | 'crimeware' | 'custom' | 'builtin';

// Assembly Execution
export interface AssemblyExecRequest {
  agent_id: string;
  assembly_data: string; // base64
  arguments: string;
  runtime_version: string;
  fork: boolean;
  amsi_bypass: boolean;
}

// Full Malleable Profile (with category and builtin flag)
export interface MalleableProfileFull {
  name: string;
  user_agent: string;
  request_headers: Record<string, string>;
  response_headers: Record<string, string>;
  uris: string[];
  body_transform: string;
  category?: ProfileCategory;
  builtin?: boolean;
}
