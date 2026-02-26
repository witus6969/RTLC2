// ═══════════════════════════════════════════════════════════════
//  RTLC2 REST API Client
// ═══════════════════════════════════════════════════════════════

import type {
  LoginResponse,
  Agent,
  TaskRequest,
  TaskResponse,
  TaskResult,
  Listener,
  ListenerConfig,
  PayloadConfig,
  PayloadResponse,
  BOF,
  Plugin,
  AuditEvent,
  ServerInfo,
  Operator,
  MalleableProfile,
  MalleableProfileFull,
  Credential,
  ChatMessage,
  Webhook,
  AutoTaskRule,
  HostedFile,
  CradleRequest,
  CradleResponse,
  ReportTemplate,
  ReportRequest,
  ReportResponse,
  Campaign,
  OperatorSession,
} from '../types';

class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

class ApiClient {
  private baseUrl: string = '/api/v1';
  private token: string | null = null;
  private onUnauthorized: (() => void) | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  setOnUnauthorized(cb: () => void) {
    this.onUnauthorized = cb;
  }

  private async request<T>(method: string, endpoint: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    // CRITICAL: Send raw token, NOT "Bearer <token>"
    // Go server checks h.tokens[token] directly
    if (this.token) {
      headers['Authorization'] = this.token;
    }

    const res = await fetch(`${this.baseUrl}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15000),
    });

    if (res.status === 401) {
      this.token = null;
      this.onUnauthorized?.();
      throw new ApiError('Unauthorized', 401);
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new ApiError(err.error || `Request failed: ${res.status}`, res.status);
    }

    // Handle empty responses
    const text = await res.text();
    if (!text) return {} as T;
    return JSON.parse(text);
  }

  private get<T>(endpoint: string) { return this.request<T>('GET', endpoint); }
  private post<T>(endpoint: string, body?: unknown) { return this.request<T>('POST', endpoint, body); }
  private put<T>(endpoint: string, body: unknown) { return this.request<T>('PUT', endpoint, body); }
  private del<T>(endpoint: string) { return this.request<T>('DELETE', endpoint); }

  // ── Auth ──────────────────────────────────────────────────
  login(username: string, password: string) {
    return this.post<LoginResponse>('/auth/login', { username, password });
  }
  logout() {
    return this.post<void>('/auth/logout', { token: this.token });
  }

  // ── Agents ────────────────────────────────────────────────
  getAgents() {
    return this.get<{ agents: Agent[] }>('/agents');
  }
  getAgent(id: string) {
    return this.get<Agent>(`/agents/${id}`);
  }
  getAgentTasks(id: string) {
    return this.get<{ tasks: TaskResponse[] }>(`/agents/${id}/tasks`);
  }
  removeAgent(id: string) {
    return this.post<void>('/agents/remove', { agent_id: id });
  }

  // ── Tasks ─────────────────────────────────────────────────
  sendTask(task: TaskRequest) {
    return this.post<TaskResponse>('/tasks', task);
  }
  getTaskResult(taskId: string) {
    return this.get<TaskResult>(`/tasks/${taskId}`);
  }

  // ── Listeners ─────────────────────────────────────────────
  getListeners() {
    return this.get<{ listeners: Listener[] }>('/listeners');
  }
  createListener(config: ListenerConfig) {
    return this.post<Listener>('/listeners', config);
  }
  getListener(id: string) {
    return this.get<Listener>(`/listeners/${id}`);
  }
  updateListener(id: string, config: ListenerConfig) {
    return this.put<Listener>(`/listeners/${id}`, config);
  }
  deleteListener(id: string) {
    return this.del<void>(`/listeners/${id}`);
  }
  stopListener(id: string) {
    return this.post<void>('/listeners/stop', { id });
  }

  // ── Payloads ──────────────────────────────────────────────
  generatePayload(config: PayloadConfig) {
    return this.post<PayloadResponse>('/payloads/generate', config);
  }
  generateShellcode(config: PayloadConfig) {
    return this.post<PayloadResponse>('/payloads/shellcode', config);
  }
  getPayloadFormats() {
    return this.get<{ formats: string[] }>('/payloads/formats');
  }

  // ── BOFs ──────────────────────────────────────────────────
  getBOFs() {
    return this.get<{ bofs: BOF[] }>('/bofs');
  }
  executeBOF(agentId: string, bofName: string, args: Record<string, string>) {
    return this.post<TaskResponse>('/bofs/execute', {
      agent_id: agentId,
      bof_name: bofName,
      arguments: args,
    });
  }
  uploadBOF(data: string, filename: string) {
    return this.post<void>('/bofs/upload', { data, filename });
  }

  // ── Profiles ──────────────────────────────────────────────
  getProfiles() {
    return this.get<{ profiles: MalleableProfile[] }>('/profiles');
  }
  getProfilesFull() {
    return this.get<{ profiles: MalleableProfileFull[] }>('/profiles');
  }
  getProfile(name: string) {
    return this.get<MalleableProfileFull>(`/profiles/${encodeURIComponent(name)}`);
  }
  uploadProfile(data: string, filename: string) {
    return this.post<void>('/profiles/upload', { data, filename });
  }
  uploadProfileFull(profile: MalleableProfileFull) {
    return this.post<void>('/profiles', profile);
  }
  deleteProfile(name: string) {
    return this.del<void>(`/profiles/${encodeURIComponent(name)}`);
  }

  // ── Assembly Execution ─────────────────────────────────────
  executeAssembly(agentId: string, data: string, args: string, options: { runtime?: string; fork?: boolean; amsi?: boolean }) {
    return this.post<TaskResponse>('/tasks', {
      agent_id: agentId,
      type: 8,
      data,
      params: {
        args,
        runtime_version: options.runtime || 'v4.0.30319',
        fork: options.fork ? '1' : '0',
        amsi_bypass: options.amsi ? '1' : '0',
      },
    });
  }

  // ── Plugins ───────────────────────────────────────────────
  getPlugins() {
    return this.get<{ plugins: Plugin[] }>('/plugins');
  }
  loadPlugin(data: string, filename: string) {
    return this.post<void>('/plugins/load', { data, filename });
  }

  // ── ImgPayload Plugin ──────────────────────────────────────
  imgPayloadEmbed(image: string, shellcode: string, format: string) {
    return this.post<{ data: string; size: number; shellcode_size: number; format: string }>(
      '/plugins/imgpayload/embed', { image, shellcode, format }
    );
  }
  imgPayloadExtract(image: string) {
    return this.post<{ data: string; size: number }>(
      '/plugins/imgpayload/extract', { image }
    );
  }

  // ── Credentials ─────────────────────────────────────────
  getCredentials() {
    return this.get<{ credentials: Credential[] }>('/credentials');
  }
  addCredential(cred: Omit<Credential, 'id' | 'timestamp'>) {
    return this.post<Credential>('/credentials', cred);
  }
  deleteCredential(id: string) {
    return this.del<void>(`/credentials/${id}`);
  }

  // ── Chat ───────────────────────────────────────────────
  getChatHistory(limit: number = 100) {
    return this.get<{ messages: ChatMessage[] }>(`/chat?limit=${limit}`);
  }
  sendChatMessage(text: string) {
    return this.post<ChatMessage>('/chat', { text });
  }

  // ── Agent Tags ──────────────────────────────────────────
  getAgentTags(agentId: string) {
    return this.get<{ tags: string[] }>(`/agents/${agentId}/tags`);
  }
  updateAgentTags(agentId: string, tags: string[]) {
    return this.put<void>(`/agents/${agentId}/tags`, { tags });
  }
  getAllAgentTags() {
    return this.get<{ tags: Record<string, string[]> }>('/agents/tags');
  }

  // ── Agent Notes ────────────────────────────────────────
  updateAgentNote(agentId: string, note: string) {
    return this.put<void>(`/agents/${agentId}/note`, { note });
  }

  // ── Webhooks ───────────────────────────────────────────
  getWebhooks() {
    return this.get<{ webhooks: Webhook[] }>('/webhooks');
  }
  addWebhook(wh: Omit<Webhook, 'id'>) {
    return this.post<Webhook>('/webhooks', wh);
  }
  updateWebhook(id: string, data: Partial<Webhook>) {
    return this.put<void>(`/webhooks/${id}`, data);
  }
  deleteWebhook(id: string) {
    return this.del<void>(`/webhooks/${id}`);
  }
  testWebhook(id: string) {
    return this.post<void>(`/webhooks/test`, { id });
  }

  // ── Auto-Tasks ─────────────────────────────────────────
  getAutoTasks() {
    return this.get<{ rules: AutoTaskRule[] }>('/autotasks');
  }
  addAutoTask(rule: Omit<AutoTaskRule, 'id'>) {
    return this.post<AutoTaskRule>('/autotasks', rule);
  }
  updateAutoTask(id: string, data: Partial<AutoTaskRule>) {
    return this.put<void>(`/autotasks/${id}`, data);
  }
  deleteAutoTask(id: string) {
    return this.del<void>(`/autotasks/${id}`);
  }

  // ── Download Cradles ───────────────────────────────────
  generateCradle(req: CradleRequest) {
    return this.post<CradleResponse>('/cradles/generate', req);
  }
  getCradleFormats() {
    return this.get<{ formats: string[] }>('/cradles/formats');
  }

  // ── Hosted Files ───────────────────────────────────────
  getHostedFiles() {
    return this.get<{ files: HostedFile[] }>('/hosted');
  }
  uploadHostedFile(data: string, filename: string, maxDownloads?: number, expiresMinutes?: number) {
    return this.post<HostedFile>('/hosted', { data, filename, max_downloads: maxDownloads, expires_minutes: expiresMinutes });
  }
  deleteHostedFile(id: string) {
    return this.del<void>(`/hosted/${id}`);
  }

  // ── Events ────────────────────────────────────────────────
  getEvents(limit: number = 50) {
    return this.get<{ events: AuditEvent[] }>(`/events?limit=${limit}`);
  }

  // ── Server ────────────────────────────────────────────────
  getServerInfo() {
    return this.get<ServerInfo>('/server/info');
  }
  getOperators() {
    return this.get<{ operators: Operator[] }>('/operators');
  }

  // ── Reports ───────────────────────────────────────────────
  getReportTemplates() {
    return this.get<{ templates: ReportTemplate[] }>('/reports/templates');
  }
  generateReport(req: ReportRequest) {
    return this.post<ReportResponse>('/reports/generate', req);
  }

  // ── Campaigns ─────────────────────────────────────────────
  getCampaigns() {
    return this.get<{ campaigns: Campaign[] }>('/campaigns');
  }
  createCampaign(name: string, description: string) {
    return this.post<Campaign>('/campaigns', { name, description });
  }
  getCampaign(id: string) {
    return this.get<Campaign>(`/campaigns/${id}`);
  }
  updateCampaign(id: string, data: Partial<Campaign>) {
    return this.put<void>(`/campaigns/${id}`, data);
  }
  deleteCampaign(id: string) {
    return this.del<void>(`/campaigns/${id}`);
  }
  getCampaignAgents(id: string) {
    return this.get<{ agents: string[] }>(`/campaigns/${id}/agents`);
  }
  addAgentToCampaign(campaignId: string, agentId: string) {
    return this.post<void>(`/campaigns/${campaignId}/agents`, { agent_id: agentId });
  }
  removeAgentFromCampaign(campaignId: string, agentId: string) {
    return this.request<void>('DELETE', `/campaigns/${campaignId}/agents`, { agent_id: agentId });
  }

  // ── Operator Management ───────────────────────────────────
  createOperator(username: string, password: string, role: string) {
    return this.post<Operator>('/operators', { username, password, role });
  }
  updateOperator(id: string, data: { password?: string; role?: string }) {
    return this.put<void>(`/operators/${id}`, data);
  }
  deleteOperator(id: string) {
    return this.del<void>(`/operators/${id}`);
  }
  getOperatorSessions() {
    return this.get<{ sessions: OperatorSession[] }>('/operators/sessions');
  }
  kickOperatorSession(token: string) {
    return this.request<void>('DELETE', '/operators/sessions', { token });
  }
}

export const api = new ApiClient();
export { ApiError };
