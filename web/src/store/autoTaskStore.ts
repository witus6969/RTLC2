import { create } from 'zustand';
import { api } from '../api/client';

export interface AutoTask {
  id: string;
  name: string;
  task_type: string;
  data: string;
  params: Record<string, string>;
  os_filter: string;
  arch_filter: string;
  active: boolean;
}

interface AutoTaskState {
  rules: AutoTask[];
  fetch: () => Promise<void>;
  add: (rule: Omit<AutoTask, 'id'>) => Promise<void>;
  remove: (id: string) => Promise<void>;
  toggle: (id: string, active: boolean) => Promise<void>;
}

export const useAutoTaskStore = create<AutoTaskState>((set, get) => ({
  rules: [],
  fetch: async () => {
    try {
      const res = await api.getAutoTasks();
      set({ rules: res.rules || [] });
    } catch {}
  },
  add: async (rule) => {
    await api.addAutoTask(rule);
    get().fetch();
  },
  remove: async (id) => {
    await api.deleteAutoTask(id);
    set(s => ({ rules: s.rules.filter(r => r.id !== id) }));
  },
  toggle: async (id, active) => {
    await api.updateAutoTask(id, { active });
    set(s => ({ rules: s.rules.map(r => r.id === id ? { ...r, active } : r) }));
  },
}));
