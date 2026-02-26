import { create } from 'zustand';
import { api } from '../api/client';
import type { Operator, OperatorSession } from '../types';

interface OperatorState {
  operators: Operator[];
  sessions: OperatorSession[];
  loading: boolean;
  fetch: () => Promise<void>;
  create: (username: string, password: string, role: string) => Promise<void>;
  updateRole: (id: string, role: string) => Promise<void>;
  resetPassword: (id: string, newPassword: string) => Promise<void>;
  remove: (id: string) => Promise<void>;
  fetchSessions: () => Promise<void>;
  kickSession: (tokenPrefix: string) => Promise<void>;
}

export const useOperatorStore = create<OperatorState>((set, get) => ({
  operators: [],
  sessions: [],
  loading: false,

  fetch: async () => {
    set({ loading: true });
    try {
      const res = await api.getOperators();
      set({ operators: res.operators || [], loading: false });
    } catch {
      set({ loading: false });
    }
  },

  create: async (username, password, role) => {
    await api.createOperator(username, password, role);
    get().fetch();
  },

  updateRole: async (id, role) => {
    await api.updateOperator(id, { role });
    get().fetch();
  },

  resetPassword: async (id, newPassword) => {
    await api.updateOperator(id, { password: newPassword });
  },

  remove: async (id) => {
    await api.deleteOperator(id);
    set((s) => ({ operators: s.operators.filter((o) => o.id !== id) }));
  },

  fetchSessions: async () => {
    try {
      const res = await api.getOperatorSessions();
      set({ sessions: res.sessions || [] });
    } catch {
      // silent
    }
  },

  kickSession: async (tokenPrefix) => {
    await api.kickOperatorSession(tokenPrefix);
    get().fetchSessions();
  },
}));
