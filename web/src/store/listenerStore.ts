import { create } from 'zustand';
import { api } from '../api/client';
import type { Listener, ListenerConfig } from '../types';

interface ListenerState {
  listeners: Listener[];
  isLoading: boolean;
  error: string | null;

  fetch: () => Promise<void>;
  create: (config: ListenerConfig) => Promise<void>;
  stop: (id: string) => Promise<void>;
  remove: (id: string) => Promise<void>;
  update: (id: string, config: ListenerConfig) => Promise<void>;
}

export const useListenerStore = create<ListenerState>((set) => ({
  listeners: [],
  isLoading: false,
  error: null,

  fetch: async () => {
    try {
      const res = await api.getListeners();
      const listeners = (res.listeners || []).map((raw: any) => {
        // If server already returns nested config, use as-is
        if (raw.config?.name !== undefined || raw.config?.bind_host !== undefined) return raw;
        // Otherwise normalize flat response into expected Listener shape
        const addr = raw.address || '';
        const parts = addr.split(':');
        return {
          ...raw,
          config: {
            name: raw.name || '',
            protocol: raw.protocol ?? 0,
            bind_host: parts[0] || '0.0.0.0',
            bind_port: parseInt(parts[1] || '0', 10),
            ...raw.config,
          },
        };
      });
      set({ listeners, error: null });
    } catch (err: any) {
      if (err.status !== 401) set({ error: err.message });
    }
  },

  create: async (config) => {
    set({ isLoading: true, error: null });
    try {
      await api.createListener(config);
      const res = await api.getListeners();
      set({ listeners: res.listeners || [], isLoading: false });
    } catch (err: any) {
      set({ isLoading: false, error: err.message });
      throw err;
    }
  },

  stop: async (id) => {
    try {
      await api.stopListener(id);
      const res = await api.getListeners();
      set({ listeners: res.listeners || [] });
    } catch (err: any) {
      set({ error: err.message });
    }
  },

  remove: async (id) => {
    try {
      await api.deleteListener(id);
      set((s) => ({ listeners: s.listeners.filter((l) => l.id !== id) }));
    } catch (err: any) {
      set({ error: err.message });
    }
  },

  update: async (id, config) => {
    try {
      await api.updateListener(id, config);
      const res = await api.getListeners();
      set({ listeners: res.listeners || [] });
    } catch (err: any) {
      set({ error: err.message });
      throw err;
    }
  },
}));
