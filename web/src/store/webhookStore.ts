import { create } from 'zustand';
import { api } from '../api/client';

export interface Webhook {
  id: string;
  name: string;
  type: string; // slack, discord, telegram, generic
  url: string;
  events: string[];
  active: boolean;
}

interface WebhookState {
  webhooks: Webhook[];
  fetch: () => Promise<void>;
  add: (wh: Omit<Webhook, 'id'>) => Promise<void>;
  remove: (id: string) => Promise<void>;
  toggle: (id: string, active: boolean) => Promise<void>;
  test: (id: string) => Promise<void>;
}

export const useWebhookStore = create<WebhookState>((set, get) => ({
  webhooks: [],
  fetch: async () => {
    try {
      const res = await api.getWebhooks();
      set({ webhooks: res.webhooks || [] });
    } catch {}
  },
  add: async (wh) => {
    await api.addWebhook(wh);
    get().fetch();
  },
  remove: async (id) => {
    await api.deleteWebhook(id);
    set(s => ({ webhooks: s.webhooks.filter(w => w.id !== id) }));
  },
  toggle: async (id, active) => {
    await api.updateWebhook(id, { active });
    set(s => ({ webhooks: s.webhooks.map(w => w.id === id ? { ...w, active } : w) }));
  },
  test: async (id) => {
    await api.testWebhook(id);
  },
}));
