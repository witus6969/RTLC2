// ═══════════════════════════════════════════════════════════════
//  RTLC2 Chat Store
// ═══════════════════════════════════════════════════════════════

import { create } from 'zustand';
import { api } from '../api/client';
import type { ChatMessage } from '../types';

interface ChatState {
  messages: ChatMessage[];
  connected: boolean;
  isLoading: boolean;
  error: string | null;

  fetchHistory: () => Promise<void>;
  sendMessage: (text: string) => Promise<void>;
  addMessage: (msg: ChatMessage) => void;
  setConnected: (connected: boolean) => void;
  clearError: () => void;
}

export const useChatStore = create<ChatState>((set) => ({
  messages: [],
  connected: false,
  isLoading: false,
  error: null,

  fetchHistory: async () => {
    try {
      set({ isLoading: true });
      const res = await api.getChatHistory(100);
      set({ messages: res.messages || [], isLoading: false, error: null });
    } catch (err: any) {
      if (err.status !== 401) {
        set({ isLoading: false, error: err.message });
      } else {
        set({ isLoading: false });
      }
    }
  },

  sendMessage: async (text) => {
    if (!text.trim()) return;
    try {
      const msg = await api.sendChatMessage(text);
      // Server echoes the message back; add it if not already present
      set((s) => {
        const exists = s.messages.some((m) => m.id === msg.id);
        if (exists) return s;
        return { messages: [...s.messages, msg] };
      });
    } catch (err: any) {
      set({ error: err.message });
    }
  },

  addMessage: (msg) => {
    set((s) => {
      // Deduplicate by id
      const exists = s.messages.some((m) => m.id === msg.id);
      if (exists) return s;
      return { messages: [...s.messages, msg] };
    });
  },

  setConnected: (connected) => set({ connected }),

  clearError: () => set({ error: null }),
}));
