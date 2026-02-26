// ═══════════════════════════════════════════════════════════════
//  RTLC2 Credential Store
// ═══════════════════════════════════════════════════════════════

import { create } from 'zustand';
import { api } from '../api/client';
import type { Credential, CredentialTypeValue } from '../types';

interface CredentialFilters {
  type: CredentialTypeValue | 'all';
  search: string;
}

interface CredentialState {
  credentials: Credential[];
  isLoading: boolean;
  error: string | null;
  filters: CredentialFilters;

  fetch: () => Promise<void>;
  addCredential: (cred: Omit<Credential, 'id' | 'timestamp'>) => Promise<void>;
  deleteCredential: (id: string) => Promise<void>;
  setFilter: (filters: Partial<CredentialFilters>) => void;
  getFiltered: () => Credential[];
  exportCSV: () => void;
}

export const useCredentialStore = create<CredentialState>((set, get) => ({
  credentials: [],
  isLoading: false,
  error: null,
  filters: {
    type: 'all',
    search: '',
  },

  fetch: async () => {
    try {
      set({ isLoading: true });
      const res = await api.getCredentials();
      set({ credentials: res.credentials || [], isLoading: false, error: null });
    } catch (err: any) {
      if (err.status !== 401) {
        set({ isLoading: false, error: err.message });
      } else {
        set({ isLoading: false });
      }
    }
  },

  addCredential: async (cred) => {
    try {
      set({ isLoading: true, error: null });
      const newCred = await api.addCredential(cred);
      set((s) => ({
        credentials: [...s.credentials, newCred],
        isLoading: false,
      }));
    } catch (err: any) {
      set({ isLoading: false, error: err.message });
      throw err;
    }
  },

  deleteCredential: async (id) => {
    try {
      await api.deleteCredential(id);
      set((s) => ({
        credentials: s.credentials.filter((c) => c.id !== id),
      }));
    } catch (err: any) {
      set({ error: err.message });
    }
  },

  setFilter: (partial) => {
    set((s) => ({
      filters: { ...s.filters, ...partial },
    }));
  },

  getFiltered: () => {
    const { credentials, filters } = get();
    return credentials.filter((c) => {
      if (filters.type !== 'all' && c.type !== filters.type) return false;
      if (filters.search) {
        const q = filters.search.toLowerCase();
        return (
          c.username.toLowerCase().includes(q) ||
          c.domain.toLowerCase().includes(q) ||
          c.value.toLowerCase().includes(q) ||
          c.source_agent_hostname.toLowerCase().includes(q)
        );
      }
      return true;
    });
  },

  exportCSV: () => {
    const filtered = get().getFiltered();
    const header = 'Type,Username,Domain,Value,Source Agent,Timestamp,Note';
    const rows = filtered.map((c) =>
      [
        c.type,
        `"${c.username.replace(/"/g, '""')}"`,
        `"${c.domain.replace(/"/g, '""')}"`,
        `"${c.value.replace(/"/g, '""')}"`,
        `"${c.source_agent_hostname.replace(/"/g, '""')}"`,
        c.timestamp,
        `"${(c.note || '').replace(/"/g, '""')}"`,
      ].join(',')
    );
    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `rtlc2_credentials_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  },
}));
