import { create } from 'zustand';
import { api } from '../api/client';
import type { AuditEvent } from '../types';

interface EventState {
  events: AuditEvent[];
  filterType: string;
  searchQuery: string;
  page: number;
  pageSize: number;
  fetch: () => Promise<void>;
  setFilterType: (t: string) => void;
  setSearchQuery: (q: string) => void;
  setPage: (p: number) => void;
  setPageSize: (s: number) => void;
}

export const useEventStore = create<EventState>((set) => ({
  events: [],
  filterType: 'all',
  searchQuery: '',
  page: 0,
  pageSize: 50,

  fetch: async () => {
    try {
      const res = await api.getEvents(200);
      set({ events: res.events || [] });
    } catch {
      // Silently fail for polling
    }
  },

  setFilterType: (filterType) => set({ filterType, page: 0 }),
  setSearchQuery: (searchQuery) => set({ searchQuery, page: 0 }),
  setPage: (page) => set({ page }),
  setPageSize: (pageSize) => set({ pageSize, page: 0 }),
}));
