import { create } from 'zustand';
import { api } from '../api/client';
import type { Agent } from '../types';

export interface AgentFilter {
  os: string[];
  status: 'all' | 'alive' | 'dead';
  tags: string[];
  search: string;
}

const defaultFilter: AgentFilter = {
  os: [],
  status: 'all',
  tags: [],
  search: '',
};

interface AgentState {
  agents: Agent[];
  selectedAgentId: string | null;
  isLoading: boolean;
  error: string | null;

  // Filter state
  filter: AgentFilter;
  selectedAgents: string[];

  fetch: () => Promise<void>;
  selectAgent: (id: string | null) => void;
  removeAgent: (id: string) => Promise<void>;

  // Filter methods
  setFilter: (f: Partial<AgentFilter>) => void;
  resetFilter: () => void;
  toggleAgentSelection: (id: string) => void;
  selectAllFiltered: () => void;
  clearSelection: () => void;
  filteredAgents: () => Agent[];
}

export const useAgentStore = create<AgentState>((set, get) => ({
  agents: [],
  selectedAgentId: null,
  isLoading: false,
  error: null,
  filter: { ...defaultFilter },
  selectedAgents: [],

  fetch: async () => {
    try {
      const res = await api.getAgents();
      set({ agents: res.agents || [], error: null });
    } catch (err: any) {
      if (err.status !== 401) {
        set({ error: err.message });
      }
    }
  },

  selectAgent: (id) => set({ selectedAgentId: id }),

  removeAgent: async (id) => {
    try {
      await api.removeAgent(id);
      set((s) => ({
        agents: s.agents.filter((a) => a.id !== id),
        selectedAgentId: s.selectedAgentId === id ? null : s.selectedAgentId,
        selectedAgents: s.selectedAgents.filter((a) => a !== id),
      }));
    } catch (err: any) {
      set({ error: err.message });
    }
  },

  setFilter: (f) => set((s) => ({ filter: { ...s.filter, ...f } })),

  resetFilter: () => set({ filter: { ...defaultFilter } }),

  toggleAgentSelection: (id) => set((s) => ({
    selectedAgents: s.selectedAgents.includes(id)
      ? s.selectedAgents.filter((a) => a !== id)
      : [...s.selectedAgents, id],
  })),

  selectAllFiltered: () => {
    const filtered = get().filteredAgents();
    set({ selectedAgents: filtered.map((a) => a.id) });
  },

  clearSelection: () => set({ selectedAgents: [] }),

  filteredAgents: () => {
    const { agents, filter } = get();
    return agents.filter((a) => {
      // OS filter
      if (filter.os.length > 0) {
        const agentOs = a.os.toLowerCase();
        const match = filter.os.some((os) => agentOs.includes(os.toLowerCase()));
        if (!match) return false;
      }
      // Status filter
      if (filter.status === 'alive' && !a.alive) return false;
      if (filter.status === 'dead' && a.alive) return false;
      // Search filter
      if (filter.search) {
        const term = filter.search.toLowerCase();
        const searchable = `${a.hostname} ${a.username} ${a.internal_ip} ${a.external_ip} ${a.id}`.toLowerCase();
        if (!searchable.includes(term)) return false;
      }
      // Tag filter
      if (filter.tags.length > 0) {
        const agentTags: string[] = a.tags || [];
        if (!filter.tags.every(t => agentTags.includes(t))) return false;
      }
      return true;
    });
  },
}));
