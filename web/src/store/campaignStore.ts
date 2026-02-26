import { create } from 'zustand';
import { api } from '../api/client';
import type { Campaign } from '../types';

interface CampaignState {
  campaigns: Campaign[];
  selectedCampaign: Campaign | null;
  loading: boolean;
  fetch: () => Promise<void>;
  create: (name: string, description: string) => Promise<void>;
  update: (id: string, data: Partial<Campaign>) => Promise<void>;
  remove: (id: string) => Promise<void>;
  select: (id: string) => Promise<void>;
  clearSelection: () => void;
  addAgent: (campaignId: string, agentId: string) => Promise<void>;
  removeAgent: (campaignId: string, agentId: string) => Promise<void>;
}

export const useCampaignStore = create<CampaignState>((set, get) => ({
  campaigns: [],
  selectedCampaign: null,
  loading: false,

  fetch: async () => {
    set({ loading: true });
    try {
      const res = await api.getCampaigns();
      set({ campaigns: res.campaigns || [], loading: false });
    } catch {
      set({ loading: false });
    }
  },

  create: async (name, description) => {
    await api.createCampaign(name, description);
    get().fetch();
  },

  update: async (id, data) => {
    await api.updateCampaign(id, data);
    get().fetch();
    // Refresh selected if it was updated
    const sel = get().selectedCampaign;
    if (sel && sel.id === id) {
      get().select(id);
    }
  },

  remove: async (id) => {
    await api.deleteCampaign(id);
    set((s) => ({
      campaigns: s.campaigns.filter((c) => c.id !== id),
      selectedCampaign: s.selectedCampaign?.id === id ? null : s.selectedCampaign,
    }));
  },

  select: async (id) => {
    try {
      const campaign = await api.getCampaign(id);
      set({ selectedCampaign: campaign });
    } catch {
      set({ selectedCampaign: null });
    }
  },

  clearSelection: () => set({ selectedCampaign: null }),

  addAgent: async (campaignId, agentId) => {
    await api.addAgentToCampaign(campaignId, agentId);
    get().select(campaignId);
    get().fetch();
  },

  removeAgent: async (campaignId, agentId) => {
    await api.removeAgentFromCampaign(campaignId, agentId);
    get().select(campaignId);
    get().fetch();
  },
}));
