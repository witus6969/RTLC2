import { create } from 'zustand';
import { api } from '../api/client';
import type { ReportTemplate } from '../types';

interface ReportState {
  templates: ReportTemplate[];
  generating: boolean;
  lastReport: { template: string; format: string; data: string; generated: string } | null;
  fetchTemplates: () => Promise<void>;
  generate: (template: string, format: string, dateFrom: string, dateTo: string, agentIds?: string[]) => Promise<void>;
  clear: () => void;
}

export const useReportStore = create<ReportState>((set) => ({
  templates: [],
  generating: false,
  lastReport: null,

  fetchTemplates: async () => {
    try {
      const res = await api.getReportTemplates();
      set({ templates: res.templates || [] });
    } catch {
      // silent
    }
  },

  generate: async (template, format, dateFrom, dateTo, agentIds) => {
    set({ generating: true });
    try {
      const res = await api.generateReport({
        template,
        format,
        date_from: dateFrom,
        date_to: dateTo,
        agent_ids: agentIds,
      });
      set({
        lastReport: {
          template: res.template,
          format: res.format,
          data: res.data,
          generated: res.generated,
        },
        generating: false,
      });
    } catch (err: any) {
      set({ generating: false });
      throw err;
    }
  },

  clear: () => set({ lastReport: null }),
}));
