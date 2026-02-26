import { create } from 'zustand';
import type { BottomTab } from '../types';

interface UIState {
  bottomTabs: BottomTab[];
  activeBottomTab: string;
  activeBottomTabId: string;
  sidebarCollapsed: boolean;
  showPayloadGenerator: boolean;
  showBOFPanel: boolean;
  showPluginManager: boolean;
  showCradleDialog: boolean;
  showAssemblyPanel: boolean;
  showLateralWizard: boolean;
  lateralWizardAgentId: string;
  wsConnected: boolean;

  setActiveBottomTab: (id: string) => void;
  openAgentTab: (agentId: string, hostname: string) => void;
  openAgentSubTab: (agentId: string, hostname: string, subType: BottomTab['type']) => void;
  closeBottomTab: (id: string) => void;
  toggleSidebar: () => void;
  setShowPayloadGenerator: (show: boolean) => void;
  setShowBOFPanel: (show: boolean) => void;
  setShowPluginManager: (show: boolean) => void;
  setShowCradleDialog: (show: boolean) => void;
  setShowAssemblyPanel: (show: boolean) => void;
  setShowLateralWizard: (show: boolean, agentId?: string) => void;
  setWsConnected: (connected: boolean) => void;
}

const defaultTabs: BottomTab[] = [
  { id: 'event-log', label: 'Event Log', type: 'event-log', closeable: false },
  { id: 'dashboard', label: 'Dashboard', type: 'dashboard', closeable: false },
  { id: 'listeners', label: 'Listeners', type: 'listeners', closeable: false },
  { id: 'plugins', label: 'Plugins', type: 'plugins', closeable: false },
  { id: 'artifacts', label: 'Artifacts', type: 'artifacts', closeable: false },
  { id: 'credentials', label: 'Credentials', type: 'credentials', closeable: false },
  { id: 'chat', label: 'Chat', type: 'chat', closeable: false },
  { id: 'webhooks', label: 'Webhooks', type: 'webhooks', closeable: false },
  { id: 'autotasks', label: 'Auto-Tasks', type: 'autotasks', closeable: false },
  { id: 'reports', label: 'Reports', type: 'reports', closeable: false },
  { id: 'campaigns', label: 'Campaigns', type: 'campaigns', closeable: false },
  { id: 'operators', label: 'Operators', type: 'operators', closeable: false },
  { id: 'hosted-files', label: 'Hosted Files', type: 'hosted-files', closeable: false },
  { id: 'profiles', label: 'Profiles', type: 'profiles', closeable: false },
  { id: 'assembly', label: '.NET Assembly', type: 'assembly', closeable: false },
  { id: 'settings', label: 'Settings', type: 'settings', closeable: false },
];

export const useUIStore = create<UIState>((set) => ({
  bottomTabs: defaultTabs,
  activeBottomTab: 'dashboard',
  activeBottomTabId: 'dashboard',
  sidebarCollapsed: false,
  showPayloadGenerator: false,
  showBOFPanel: false,
  showPluginManager: false,
  showCradleDialog: false,
  showAssemblyPanel: false,
  showLateralWizard: false,
  lateralWizardAgentId: '',
  wsConnected: false,

  setActiveBottomTab: (id) => set({ activeBottomTab: id, activeBottomTabId: id }),

  openAgentTab: (agentId, hostname) => {
    set((s) => {
      const tabId = `agent-${agentId}`;
      const exists = s.bottomTabs.find((t) => t.id === tabId);
      if (exists) {
        return { activeBottomTab: tabId, activeBottomTabId: tabId };
      }
      return {
        bottomTabs: [
          ...s.bottomTabs,
          { id: tabId, label: hostname, type: 'agent', closeable: true, agentId },
        ],
        activeBottomTab: tabId,
        activeBottomTabId: tabId,
      };
    });
  },

  openAgentSubTab: (agentId, hostname, subType) => {
    set((s) => {
      const tabId = `${subType}-${agentId}`;
      const exists = s.bottomTabs.find((t) => t.id === tabId);
      if (exists) {
        return { activeBottomTab: tabId, activeBottomTabId: tabId };
      }
      const label = `${hostname} - ${subType.charAt(0).toUpperCase() + subType.slice(1)}`;
      return {
        bottomTabs: [
          ...s.bottomTabs,
          { id: tabId, label, type: subType, closeable: true, agentId },
        ],
        activeBottomTab: tabId,
        activeBottomTabId: tabId,
      };
    });
  },

  closeBottomTab: (id) => {
    set((s) => {
      const tab = s.bottomTabs.find((t) => t.id === id);
      if (!tab || !tab.closeable) return s;
      const filtered = s.bottomTabs.filter((t) => t.id !== id);
      const newActive = s.activeBottomTab === id ? 'dashboard' : s.activeBottomTab;
      return { bottomTabs: filtered, activeBottomTab: newActive, activeBottomTabId: newActive };
    });
  },

  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),

  setShowPayloadGenerator: (show) => set({ showPayloadGenerator: show }),
  setShowBOFPanel: (show) => set({ showBOFPanel: show }),
  setShowPluginManager: (show) => set({ showPluginManager: show }),
  setShowCradleDialog: (show) => set({ showCradleDialog: show }),
  setShowAssemblyPanel: (show) => set({ showAssemblyPanel: show }),
  setShowLateralWizard: (show, agentId) => set({ showLateralWizard: show, lateralWizardAgentId: agentId || '' }),
  setWsConnected: (connected) => set({ wsConnected: connected }),
}));
