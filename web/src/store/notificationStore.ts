import { create } from 'zustand';

interface NotificationState {
    unreadCredentials: number;
    unreadEvents: number;
    newAgents: number;
    setUnreadCredentials: (n: number) => void;
    setUnreadEvents: (n: number) => void;
    setNewAgents: (n: number) => void;
    clearAll: () => void;
}

export const useNotificationStore = create<NotificationState>((set) => ({
    unreadCredentials: 0,
    unreadEvents: 0,
    newAgents: 0,
    setUnreadCredentials: (n) => set({ unreadCredentials: n }),
    setUnreadEvents: (n) => set({ unreadEvents: n }),
    setNewAgents: (n) => set({ newAgents: n }),
    clearAll: () => set({ unreadCredentials: 0, unreadEvents: 0, newAgents: 0 }),
}));
