import { create } from 'zustand';

export interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  duration: number;
  createdAt: number;
}

interface ToastState {
  toasts: Toast[];
  addToast: (type: Toast['type'], title: string, message: string, duration?: number) => void;
  removeToast: (id: string) => void;
}

let counter = 0;

export const useToastStore = create<ToastState>((set, get) => ({
  toasts: [],

  addToast: (type, title, message, duration = 5000) => {
    const id = `toast-${Date.now()}-${++counter}`;
    const toast: Toast = { id, type, title, message, duration, createdAt: Date.now() };

    set((s) => {
      const toasts = [...s.toasts, toast];
      // Keep max 5
      return { toasts: toasts.length > 5 ? toasts.slice(-5) : toasts };
    });

    // Auto-remove
    setTimeout(() => {
      get().removeToast(id);
    }, duration);
  },

  removeToast: (id) => {
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
  },
}));
