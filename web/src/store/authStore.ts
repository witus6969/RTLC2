import { create } from 'zustand';
import { api } from '../api/client';
import type { Operator } from '../types';

interface AuthState {
  token: string | null;
  username: string | null;
  role: string | null;
  operator: Operator | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;

  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  restoreSession: () => void;
  isAdmin: () => boolean;
  isOperator: () => boolean;
}

export const useAuthStore = create<AuthState>((set, get) => {
  // Set up 401 handler
  api.setOnUnauthorized(() => {
    set({ token: null, username: null, role: null, operator: null, isAuthenticated: false });
    sessionStorage.removeItem('rtlc2_token');
    sessionStorage.removeItem('rtlc2_username');
    sessionStorage.removeItem('rtlc2_role');
  });

  return {
    token: null,
    username: null,
    role: null,
    operator: null,
    isAuthenticated: false,
    isLoading: false,
    error: null,

    login: async (username: string, password: string) => {
      set({ isLoading: true, error: null });
      try {
        const res = await api.login(username, password);
        api.setToken(res.token);
        sessionStorage.setItem('rtlc2_token', res.token);
        sessionStorage.setItem('rtlc2_username', res.operator.username);
        sessionStorage.setItem('rtlc2_role', res.operator.role);
        set({
          token: res.token,
          username: res.operator.username,
          role: res.operator.role,
          operator: res.operator,
          isAuthenticated: true,
          isLoading: false,
        });
      } catch (err: any) {
        set({ isLoading: false, error: err.message || 'Login failed' });
        throw err;
      }
    },

    logout: () => {
      api.logout().catch(() => {});
      api.setToken(null);
      sessionStorage.removeItem('rtlc2_token');
      sessionStorage.removeItem('rtlc2_username');
      sessionStorage.removeItem('rtlc2_role');
      set({ token: null, username: null, role: null, operator: null, isAuthenticated: false });
    },

    restoreSession: () => {
      const token = sessionStorage.getItem('rtlc2_token');
      const username = sessionStorage.getItem('rtlc2_username');
      const role = sessionStorage.getItem('rtlc2_role');
      if (token && username) {
        api.setToken(token);
        set({ token, username, role, isAuthenticated: true });
      }
    },

    isAdmin: (): boolean => {
      return get().role === 'admin';
    },

    isOperator: (): boolean => {
      const r = get().role;
      return r === 'admin' || r === 'operator';
    },
  };
});
