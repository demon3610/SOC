import { create } from 'zustand';
import { api } from '../lib/api';
import { queryClient } from '../lib/queryClient';
import { useProjectStore } from './projectStore';

export const useAuthStore = create((set) => ({
  user: null,
  loading: true,
  initialized: false,
  error: null,

  checkAuth: async () => {
    set({ loading: true, _token: localStorage.getItem('soc_token') });
    try {
      const res = await api.auth.meRaw();
      if (res.ok) {
        const body = await res.json();
        if (body && typeof body === 'object' && 'id' in body && 'email' in body && 'name' in body) {
          const user = {
            id: Number(body.id),
            email: String(body.email),
            name: String(body.name),
            created_at: String(body.created_at ?? ''),
          };
          set({ user, initialized: true, loading: false, error: null });
        } else {
          set({ user: null, initialized: true, loading: false, error: null });
        }
      } else {
        localStorage.removeItem('soc_token');
        set({ user: null, initialized: true, loading: false, error: null, _token: null });
      }
    } catch {
      set({ user: null, initialized: true, loading: false, error: 'Network error — cannot reach server' });
    }
  },

  _token: null,

  getToken: () => {
    const s = useAuthStore.getState();
    return s._token || localStorage.getItem('soc_token');
  },

  login: async (email, password) => {
    set({ error: null, loading: true });
    try {
      const res = await api.auth.login({ email, password });
      const token = res.token;
      if (token) {
        localStorage.setItem('soc_token', token);
        set({ _token: token });
      }
      queryClient.clear();
      useProjectStore.getState().setActiveProject(null);
      const meRes = await api.auth.meRaw();
      if (meRes.ok) {
        const user = await meRes.json();
        set({ user, loading: false, error: null });
      } else {
        const e = 'Login succeeded but failed to load profile';
        set({ user: null, loading: false, error: e });
        throw new Error(e);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Login failed';
      set({ user: null, loading: false, error: message });
      throw err instanceof Error ? err : new Error(message);
    }
  },

  register: async (email, password, name) => {
    set({ error: null, loading: true });
    try {
      const res = await api.auth.register({ email, password, name });
      const token = res.token;
      if (token) {
        localStorage.setItem('soc_token', token);
        set({ _token: token });
      }
      queryClient.clear();
      useProjectStore.getState().setActiveProject(null);
      const meRes = await api.auth.meRaw();
      if (meRes.ok) {
        const user = await meRes.json();
        set({ user, loading: false, error: null });
      } else {
        const e = 'Registration succeeded but failed to load profile';
        set({ user: null, loading: false, error: e });
        throw new Error(e);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      set({ user: null, loading: false, error: message });
      throw err instanceof Error ? err : new Error(message);
    }
  },

  logout: async () => {
    try {
      await api.auth.logout();
    } catch {
    }
    localStorage.removeItem('soc_token');
    queryClient.clear();
    useProjectStore.getState().setActiveProject(null);
    set({ user: null, loading: false, error: null, _token: null });
  },
}));
