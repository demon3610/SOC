import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export const useProjectStore = create(persist(
  (set) => ({
    activeProject: null,
    setActiveProject: (project) => set({ activeProject: project }),
  }),
  { name: 'soc-active-project' }
));
