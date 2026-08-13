import { useEffect } from 'react';
import { Sidebar } from '../components/layout/Sidebar';
import { TopBar } from '../components/layout/TopBar';
import { FooterBar } from '../components/layout/FooterBar';
import { Toaster } from '../components/ui/Toaster';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';

export function AppShell({ children }) {
  const activeProject = useProjectStore((s) => s.activeProject);
  const setActiveProject = useProjectStore((s) => s.setActiveProject);

  useEffect(() => {
    if (!activeProject) return;
    let cancelled = false;
    api.projects
      .get(activeProject.id)
      .catch((err) => {
        if (err?.status === 404 && !cancelled) setActiveProject(null);
      });
    return () => {
      cancelled = true;
    };
  }, [activeProject?.id, setActiveProject]);

  return (
    <div className="min-h-screen bg-soc-bg">
      <Sidebar />
      <TopBar />
      <main className="pt-14 pb-10 ml-60 max-lg:ml-0 min-h-[calc(100vh-3.5rem)]">
        <div className="px-6 py-6 lg:px-8">{children}</div>
      </main>
      <FooterBar />
      <Toaster />
    </div>
  );
}