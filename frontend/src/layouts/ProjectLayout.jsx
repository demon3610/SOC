import { useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';

function PageSkeleton() {
  return (
    <div className="space-y-4">
      <div className="h-8 w-48 bg-soc-card rounded-lg animate-pulse" />
      <div className="h-40 bg-soc-card rounded-xl animate-pulse" />
      <div className="h-40 bg-soc-card rounded-xl animate-pulse" />
    </div>
  );
}

export function ProjectLayout({ children }) {
  const queryClient = useQueryClient();
  const setActiveProject = useProjectStore((s) => s.setActiveProject);

  const { data: project, isLoading, isError } = useQuery({
    queryKey: ['currentProject'],
    queryFn: () => api.projects.current(),
    retry: false,
  });

  useEffect(() => {
    if (project) setActiveProject(project);
  }, [project, setActiveProject]);

  // Multi-tab: another tab selected a different project — refresh the pointer
  // so this tab never silently shows a stale project.
  useEffect(() => {
    if (typeof BroadcastChannel === 'undefined') return;
    const channel = new BroadcastChannel('soc-project');
    channel.onmessage = (msg) => {
      if (msg.data?.type === 'project-changed') {
        queryClient.invalidateQueries({ queryKey: ['currentProject'] });
      }
    };
    return () => channel.close();
  }, [queryClient]);

  if (isError) {
    return <Navigate to="/workspace" replace />;
  }
  if (isLoading || !project) {
    return <PageSkeleton />;
  }
  return <>{children}</>;
}
