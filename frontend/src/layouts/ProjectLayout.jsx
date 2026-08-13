import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';

export function ProjectLayout({ children }) {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const activeProject = useProjectStore((s) => s.activeProject);
  const setActiveProject = useProjectStore((s) => s.setActiveProject);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    if (!projectId) return;
    const pid = Number(projectId);

    if (activeProject?.id === pid) return;

    let cancelled = false;
    api.projects.get(pid).then((project) => {
      if (!cancelled) {
        setActiveProject(project);
      }
    }).catch(() => {
      if (!cancelled) {
        setNotFound(true);
      }
    });
    return () => { cancelled = true; };
  }, [projectId]);

  if (notFound) {
    navigate('/workspace', { replace: true });
    return null;
  }

  return <>{children}</>;
}
