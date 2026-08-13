import { Navigate } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';

export function PublicRoute({ children }) {
  const initialized = useAuthStore((s) => s.initialized);
  const loading = useAuthStore((s) => s.loading);
  const user = useAuthStore((s) => s.user);

  if (!initialized || loading) {
    return (
      <div className="min-h-screen bg-soc-bg flex items-center justify-center">
        <div className="text-soc-muted text-sm animate-pulse">Loading...</div>
      </div>
    );
  }

  if (user) {
    return <Navigate to="/workspace" replace />;
  }

  return <>{children}</>;
}
