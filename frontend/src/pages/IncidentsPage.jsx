import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { api } from '../lib/api';
import { PageHeader } from '../components/ui/PageHeader';

const SEV_CLASS = {
  critical: 'severity-critical', high: 'severity-high',
  medium: 'severity-medium', low: 'severity-low',
};

const STATUS_COLOR = {
  open: 'bg-red-50 text-red-600 border border-red-200',
  investigating: 'bg-amber-50 text-amber-600 border border-amber-200',
  resolved: 'bg-green-50 text-green-700 border border-green-200',
};

export function IncidentsPage() {
  const { projectId } = useParams();
  const pid = Number(projectId);
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('medium');

  const { data: incidents, isLoading, isError, refetch } = useQuery({
    queryKey: ['incidents', pid],
    queryFn: () => api.incidents.list(pid),
    enabled: !!pid,
  });

  const handleCreate = async () => {
    await api.incidents.create(pid, { title, severity });
    setShowCreate(false);
    setTitle('');
    setSeverity('medium');
    refetch();
  };

  return (
    <div>
      <PageHeader
        title="Incidents"
        right={
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm font-medium"
          >
            <Plus size={15} />
            New Incident
          </button>
        }
      />
      {isLoading ? (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="glass-card rounded-xl p-4 animate-pulse">
              <div className="h-4 bg-soc-panel rounded w-1/3 mb-2" />
              <div className="h-3 bg-soc-card rounded w-1/2" />
            </div>
          ))}
        </div>
      ) : isError ? (
        <div className="flex flex-col items-center justify-center py-16 text-soc-muted">
          <span className="text-4xl mb-2">⚠</span>
          <p className="text-sm text-red-600">Failed to load incidents</p>
          <button onClick={() => refetch()} className="mt-3 text-xs bg-white border border-soc-border hover:bg-soc-panel px-3 py-1.5 rounded transition-colors">
            Retry
          </button>
        </div>
      ) : incidents && incidents.length > 0 ? (
        <div className="space-y-3">
          {incidents.map((inc) => (
            <Link
              key={inc.id}
              to={`/projects/${pid}/incidents/${inc.id}`}
              className={`block glass-card rounded-xl p-4 hover:border-soc-accent/40 hover:shadow-lift transition-all ${SEV_CLASS[inc.severity] || ''}`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-sm text-soc-text">{inc.title}</h3>
                  {inc.description && (
                    <p className="text-xs text-soc-muted mt-0.5">{inc.description}</p>
                  )}
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-soc-muted-cool">
                    {new Date(inc.created_at).toLocaleDateString()}
                  </span>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${STATUS_COLOR[inc.status] || ''}`}>
                    {inc.status}
                  </span>
                  <span className="text-xs text-soc-muted">{inc.evidence_count} evidence</span>
                </div>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-16 text-soc-muted">
          <span className="text-4xl mb-2">⚠️</span>
          <p className="text-sm">No incidents yet</p>
          <p className="text-xs mt-1">Create an incident from a Live Event or click "New Incident"</p>
        </div>
      )}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60">
          <div className="glass-elevated rounded-xl p-6 w-full max-w-md mx-4">
            <h2 className="text-lg font-semibold mb-4 text-soc-slate">New Incident</h2>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Incident title"
              className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm mb-3 focus:outline-none focus:border-soc-accent"
            />
              <div className="flex gap-2 mb-4">
                {['low', 'medium', 'high', 'critical'].map((s) => (
                  <button
                    key={s}
                    onClick={() => setSeverity(s)}
                    className={`px-3 py-1.5 rounded-full text-xs border font-medium ${
                      severity === s
                        ? 'bg-soc-accent border-soc-accent text-white'
                        : 'bg-white border-soc-border text-soc-muted'
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowCreate(false)} className="text-sm text-soc-muted">Cancel</button>
              <button
                onClick={handleCreate}
                disabled={!title}
                className="bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm disabled:opacity-50"
              >
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
