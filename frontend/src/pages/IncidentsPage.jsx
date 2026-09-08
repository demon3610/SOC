import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { FileDown, Plus } from 'lucide-react';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';
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

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function IncidentsPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const navigate = useNavigate();
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('medium');
  const [selected, setSelected] = useState(new Set());
  const [selMode, setSelMode] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState('');

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

  const toggleSelect = (id) => {
    setGenError('');
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    setGenError('');
    setSelected((prev) =>
      prev.size === (incidents?.length || 0) ? new Set() : new Set((incidents || []).map((i) => i.id))
    );
  };

  const handleBulkPdf = async () => {
    if (!selected.size) return;
    setGenerating(true);
    setGenError('');
    try {
      if (selected.size === 1) {
        const id = [...selected][0];
        const blob = await api.incidents.reportPdf(pid, id);
        downloadBlob(blob, `incident-report-${id}.pdf`);
      } else {
        const blob = await api.incidents.bulkReports(pid, [...selected]);
        downloadBlob(blob, `incident-reports-${pid}.zip`);
      }
      clearSelection();
      setSelMode(false);
    } catch (err) {
      setGenError(err.message);
    } finally {
      setGenerating(false);
    }
  };

  const clearSelection = () => setSelected(new Set());

  const startSelection = () => {
    setGenError('');
    setSelMode(true);
  };

  const cancelSelection = () => {
    setSelMode(false);
    setSelected(new Set());
    setGenError('');
  };

  return (
    <div>
      <PageHeader
        title="Incidents"
        right={
          <div className="flex items-center gap-2">
            <button
              onClick={selMode ? handleBulkPdf : startSelection}
              disabled={generating}
              className="flex items-center gap-1.5 text-soc-muted bg-soc-card border border-soc-border hover:border-soc-accent/50 hover:text-soc-accent px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
            >
              <FileDown size={15} />
              {generating ? 'Generating…' : selMode ? `Generate PDF (${selected.size})` : 'Generate PDF'}
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-1.5 bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-2 rounded-lg text-sm font-medium"
            >
              <Plus size={15} />
              New Incident
            </button>
          </div>
        }
      />
      {selMode && (
        <div className="sticky top-0 z-30 mb-4 flex items-center gap-3 glass-elevated rounded-xl px-4 py-2.5">
          <span className="text-xs font-medium text-soc-text">
            {selected.size === 0
              ? 'Select incidents to export — one gives a PDF, multiple give a zip'
              : `${selected.size} selected — ${selected.size === 1 ? 'single PDF' : 'zip with all reports'}`}
          </span>
          <button
            onClick={cancelSelection}
            className="text-xs text-soc-muted hover:text-soc-accent"
          >
            Cancel
          </button>
          <button
            onClick={handleBulkPdf}
            disabled={generating || !selected.size}
            className="ml-auto flex items-center gap-1.5 text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-3 py-1.5 rounded-lg disabled:opacity-50"
          >
            <FileDown size={13} />
            {generating ? 'Generating…' : `Generate PDF (${selected.size} selected)`}
          </button>
          {genError && <span className="text-xs text-red-600">{genError}</span>}
        </div>
      )}
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
          {incidents.map((inc) => {
            const checked = selected.has(inc.id);
            return (
              <div
                key={inc.id}
                role="button"
                tabIndex={0}
                onClick={() => (selMode ? toggleSelect(inc.id) : navigate(`/incidents/${inc.id}`))}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    if (selMode) toggleSelect(inc.id);
                    else navigate(`/incidents/${inc.id}`);
                  }
                }}
                className={`block glass-card rounded-xl p-4 hover:border-soc-accent/40 hover:shadow-lift transition-all cursor-pointer ${SEV_CLASS[inc.severity] || ''} ${selMode && checked ? 'border-soc-accent shadow-lift' : ''}`}
              >
                <div className="flex items-center gap-3">
                  {selMode && (
                    <span
                      role="checkbox"
                      aria-checked={checked}
                      tabIndex={-1}
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleSelect(inc.id);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.stopPropagation();
                          toggleSelect(inc.id);
                        }
                      }}
                      className={`mt-0.5 w-4.5 h-4.5 shrink-0 rounded border flex items-center justify-center text-[10px] transition-colors ${
                        checked ? 'bg-soc-accent border-soc-accent text-white' : 'border-soc-border bg-white hover:border-soc-accent/50'
                      }`}
                    >
                      {checked ? '✔' : ''}
                    </span>
                  )}
                  <div className="flex-1 min-w-0">
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
                  </div>
                </div>
              </div>
            );
          })}
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
