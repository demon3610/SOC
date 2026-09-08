import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { ArrowLeft, ChevronDown, Link2, Plus } from 'lucide-react';
import { api } from '../lib/api';
import { formatLocalDate, formatLocalTime } from '../lib/time';
import { PageHeader } from '../components/ui/PageHeader';
import { useProjectStore } from '../stores/projectStore';

function parseSnapshot(ev) {
  try {
    const snap = JSON.parse(ev.event_snapshot);
    return snap && typeof snap === 'object' ? snap : null;
  } catch {
    return null;
  }
}

function evOs(snap) {
  const map = { windows: 'Windows', linux: 'Linux', website: 'Web' };
  const source = snap?.source;
  return map[source] || source || null;
}

function evHostname(snap) {
  return snap?.hostname || snap?.raw?.hostname || null;
}

function evIp(snap) {
  const pairs = [
    snap?.enriched?.ip,
    snap?.parsed?.ip,
    snap?.parsed?.src_ip,
    snap?.raw?.ip,
    snap?.raw?.src_ip,
  ];
  for (const ip of pairs) {
    if (ip && ip !== '' && ip !== 'unknown' && ip !== 'local') return ip;
  }
  return null;
}

function evRisk(snap) {
  const score = snap?.enriched?.risk_score;
  return typeof score === 'number' ? score : 0;
}

function riskBadgeClass(score) {
  if (score >= 70) return 'bg-red-500/12 text-red-600';
  if (score >= 40) return 'bg-amber-500/15 text-amber-600';
  if (score >= 15) return 'bg-blue-500/12 text-blue-600';
  return 'bg-soc-panel text-soc-muted';
}

function severityBadgeClass(sev) {
  if (sev === 'critical') return 'bg-red-500/12 text-red-600';
  if (sev === 'high') return 'bg-amber-500/15 text-amber-600';
  if (sev === 'medium') return 'bg-sky-500/12 text-sky-600';
  return 'bg-emerald-500/12 text-emerald-600';
}

function statusBadgeClass(status) {
  if (status === 'resolved') return 'bg-emerald-500/12 text-emerald-600';
  if (status === 'investigating') return 'bg-amber-500/15 text-amber-600';
  return 'bg-soc-panel text-soc-muted';
}

function Chip({ label, className }) {
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border border-soc-border/60 ${className || 'bg-soc-panel text-soc-muted'}`}>
      {label}
    </span>
  );
}

const ACTION_LABEL = {
  created: 'created incident',
  status_changed: 'changed status',
  severity_changed: 'changed severity',
  note_added: 'added note',
  evidence_attached: 'attached evidence',
  mitigation_added: 'added mitigation item',
  mitigation_toggled: 'toggled mitigation item',
};

function EvidencePickerModal({ open, projectId, incidentId, onClose, onAdded }) {
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [adding, setAdding] = useState(false);
  const queryClient = useQueryClient();

  const { data } = useQuery({
    queryKey: ['evidence-picker', projectId, search],
    queryFn: () => api.events.list(projectId, { query: search || undefined, size: 100 }),
    enabled: open && !!projectId,
  });

  useEffect(() => {
    if (open) {
      setSelected(new Set());
      setSearch('');
    }
  }, [open]);

  const addMutation = useMutation({
    mutationFn: async (events) => {
      for (const ev of events) {
        await api.incidents.addEvidence(incidentId, {
          event_snapshot: JSON.stringify(ev),
          source_event_id: ev.id,
        });
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence', incidentId] });
      onAdded?.();
      onClose();
    },
  });

  if (!open) return null;
  const events = data?.events || [];

  const toggle = (id) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95 }}
        animate={{ scale: 1 }}
        className="glass-elevated rounded-xl w-full max-w-2xl max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-4 border-b border-soc-border">
          <h2 className="text-lg font-semibold text-soc-text">Add Evidence from Live Events</h2>
          <p className="text-xs text-soc-muted mt-0.5">Select events to attach to this incident ({selected.size} selected)</p>
        </div>
        <div className="p-3 border-b border-soc-border">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search events…"
            className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent"
          />
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {events.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-soc-muted">
              <span className="text-3xl mb-2">📄</span>
              <p className="text-xs">No events found</p>
            </div>
          ) : (
            events.map((ev) => (
              <button
                key={ev.id}
                onClick={() => toggle(ev.id)}
                className={`w-full flex items-start gap-3 p-2.5 rounded-lg border text-left transition-colors ${
                  selected.has(ev.id)
                    ? 'bg-soc-accent/15 border-soc-accent/40'
                    : 'bg-soc-card border-soc-border/60 hover:bg-soc-panel'
                }`}
              >
                <span className={`mt-0.5 w-4 h-4 shrink-0 rounded border flex items-center justify-center text-[10px] ${
                  selected.has(ev.id) ? 'bg-soc-accent border-soc-accent text-white' : 'border-soc-border'
                }`}>
                  {selected.has(ev.id) ? '✔' : ''}
                </span>
                <span className="flex-1 min-w-0">
                  <span className="flex items-center gap-2 mb-0.5">
                    <span className="text-[10px] text-soc-muted-cool">{formatLocalTime(ev.timestamp)}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                      ev.event_type === 'critical' ? 'bg-red-500/12 text-red-600' :
                      ev.event_type === 'high' ? 'bg-amber-500/15 text-amber-600' :
                      'bg-soc-panel text-soc-muted'
                    }`}>{ev.event_type}</span>
                    <span className="text-[10px] text-soc-muted/50">{ev.source}</span>
                  </span>
                  <span className="block text-sm text-soc-muted truncate">
                    {ev.summary || ev.raw?.message || ev.id}
                  </span>
                </span>
              </button>
            ))
          )}
        </div>
        <div className="p-3 border-t border-soc-border flex items-center justify-between">
          <span className="text-xs text-soc-muted">{events.length} events loaded</span>
          <div className="flex gap-3">
            <button onClick={onClose} className="text-sm text-soc-muted">Cancel</button>
            <button
              onClick={() => addMutation.mutate(events.filter((e) => selected.has(e.id)))}
              disabled={selected.size === 0 || addMutation.isPending}
              className="bg-soc-accent hover:bg-soc-accent-glow text-white px-4 py-1.5 rounded-lg text-xs disabled:opacity-50"
            >
              {addMutation.isPending ? 'Adding…' : `Attach ${selected.size} event${selected.size === 1 ? '' : 's'}`}
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

function ChainPickerModal({ open, projectId, incidentId, evidence, onClose, onAttached }) {
  const [attaching, setAttaching] = useState(null);
  const queryClient = useQueryClient();

  const { data } = useQuery({
    queryKey: ['chain-picker', projectId],
    queryFn: () => api.threatIntel.narratives(projectId, 72),
    enabled: open && !!projectId,
  });

  if (!open) return null;
  const all = data?.narratives || [];
  const evidenceHosts = new Set(
    (evidence || []).map((ev) => evHostname(parseSnapshot(ev))).filter(Boolean)
  );
  const narratives = evidenceHosts.size
    ? all.filter((n) => evidenceHosts.has(n.hostname))
    : all;

  const attach = async (n) => {
    setAttaching(n.hostname);
    try {
      await api.incidents.attachChain(incidentId, {
        hostname: n.hostname,
        start_time: n.start_time,
        end_time: n.end_time,
      });
      queryClient.invalidateQueries({ queryKey: ['evidence', incidentId] });
      queryClient.invalidateQueries({ queryKey: ['incident', incidentId] });
      queryClient.invalidateQueries({ queryKey: ['incident-activity', incidentId] });
      onAttached?.();
      onClose();
    } finally {
      setAttaching(null);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95 }}
        animate={{ scale: 1 }}
        className="glass-elevated rounded-xl w-full max-w-xl max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-4 border-b border-soc-border">
          <h2 className="text-lg font-semibold text-soc-text">Attach a correlated chain</h2>
          <p className="text-xs text-soc-muted mt-0.5">
            {evidenceHosts.size
              ? `Recent Attack Narratives matching this incident's evidence (${[...evidenceHosts].join(', ')})`
              : 'Recent Attack Narratives for this project'}
          </p>
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-2">
          {narratives.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-soc-muted">
              <span className="text-3xl mb-2">🔗</span>
              <p className="text-xs">No correlated chains found in the last 72h</p>
            </div>
          ) : (
            narratives.map((n) => (
              <div key={`${n.hostname}-${n.start_time}`} className="bg-soc-card border border-soc-border/60 rounded-lg px-3 py-2.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs font-semibold text-soc-text">{n.hostname}</span>
                  <span className="text-[10px] text-soc-muted">
                    {formatLocalDate(n.start_time)} {formatLocalTime(n.start_time)} → {formatLocalTime(n.end_time)} · {n.event_count} events
                  </span>
                  <span className="text-[10px] text-soc-muted/70">
                    {[...new Set(n.chain.map((s) => s.tactic).filter(Boolean))].slice(0, 3).join(', ') || 'no tactics'}
                  </span>
                  <button
                    onClick={() => attach(n)}
                    disabled={attaching !== null}
                    className="ml-auto text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-2.5 py-1 rounded disabled:opacity-50"
                  >
                    {attaching === n.hostname ? 'Attaching…' : 'Attach chain'}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
        <div className="p-3 border-t border-soc-border flex justify-end">
          <button onClick={onClose} className="text-sm text-soc-muted">Close</button>
        </div>
      </motion.div>
    </motion.div>
  );
}

export function IncidentDetailPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const { incidentId } = useParams();
  const iid = Number(incidentId);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [note, setNote] = useState('');
  const [pickerOpen, setPickerOpen] = useState(false);
  const [chainPickerOpen, setChainPickerOpen] = useState(false);
  const [savedFlash, setSavedFlash] = useState('');
  const [openRaw, setOpenRaw] = useState({});
  const [newMitigation, setNewMitigation] = useState('');

  const { data: incident, refetch } = useQuery({
    queryKey: ['incident', iid],
    queryFn: () => api.incidents.get(iid),
    enabled: !!iid,
  });

  const { data: evidence, refetch: refetchEvidence } = useQuery({
    queryKey: ['evidence', iid],
    queryFn: () => api.incidents.listEvidence(iid),
    enabled: !!iid,
  });

  const { data: activity } = useQuery({
    queryKey: ['incident-activity', iid],
    queryFn: () => api.incidents.activity(iid),
    enabled: !!iid,
    refetchInterval: 30000,
  });

  const { data: suggestions } = useQuery({
    queryKey: ['mitigation-suggestions', pid, iid],
    queryFn: () => api.incidents.mitigationSuggestions(pid, iid),
    enabled: !!pid && !!iid,
  });

  const addNoteMutation = useMutation({
    mutationFn: (text) => api.incidents.addNote(iid, { text }),
    onSuccess: () => {
      setNote('');
      refetch();
      queryClient.invalidateQueries({ queryKey: ['incident-activity', iid] });
    },
  });

  const addMitigationMutation = useMutation({
    mutationFn: (text) => api.incidents.addMitigation(pid, iid, text),
    onSuccess: () => {
      setNewMitigation('');
      refetch();
      queryClient.invalidateQueries({ queryKey: ['incident-activity', iid] });
    },
  });

  const toggleMitigationMutation = useMutation({
    mutationFn: ({ itemId, done }) => api.incidents.toggleMitigation(pid, iid, itemId, done),
    onSuccess: () => {
      refetch();
      queryClient.invalidateQueries({ queryKey: ['incident-activity', iid] });
    },
  });

  const handleUpdate = async (field, value) => {
    setSavedFlash('Saving…');
    try {
      await api.incidents.update(iid, { [field]: value });
      setSavedFlash('Saved ✔');
      refetch();
      queryClient.invalidateQueries({ queryKey: ['incident-activity', iid] });
    } catch {
      setSavedFlash('Save failed');
    }
    setTimeout(() => setSavedFlash(''), 2500);
  };

  if (!incident) return null;

  const chips = [
    { label: `Severity: ${incident.severity}`, className: severityBadgeClass(incident.severity) },
    { label: `Status: ${incident.status}`, className: statusBadgeClass(incident.status) },
    incident.risk_score != null && { label: `Risk Score: ${incident.risk_score}`, className: riskBadgeClass(incident.risk_score) },
    ...(incident.os_types || []).map((os) => ({ label: `OS: ${os}`, className: 'bg-soc-panel text-soc-muted' })),
    incident.primary_ip
      ? { label: `IP: ${incident.primary_ip}`, className: 'bg-soc-tint-neutral text-slate-600' }
      : { label: 'IP: Not captured', className: 'bg-soc-panel text-soc-muted' },
    ...(incident.mitre_tags || []).map((tag) => ({
      label: `${tag.tactic}${tag.technique ? ` · ${tag.technique}` : ''}`,
      className: 'bg-soc-accent/10 text-soc-accent border-soc-accent/30',
    })),
  ].filter(Boolean);

  const mitigation = incident.mitigation || [];

  return (
    <div>
      <button
        onClick={() => navigate(`/incidents`)}
        className="flex items-center gap-1.5 text-xs text-soc-muted hover:text-soc-accent mb-4 transition-colors"
      >
        <ArrowLeft size={13} />
        Back to Incidents
      </button>
      <PageHeader title="Incident Detail" />
      <div className="glass-card rounded-xl p-6 mb-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1">
            <input
              defaultValue={incident.title}
              onBlur={(e) => handleUpdate('title', e.target.value)}
              className="text-xl font-bold bg-transparent border-b border-transparent hover:border-soc-accent/40 focus:border-soc-accent focus:outline-none w-full"
            />
          </div>
          <div className="flex items-center gap-2 ml-4">
            <span className="text-xs text-soc-muted min-w-16 text-right">{savedFlash}</span>
            <select
              defaultValue={incident.severity}
              onChange={(e) => handleUpdate('severity', e.target.value)}
              className="bg-white border border-soc-border rounded-lg px-2 py-1 text-xs"
            >
              {['critical', 'high', 'medium', 'low'].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select
              defaultValue={incident.status}
              onChange={(e) => handleUpdate('status', e.target.value)}
              className="bg-white border border-soc-border rounded-lg px-2 py-1 text-xs"
            >
              {['open', 'investigating', 'resolved'].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 mb-4">
          {chips.map((chip) => (
            <Chip key={chip.label} label={chip.label} className={chip.className} />
          ))}
          <span className="text-[10px] text-soc-muted ml-2">
            Created {formatLocalDate(incident.created_at)} · Updated {formatLocalDate(incident.updated_at)}
          </span>
        </div>
        <textarea
          defaultValue={incident.description || ''}
          onBlur={(e) => handleUpdate('description', e.target.value)}
          placeholder="Description..."
          className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent min-h-[80px]"
        />
      </div>

      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-soc-text">Evidence Timeline</h2>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setChainPickerOpen(true)}
            className="flex items-center gap-1.5 text-xs bg-soc-card border border-soc-border/70 hover:border-soc-accent/50 text-soc-text px-3 py-1.5 rounded-lg transition-colors"
          >
            <Link2 size={13} />
            Attach a correlated chain
          </button>
          <button
            onClick={() => setPickerOpen(true)}
            className="flex items-center gap-1.5 text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-3 py-1.5 rounded-lg"
          >
            <Plus size={13} />
            Add Evidence from Live Events
          </button>
        </div>
      </div>
      {evidence && evidence.length > 0 ? (
        <div className="space-y-2 mb-6">
          {evidence.map((ev) => {
            const snapshot = parseSnapshot(ev);
            const summary = snapshot?.summary || snapshot?.raw?.message || '';
            const os = evOs(snapshot);
            const host = evHostname(snapshot);
            const ip = evIp(snapshot);
            const risk = evRisk(snapshot);
            const mitre = snapshot?.mitre;
            return (
              <div key={ev.id} className="glass-card rounded-xl p-4">
                <div className="flex flex-wrap items-center gap-1.5 mb-2 text-[10px]">
                  <span className="font-mono bg-soc-panel px-1.5 py-0.5 rounded">{ev.source_event_id}</span>
                  {snapshot?.event_type && (
                    <span className={`px-1.5 py-0.5 rounded ${
                      snapshot.event_type === 'critical' ? 'bg-red-500/12 text-red-600' :
                      snapshot.event_type === 'high' ? 'bg-amber-500/15 text-amber-600' :
                      'bg-soc-panel text-soc-muted'
                    }`}>{snapshot.event_type}</span>
                  )}
                  {host && <span className="px-1.5 py-0.5 rounded bg-soc-panel text-soc-muted font-mono">{host}</span>}
                  {os && <span className="px-1.5 py-0.5 rounded bg-soc-panel text-soc-muted">OS: {os}</span>}
                  {ip
                    ? <span className="px-1.5 py-0.5 rounded bg-soc-tint-neutral text-slate-600">IP: {ip}</span>
                    : <span className="px-1.5 py-0.5 rounded bg-soc-panel text-soc-muted">IP: Not captured</span>}
                  <span className={`px-1.5 py-0.5 rounded font-semibold ${riskBadgeClass(risk)}`}>Risk: {risk}</span>
                  {mitre?.tactic && (
                    <span className="px-1.5 py-0.5 rounded bg-soc-accent/10 text-soc-accent border border-soc-accent/30">
                      {mitre.tactic}{mitre.technique ? ` · ${mitre.technique}` : ''}
                    </span>
                  )}
                  {snapshot?.enriched?.form?.name && (
                    <span className="px-1.5 py-0.5 rounded bg-soc-tint-steel text-blue-700">
                      Form: {snapshot.enriched.form.name}
                      {snapshot.enriched.form.timing_ms != null ? ` · ${snapshot.enriched.form.timing_ms}ms` : ''}
                    </span>
                  )}
                  <span className="text-soc-muted-cool ml-auto">{formatLocalDate(ev.added_at)}</span>
                </div>
                {summary && <p className="text-sm text-soc-text mb-2">{summary}</p>}
                <button
                  onClick={() => setOpenRaw((prev) => ({ ...prev, [ev.id]: !prev[ev.id] }))}
                  className="flex items-center gap-1 text-[10px] text-soc-muted hover:text-soc-accent transition-colors"
                >
                  <ChevronDown size={11} className={`transition-transform ${openRaw[ev.id] ? 'rotate-180' : ''}`} />
                  {openRaw[ev.id] ? 'Hide raw log' : 'View raw log'}
                </button>
                {openRaw[ev.id] && (
                  <pre className="bg-soc-code border border-soc-border rounded p-2 text-xs font-mono overflow-x-auto max-h-60 mt-2">
                    {JSON.stringify(snapshot || ev.event_snapshot, null, 2)}
                  </pre>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="glass-card rounded-xl p-4 mb-6 text-center text-sm text-soc-muted">
          No evidence attached yet.
          <button onClick={() => setPickerOpen(true)} className="text-soc-accent hover:underline ml-1">
            Add events from Live Events →
          </button>
        </div>
      )}

      <h2 className="text-lg font-semibold mb-3 text-soc-text">Mitigation Checklist</h2>
      <div className="glass-card rounded-xl p-4 mb-6">
        {mitigation.length > 0 ? (
          <ul className="space-y-1.5 mb-3">
            {mitigation.map((item) => (
              <li key={item.id} className="flex items-start gap-2.5 bg-soc-card border border-soc-border/60 rounded-lg px-3 py-2">
                <button
                  onClick={() => toggleMitigationMutation.mutate({ itemId: item.id, done: !item.done })}
                  className={`mt-0.5 w-4 h-4 shrink-0 rounded border flex items-center justify-center text-[10px] transition-colors ${
                    item.done ? 'bg-emerald-500/20 border-emerald-500/60 text-emerald-700' : 'border-soc-border bg-white hover:border-soc-accent/50'
                  }`}
                >
                  {item.done ? '✔' : ''}
                </button>
                <span className="flex-1 min-w-0">
                  <span className={`block text-sm ${item.done ? 'line-through text-soc-muted' : 'text-soc-text'}`}>
                    {item.text}
                  </span>
                  {item.done && (
                    <span className="text-[10px] text-soc-muted">
                      completed by {item.completed_by_name || `User #${item.completed_by}`} at {formatLocalDate(item.completed_at)}
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-soc-muted mb-3">No mitigation items yet — add one below or pick a suggestion.</p>
        )}
        {suggestions?.suggestions?.length > 0 && (
          <div className="mb-3">
            {suggestions.suggestions.map((s) => (
              <div key={s.tactic} className="mb-1.5">
                <span className="text-[10px] font-semibold text-soc-accent">{s.tactic}</span>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {s.items.map((text) => (
                    <button
                      key={text}
                      onClick={() => addMitigationMutation.mutate(text)}
                      disabled={addMitigationMutation.isPending}
                      className="text-[11px] border border-dashed border-soc-accent/40 text-soc-accent hover:bg-soc-accent/10 rounded-full px-2.5 py-0.5 transition-colors disabled:opacity-50"
                    >
                      + {text}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <input
            value={newMitigation}
            onChange={(e) => setNewMitigation(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && newMitigation.trim()) addMitigationMutation.mutate(newMitigation.trim());
            }}
            placeholder="Add a mitigation item…"
            className="flex-1 bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent"
          />
          <button
            onClick={() => addMitigationMutation.mutate(newMitigation.trim())}
            disabled={!newMitigation.trim() || addMitigationMutation.isPending}
            className="bg-soc-accent hover:bg-soc-accent-glow text-white px-3 py-1.5 rounded text-xs disabled:opacity-50"
          >
            {addMitigationMutation.isPending ? 'Adding…' : 'Add item'}
          </button>
        </div>
      </div>

      <h2 className="text-lg font-semibold mb-3 text-soc-text">Notes</h2>
      <div className="glass-card rounded-xl p-4 mb-6">
        {incident.notes && incident.notes.length > 0 && (
          <ul className="space-y-2 mb-3">
            {incident.notes.map((n) => (
              <li key={n.id} className="flex items-start justify-between gap-3 bg-soc-card border border-soc-border rounded-lg px-3 py-2">
                <span className="text-sm text-soc-text whitespace-pre-wrap">{n.text}</span>
                <span className="text-[10px] text-soc-muted shrink-0 pt-0.5">{formatLocalDate(n.added_at)}</span>
              </li>
            ))}
          </ul>
        )}
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Add a note..."
          className="w-full bg-soc-card border border-soc-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-soc-accent min-h-[60px]"
        />
        <button
          onClick={() => addNoteMutation.mutate(note)}
          disabled={!note.trim() || addNoteMutation.isPending}
          className="mt-2 bg-soc-accent hover:bg-soc-accent-glow text-white px-3 py-1.5 rounded text-xs disabled:opacity-50"
        >
          {addNoteMutation.isPending ? 'Adding…' : 'Add Note'}
        </button>
      </div>

      <h2 className="text-lg font-semibold mb-3 text-soc-text">Activity Log</h2>
      <div className="glass-card rounded-xl p-4">
        {activity && activity.length > 0 ? (
          <ul className="space-y-2">
            {activity.map((a) => (
              <li key={a.id} className="flex items-start justify-between gap-3 text-sm">
                <span className="text-soc-text">
                  <span className="font-medium">{a.user_name}</span>{' '}
                  <span className="text-soc-muted">
                    {ACTION_LABEL[a.action] || a.action}: {a.detail}
                  </span>
                </span>
                <span className="text-[10px] text-soc-muted shrink-0 pt-1">
                  {formatLocalDate(a.timestamp)} {formatLocalTime(a.timestamp)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-soc-muted">No activity recorded yet.</p>
        )}
      </div>

      <EvidencePickerModal
        open={pickerOpen}
        projectId={pid}
        incidentId={iid}
        onClose={() => setPickerOpen(false)}
        onAdded={() => {
          refetchEvidence();
          refetch();
          queryClient.invalidateQueries({ queryKey: ['incident-activity', iid] });
        }}
      />
      <ChainPickerModal
        open={chainPickerOpen}
        projectId={pid}
        incidentId={iid}
        evidence={evidence || []}
        onClose={() => setChainPickerOpen(false)}
        onAttached={() => {
          refetchEvidence();
          refetch();
          queryClient.invalidateQueries({ queryKey: ['incident-activity', iid] });
        }}
      />
    </div>
  );
}
