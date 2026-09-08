import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { Link2 } from 'lucide-react';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid, Legend,
} from 'recharts';
import { api } from '../lib/api';
import { useProjectStore } from '../stores/projectStore';
import { formatLocalTime, formatLocalDate, formatRelative } from '../lib/time';
import { useToastStore } from '../stores/toastStore';
import { CreateIncidentModal } from '../components/CreateIncidentModal';
import { PageHeader } from '../components/ui/PageHeader';

const COLORS = ['#2563EB', '#4F46E5', '#0D9488', '#B45309', '#7C3AED', '#0284C7', '#DC2626', '#EA580C'];
const WINDOWS = [
  { value: '24h', label: '24h' },
  { value: '7d', label: '7d' },
  { value: '30d', label: '30d' },
];

function flagEmoji(countryCode) {
  if (!countryCode || !/^[A-Za-z]{2}$/.test(countryCode)) return '';
  const cp = [...countryCode.toUpperCase()].map((c) => 127397 + c.charCodeAt(0));
  return String.fromCodePoint(...cp);
}

function sevPill(eventType) {
  const t = eventType || '';
  if (t === 'critical') return 'bg-red-500/12 text-red-600';
  if (t === 'high') return 'bg-amber-500/15 text-amber-600';
  if (t === 'medium') return 'bg-yellow-500/15 text-yellow-600';
  if (t === 'low') return 'bg-blue-500/12 text-blue-600';
  return 'bg-soc-panel text-soc-muted';
}

function sourceBadge(source) {
  const s = source || 'unknown';
  if (s === 'website') return 'badge-website';
  if (s === 'linux') return 'badge-linux';
  return 'badge-system';
}

function bucketLabel(iso, window) {
  if (!iso) return '';
  if (window === '24h') return formatLocalTime(iso);
  return formatLocalDate(iso);
}

function EnrichmentNote() {
  return (
    <div className="text-[11px] text-soc-muted bg-soc-panel/60 border border-soc-border/40 rounded-lg px-3 py-2 mt-1">
      Waiting on IP enrichment — see backend setup. These sections light up automatically once{' '}
      <code className="font-mono text-soc-accent-glow">enriched.ip</code> is populated on ingested events.
    </div>
  );
}

export function ThreatIntelPage() {
  const activeProject = useProjectStore((s) => s.activeProject);
  const pid = activeProject?.id;
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);

  const [window, setWindow] = useState('24h');
  const [narrativeHours, setNarrativeHours] = useState(24);
  const [tacticOpen, setTacticOpen] = useState(null);
  const [createIncidentModal, setCreateIncidentModal] = useState({ open: false, initialTitle: '', initialDescription: '', initialSeverity: null });
  const [indicatorPage, setIndicatorPage] = useState(1);
  const [indicatorFeed, setIndicatorFeed] = useState('');
  const [attachChain, setAttachChain] = useState(null);

  const { data: tacticsData } = useQuery({
    queryKey: ['threat-tactics', pid, window],
    queryFn: () => api.threatIntel.tactics(pid, window),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: timelineData } = useQuery({
    queryKey: ['threat-timeline', pid, window],
    queryFn: () => api.threatIntel.timeline(pid, window),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: narrativesData } = useQuery({
    queryKey: ['threat-narratives', pid, narrativeHours],
    queryFn: () => api.threatIntel.narratives(pid, narrativeHours),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: topHostsData } = useQuery({
    queryKey: ['threat-top-hosts', pid, window],
    queryFn: () => api.threatIntel.topHosts(pid, window),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: indData, isLoading: indLoading } = useQuery({
    queryKey: ['threat-indicators', pid],
    queryFn: () => api.threatIntel.indicators(pid),
    enabled: !!pid,
    refetchInterval: 30000,
  });

  const { data: matchData, isLoading: matchLoading } = useQuery({
    queryKey: ['threat-matches', pid],
    queryFn: () => api.threatIntel.matches(pid),
    enabled: !!pid,
    refetchInterval: 30000,
  });

  const { data: allIndData } = useQuery({
    queryKey: ['threat-all-indicators', pid, indicatorPage, indicatorFeed],
    queryFn: () => api.threatIntel.allIndicators(pid, { page: indicatorPage, pageSize: 50, sourceFeed: indicatorFeed }),
    enabled: !!pid,
    refetchInterval: 60000,
  });

  const { data: openIncidents } = useQuery({
    queryKey: ['incidents', pid],
    queryFn: () => api.incidents.list(pid),
    enabled: !!pid && !!attachChain,
  });

  const attachChainMutation = useMutation({
    mutationFn: ({ incidentId }) =>
      api.incidents.attachChain(incidentId, {
        hostname: attachChain.hostname,
        start_time: attachChain.start_time,
        end_time: attachChain.end_time,
      }),
    onSuccess: (r, vars) => {
      addToast(`Attached ${r.attached} events from chain to incident #${vars.incidentId}`, 'success');
      setAttachChain(null);
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['threat-indicators', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-matches', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-all-indicators', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-tactics', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-timeline', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-narratives', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-top-hosts', pid] });
  };

  const refreshMutation = useMutation({
    mutationFn: () => api.threatIntel.refresh(pid),
    onSuccess: (r) => {
      addToast(r.error ? `Feed refresh failed: ${r.error}` : `Feeds refreshed — ${r.count} indicators`, r.error ? 'error' : 'success');
      invalidate();
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const feedbackMutation = useMutation({
    mutationFn: ({ matchId }) => api.threatIntel.feedback(pid, matchId, true),
    onSuccess: (r) => {
      addToast(`Suppressed ${r.value} for this project`, 'success');
      invalidate();
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const indicators = indData?.indicators ?? [];
  const matches = matchData?.events ?? [];
  const tactics = tacticsData?.tactics ?? [];
  const buckets = timelineData?.buckets ?? [];
  const narratives = narrativesData?.narratives ?? [];
  const hosts = topHostsData?.hosts ?? [];
  const feeds = allIndData?.feeds ?? [];
  const loadedFeedCount = feeds.filter((f) => f.last_sync).length;
  const totalIndicators = allIndData?.total ?? 0;
  const lastSync = allIndData?.last_sync;
  const feedError = allIndData?.error;

  const toEvent = (m) => ({
    id: m.id,
    summary: m.summary,
    raw: {},
    event_type: m.event_type,
  });

  const openIncident = (m) => {
    const sev = m.event_type === 'critical' || m.event_type === 'high' ? m.event_type : null;
    setCreateIncidentModal({ open: true, initialTitle: '', initialDescription: '', initialSeverity: sev, event: toEvent(m) });
  };

  const openChainIncident = (n) => {
    const steps = n.chain.map((s) => `- [${formatLocalTime(s.time)}] ${s.tactic || '—'}${s.technique ? ` (${s.technique})` : ''}: ${s.summary}`).join('\n');
    const sev = n.chain.some((s) => s.event_type === 'critical' || s.event_type === 'high') ? 'high' : 'medium';
    setCreateIncidentModal({
      open: true,
      initialTitle: `Attack chain on ${n.hostname} (${n.event_count} events, ${formatLocalDate(n.start_time)} ${formatLocalTime(n.start_time)})`,
      initialDescription: `Correlated attack narrative for host ${n.hostname}:\n${steps}`,
      initialSeverity: sev,
      event: null,
    });
  };

  const timelineChart = useMemo(() => {
    return buckets.map((b) => ({
      label: bucketLabel(b.bucket_start, window),
      count: b.event_count,
      avg: b.avg_risk_score ?? 0,
    }));
  }, [buckets, window]);

  const tacticsTotal = tactics.reduce((a, t) => a + t.count, 0);

  const pageCount = Math.max(1, Math.ceil(totalIndicators / 50));
  const feedOptions = useMemo(() => {
    const names = new Set(feeds.map((f) => f.name));
    if (totalIndicators > 0) names.add('manual');
    return ['', ...Array.from(names)];
  }, [feeds, totalIndicators]);

  return (
    <div>
      <PageHeader title="Threat Intelligence" />

      {/* 1. Feed status bar */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-soc-text">Threat Feed</h2>
              <span className="badge-feed text-[10px] px-1.5 py-0.5 rounded">feed</span>
            </div>
            <p className="text-xs text-soc-muted mt-0.5">
              {feeds.length ? `${feeds.length} feeds, last updated ${lastSync ? formatRelative(lastSync) : 'never'}` : 'loading…'}
            </p>
          </div>
          <div className="text-xs text-soc-muted-cool">
            <span className="font-medium">{totalIndicators}</span> indicators loaded
          </div>
          {feedError && (
            <div className="text-xs text-red-600" title={feedError}>
              ⚠ Last refresh failed
            </div>
          )}
          <button
            onClick={() => refreshMutation.mutate()}
            disabled={refreshMutation.isPending}
            className="ml-auto text-xs bg-white border border-soc-border hover:bg-soc-panel text-soc-muted hover:text-soc-accent px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50"
          >
            {refreshMutation.isPending ? 'Refreshing…' : 'Refresh Feed'}
          </button>
        </div>
        <div className="flex flex-wrap gap-2 mt-3">
          {feeds.map((f) => (
            <div
              key={f.name}
              className="flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-lg border border-soc-border/50 bg-soc-panel/50"
              title={f.error || `Last sync ${f.last_sync ? formatRelative(f.last_sync) : 'never'}`}
            >
              <span className="font-medium text-soc-text">{f.name}</span>
              <span className="text-soc-muted">{f.count}</span>
              {f.error ? (
                <span className="text-red-600" title={f.error}>⚠ failed</span>
              ) : (
                <span className="w-1.5 h-1.5 rounded-full bg-soc-sage" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Window selector */}
      <div className="flex items-center gap-1.5 mb-4">
        {WINDOWS.map((w) => (
          <button
            key={w.value}
            onClick={() => setWindow(w.value)}
            className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
              window === w.value
                ? 'bg-soc-accent border-soc-accent text-white'
                : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
            }`}
          >
            {w.label}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-soc-muted">window applies to timeline · tactics · top hosts</span>
      </div>

      {/* 2. Attack Timeline */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Attack Timeline</h2>
          <span className="text-[10px] text-soc-muted">volume + avg risk · {timelineData?.source === 'elasticsearch' ? 'Elasticsearch' : 'Mongo fallback'}</span>
        </div>
        {timelineChart.length === 0 ? (
          <p className="text-xs text-soc-muted py-4 text-center">No events in this window</p>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <ComposedChart data={timelineChart} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.12)" />
              <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#94A3B8' }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
              <YAxis yAxisId="count" tick={{ fontSize: 10, fill: '#94A3B8' }} tickLine={false} axisLine={false} />
              <YAxis yAxisId="risk" orientation="right" tick={{ fontSize: 10, fill: '#94A3B8' }} tickLine={false} axisLine={false} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: '#0B1120', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 8, fontSize: 11 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar yAxisId="count" dataKey="count" name="events" fill="#2563EB" radius={[3, 3, 0, 0]} maxBarSize={28} />
              <Line yAxisId="risk" type="monotone" dataKey="avg" name="avg risk" stroke="#DC2626" strokeWidth={1.8} dot={false} />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* 3. Tactics Observed */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Tactics Observed (MITRE ATT&CK)</h2>
          <span className="text-[10px] text-soc-muted">{tacticsTotal} mapped events in window</span>
        </div>
        {tactics.length === 0 ? (
          <p className="text-xs text-soc-muted py-4 text-center">
            No ATT&CK-mapped activity yet — failed logons (T1110), service installs (T1543.003) and log clears (T1070.001) will appear here.
          </p>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <ResponsiveContainer width="100%" height={190}>
              <PieChart>
                <Pie
                  data={tactics}
                  dataKey="count"
                  nameKey="tactic"
                  cx="50%"
                  cy="50%"
                  innerRadius={48}
                  outerRadius={78}
                  paddingAngle={2}
                >
                  {tactics.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#0B1120', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 8, fontSize: 11 }}
                  formatter={(v, name) => [`${v} events`, name]}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-2">
              {tactics.slice(0, 8).map((t, i) => (
                <div key={t.tactic} className="border border-soc-border/40 rounded-lg bg-soc-panel/40">
                  <button
                    onClick={() => setTacticOpen(tacticOpen === t.tactic ? null : t.tactic)}
                    className="w-full flex items-center justify-between gap-2 px-3 py-2 text-left"
                  >
                    <span className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full shrink-0" style={{ background: COLORS[i % COLORS.length] }} />
                      <span className="text-xs font-medium">{t.tactic}</span>
                    </span>
                    <span className="flex items-center gap-2 shrink-0">
                      <span className="text-soc-muted text-xs">{t.count}</span>
                      <span className="text-[10px] text-soc-muted">{Math.round((t.count / tacticsTotal) * 100)}%</span>
                    </span>
                  </button>
                  {tacticOpen === t.tactic && (
                    <div className="px-3 pb-3 pt-1 border-t border-soc-border/30 space-y-2">
                      <div className="flex flex-wrap gap-1.5">
                        {t.techniques.map((tech) => (
                          <span key={tech.technique} className="text-[10px] px-1.5 py-0.5 rounded bg-soc-card text-soc-accent-glow font-mono">
                            {tech.technique} · {tech.count}
                          </span>
                        ))}
                      </div>
                      {t.examples.length > 0 && (
                        <div className="space-y-1">
                          {t.examples.map((ex, j) => (
                            <p key={j} className="text-[11px] text-soc-muted truncate" title={ex}>{ex}</p>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 4. Attack Narratives */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3 gap-3">
          <h2 className="text-sm font-semibold text-soc-text">Attack Narratives</h2>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-soc-muted">lookback</span>
            {[6, 24, 72].map((h) => (
              <button
                key={h}
                onClick={() => setNarrativeHours(h)}
                className={`px-2 py-0.5 rounded-full text-[10px] border transition-colors ${
                  narrativeHours === h
                    ? 'bg-soc-accent border-soc-accent text-white'
                    : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                }`}
              >
                {h}h
              </button>
            ))}
          </div>
        </div>
        {narratives.length === 0 ? (
          <p className="text-xs text-soc-muted py-4 text-center">
            No correlated chains yet — 3+ events from one host within 2h (escalating tactics or high risk) become a narrative here.
          </p>
        ) : (
          <div className="space-y-3">
            {narratives.map((n) => (
              <div key={`${n.hostname}-${n.start_time}`} className="border border-soc-border/40 rounded-xl bg-soc-panel/40 overflow-hidden">
                <div className="flex items-center gap-3 px-4 py-2.5 bg-soc-panel/60 border-b border-soc-border/30 flex-wrap">
                  <span className="text-xs font-semibold font-mono text-soc-text">{n.hostname}</span>
                  <span className="text-[10px] text-soc-muted">
                    {formatLocalDate(n.start_time)} {formatLocalTime(n.start_time)} → {formatLocalTime(n.end_time)} · {n.event_count} events
                  </span>
                  <div className="flex items-center gap-2 ml-auto">
                    <button
                      onClick={() => setAttachChain(n)}
                      className="text-xs bg-soc-card border border-soc-border/70 hover:border-soc-accent/50 text-soc-text px-2.5 py-1 rounded transition-colors"
                    >
                      Attach to Incident
                    </button>
                    <button
                      onClick={() => openChainIncident(n)}
                      className="text-xs bg-soc-accent hover:bg-soc-accent-glow text-white px-2.5 py-1 rounded transition-colors"
                    >
                      Create Incident from chain
                    </button>
                  </div>
                </div>
                <div className="px-4 py-3">
                  {n.chain.map((s, i) => (
                    <div key={i} className="flex gap-3">
                      <div className="flex flex-col items-center">
                        <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${s.event_type === 'critical' || s.event_type === 'high' ? 'bg-red-500' : 'bg-soc-accent'}`} />
                        {i < n.chain.length - 1 && <div className="w-px flex-1 bg-soc-border/50" />}
                      </div>
                      <div className="pb-3 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[10px] text-soc-muted-cool font-mono">{formatLocalTime(s.time)}</span>
                          {s.tactic && (
                            <span className={`text-[10px] px-1.5 py-0.5 rounded ${sevPill(s.event_type)}`}>{s.tactic}</span>
                          )}
                          {s.technique && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-soc-card text-soc-accent-glow font-mono">{s.technique}</span>
                          )}
                          <Link
                            to={`/live-events?query=${encodeURIComponent(s.summary.slice(0, 40))}`}
                            className="text-[10px] text-soc-muted hover:text-soc-accent"
                          >
                            open in events
                          </Link>
                        </div>
                        <p className="text-xs text-soc-muted mt-1 break-words">{s.summary}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 5. Top Risk Hosts */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Top Risk Hosts</h2>
          <span className="text-[10px] text-soc-muted">accumulated risk · {window} window</span>
        </div>
        {hosts.length === 0 ? (
          <p className="text-xs text-soc-muted py-4 text-center">No agent events in this window</p>
        ) : (
          <div className="space-y-2">
            {hosts.slice(0, 12).map((h, i) => {
              const pct = Math.max(2, Math.round((h.risk_total / (hosts[0].risk_total || 1)) * 100));
              return (
                <Link
                  key={h.hostname}
                  to={`/live-events?host=${encodeURIComponent(h.hostname)}`}
                  className="flex items-center gap-3 text-sm rounded-lg px-2 py-1.5 hover:bg-soc-panel transition-colors group"
                  title="Open this host's events in Live Events"
                >
                  <span className="text-[10px] text-soc-muted w-5 text-right shrink-0">{i + 1}</span>
                  <span className="font-mono text-xs w-48 truncate shrink-0 group-hover:text-soc-accent">{h.hostname}</span>
                  <div className="flex-1 h-2 bg-soc-panel rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${h.risk_total >= 500 ? 'bg-red-500/70' : h.risk_total >= 200 ? 'bg-amber-500/70' : 'bg-soc-accent/40'}`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-xs font-medium text-soc-text w-14 text-right shrink-0">{h.risk_total}</span>
                  <span className="text-soc-muted text-[10px] w-8 text-right shrink-0">{h.event_count} ev</span>
                </Link>
              );
            })}
          </div>
        )}
      </div>

      {/* 6. Known Threat IPs + Geo Breakdown (IP-enrichment dependent) */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Known Threat IPs</h2>
          <span className={`text-xs px-2 py-0.5 rounded-full ${indicators.length > 0 ? 'bg-red-50 text-red-600 border border-red-200' : 'bg-soc-panel text-soc-muted'}`}>
            {indicators.length} indicators
          </span>
        </div>
        <EnrichmentNote />
        {indLoading ? (
          <div className="space-y-2 mt-2">{[1, 2, 3].map((i) => <div key={i} className="h-9 bg-soc-panel rounded-lg animate-pulse" />)}</div>
        ) : indicators.length === 0 ? (
          <p className="text-xs text-soc-muted py-4 text-center">
            No indicators have matched this project's events yet — feed indicators will appear here once they do
          </p>
        ) : (
          <div className="overflow-x-auto mt-2">
            <div className="min-w-[640px]">
              <div className="grid grid-cols-[1.4fr_1fr_1fr_0.5fr] gap-3 px-3 py-2 text-[10px] uppercase tracking-wide text-soc-muted border-b border-soc-border/60">
                <span>Indicator / Category</span>
                <span>First seen</span>
                <span>Last seen</span>
                <span>Hits</span>
              </div>
              <div className="divide-y divide-soc-border/60">
                {indicators.map((item) => (
                  <div key={item.id} className="grid grid-cols-[1.4fr_1fr_1fr_0.5fr] gap-3 px-3 py-2 items-center text-sm">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`text-xs px-1.5 py-0.5 rounded ${item.source === 'manual' ? 'badge-manual' : 'badge-feed'}`}>
                        {item.source}
                      </span>
                      <span className="font-mono text-xs text-soc-text truncate">{item.value}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-soc-panel text-soc-muted shrink-0">
                        {item.category}
                      </span>
                    </div>
                    <span className="text-xs text-soc-muted-cool">{item.first_seen ? formatLocalDate(item.first_seen) : '—'}</span>
                    <span className="text-xs text-soc-muted-cool">{item.last_seen ? formatLocalDate(item.last_seen) : '—'}</span>
                    <span className="text-xs font-medium text-soc-text">{item.hit_count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Geo Breakdown */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <h2 className="text-sm font-semibold mb-3 text-soc-text">Geo Breakdown</h2>
        <EnrichmentNote />
        <p className="text-xs text-soc-muted py-4 text-center">No geo data yet — requires IP enrichment</p>
      </div>

      {/* Matched Events (Part F feedback) */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Matched Events</h2>
          <span className={`text-xs px-2 py-0.5 rounded-full ${matches.length > 0 ? 'bg-red-500/12 text-red-600' : 'bg-soc-panel text-soc-muted'}`}>
            {matches.length} matching events
          </span>
        </div>
        {matchLoading ? (
          <div className="space-y-2">{[1, 2, 3].map((i) => <div key={i} className="h-9 bg-soc-panel rounded-lg animate-pulse" />)}</div>
        ) : matches.length === 0 ? (
          <p className="text-xs text-soc-muted py-4 text-center">
            No events currently match the indicator list
          </p>
        ) : (
          <div className="space-y-1.5 max-h-96 overflow-y-auto">
            {matches.map((m) => (
              <div
                key={m.id}
                className="flex items-center gap-3 px-3 py-2 text-sm rounded-lg bg-soc-card border border-soc-border/60 hover:bg-soc-panel transition-colors"
              >
                <span className="text-xs text-soc-muted-cool w-14 shrink-0">{formatLocalTime(m.timestamp)}</span>
                <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded ${sourceBadge(m.source)}`}>{m.source}</span>
                <span className="text-xs font-mono text-red-600 shrink-0">{m.ip || '—'}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded shrink-0 ${sevPill(m.event_type)}`}>{m.event_type}</span>
                <span className="flex-1 truncate text-soc-muted">{m.summary}</span>
                <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded ${m.matched?.source === 'manual' ? 'badge-manual' : 'badge-feed'}`}>
                  {m.matched?.source} · {m.matched?.category}
                </span>
                <button
                  onClick={() => openIncident(m)}
                  className="text-xs bg-soc-panel hover:bg-soc-card text-soc-muted hover:text-soc-accent px-2 py-1 rounded shrink-0 transition-colors"
                >
                  + Incident
                </button>
                <button
                  onClick={() => feedbackMutation.mutate({ matchId: m.id })}
                  disabled={feedbackMutation.isPending}
                  className="text-xs bg-soc-panel hover:bg-red-500/10 text-soc-muted hover:text-red-600 px-2 py-1 rounded shrink-0 transition-colors disabled:opacity-50"
                  title="Suppress this indicator for this project (feed stays untouched)"
                >
                  Not a threat
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 7. Browsable indicator list */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
          <h2 className="text-sm font-semibold text-soc-text">Indicator List</h2>
          <div className="flex items-center gap-2">
            <select
              value={indicatorFeed}
              onChange={(e) => { setIndicatorFeed(e.target.value); setIndicatorPage(1); }}
              className="text-xs bg-soc-card border border-soc-border rounded-lg px-2 py-1.5 focus:outline-none focus:border-soc-accent"
            >
              <option value="">all source feeds</option>
              {feedOptions.filter(Boolean).map((f) => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
            <span className="text-[10px] text-soc-muted">{totalIndicators} loaded</span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <div className="min-w-[560px]">
            <div className="grid grid-cols-[1.2fr_1fr_1fr_auto] gap-3 px-3 py-2 text-[10px] uppercase tracking-wide text-soc-muted border-b border-soc-border/60">
              <span>Value</span>
              <span>Category</span>
              <span>Source feed</span>
              <span>Loaded</span>
            </div>
            <div className="divide-y divide-soc-border/60">
              {(allIndData?.indicators ?? []).map((item) => (
                <div key={`${item.source_feed}-${item.value}`} className="grid grid-cols-[1.2fr_1fr_1fr_auto] gap-3 px-3 py-2 items-center text-sm">
                  <span className="font-mono text-xs text-soc-text truncate" title={item.value}>{item.value}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-soc-panel text-soc-muted w-fit">{item.category}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded w-fit ${item.source_feed === 'manual' ? 'badge-manual' : 'badge-feed'}`}>
                    {item.source_feed}
                  </span>
                  <span className="text-[10px] text-soc-muted-cool">{item.loaded_at ? formatLocalDate(item.loaded_at) : '—'}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        {pageCount > 1 && (
          <div className="flex items-center justify-center gap-2 mt-3">
            <button
              onClick={() => setIndicatorPage((p) => Math.max(1, p - 1))}
              disabled={indicatorPage <= 1}
              className="text-xs px-2.5 py-1 rounded-lg border border-soc-border text-soc-muted hover:text-soc-accent disabled:opacity-40"
            >
              Prev
            </button>
            <span className="text-[10px] text-soc-muted">page {indicatorPage} / {pageCount}</span>
            <button
              onClick={() => setIndicatorPage((p) => Math.min(pageCount, p + 1))}
              disabled={indicatorPage >= pageCount}
              className="text-xs px-2.5 py-1 rounded-lg border border-soc-border text-soc-muted hover:text-soc-accent disabled:opacity-40"
            >
              Next
            </button>
          </div>
        )}
      </div>

      <CreateIncidentModal
        open={createIncidentModal.open}
        event={createIncidentModal.event}
        projectId={pid}
        initialSeverity={createIncidentModal.initialSeverity}
        initialTitle={createIncidentModal.initialTitle}
        initialDescription={createIncidentModal.initialDescription}
        onClose={() => setCreateIncidentModal({ open: false, initialTitle: '', initialDescription: '', initialSeverity: null, event: null })}
      />

      {attachChain && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-soc-overlay/60 p-4"
          onClick={() => setAttachChain(null)}
        >
          <motion.div
            initial={{ scale: 0.95 }}
            animate={{ scale: 1 }}
            className="glass-elevated rounded-xl w-full max-w-md flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-4 border-b border-soc-border">
              <h2 className="text-lg font-semibold text-soc-text">Attach chain to incident</h2>
              <p className="text-xs text-soc-muted mt-0.5">
                {attachChain.hostname} · {attachChain.event_count} events · {formatLocalDate(attachChain.start_time)} {formatLocalTime(attachChain.start_time)} → {formatLocalTime(attachChain.end_time)}
              </p>
            </div>
            <div className="p-3 border-b border-soc-border">
              <button
                onClick={() => {
                  setAttachChain(null);
                  openChainIncident(attachChain);
                }}
                className="w-full text-left text-sm text-soc-accent hover:underline px-2 py-1.5 rounded hover:bg-soc-panel"
              >
                + Create new incident from this chain
              </button>
            </div>
            <div className="max-h-64 overflow-y-auto p-2 space-y-1">
              <p className="text-[10px] uppercase tracking-wide text-soc-muted px-2 pt-1">Open incidents</p>
              {(openIncidents || []).filter((i) => i.status !== 'resolved').length === 0 ? (
                <p className="text-xs text-soc-muted px-2 py-2">No open incidents — create one first.</p>
              ) : (
                (openIncidents || [])
                  .filter((i) => i.status !== 'resolved')
                  .map((i) => (
                    <button
                      key={i.id}
                      onClick={() => attachChainMutation.mutate({ incidentId: i.id })}
                      disabled={attachChainMutation.isPending}
                      className="w-full flex items-center gap-2 px-2 py-2 rounded-lg hover:bg-soc-panel text-left transition-colors disabled:opacity-50"
                    >
                      <Link2 size={13} className="text-soc-muted shrink-0" />
                      <span className="flex-1 min-w-0">
                        <span className="block text-sm text-soc-text truncate">{i.title}</span>
                        <span className="block text-[10px] text-soc-muted">
                          #{i.id} · {i.severity} · {i.evidence_count} evidence
                        </span>
                      </span>
                      {attachChainMutation.isPending && attachChainMutation.variables?.incidentId === i.id && (
                        <span className="text-[10px] text-soc-muted">Attaching…</span>
                      )}
                    </button>
                  ))
              )}
            </div>
            <div className="p-3 border-t border-soc-border flex justify-end">
              <button onClick={() => setAttachChain(null)} className="text-sm text-soc-muted">Cancel</button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
}