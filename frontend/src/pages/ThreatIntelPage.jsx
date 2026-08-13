import { useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { api } from '../lib/api';
import { formatLocalTime, formatLocalDate, formatRelative } from '../lib/time';
import { useToastStore } from '../stores/toastStore';
import { CreateIncidentModal } from '../components/CreateIncidentModal';
import { PageHeader } from '../components/ui/PageHeader';

const COLORS = ['#2563EB', '#4F46E5', '#0D9488', '#B45309', '#7C3AED', '#0284C7'];

const TOP_IPS = 15;

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

function aggregate(data) {
  if (!data?.events) return null;
  const events = data.events;
  const ips = {};
  const ipCountry = {};
  const types = {};
  const countries = {};
  events.forEach((e) => {
    const ip = e.enriched?.ip || e.source_ip || e.ip || 'unknown';
    ips[ip] = (ips[ip] || 0) + 1;
    const country = e.enriched?.geo?.country || 'unknown';
    if (!ipCountry[ip] && country !== 'unknown') ipCountry[ip] = country;
    const t = e.event_type || 'unknown';
    types[t] = (types[t] || 0) + 1;
    countries[country] = (countries[country] || 0) + 1;
  });
  return {
    top_ips: Object.entries(ips).map(([key, count]) => ({ key, count, country: ipCountry[key] || '' })).sort((a, b) => b.count - a.count),
    event_types: Object.entries(types).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count),
    countries: Object.entries(countries).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count),
  };
}

function CorrCell({ ip, cell, mode, tInt, pid }) {
  const intensity = Math.max(0, Math.min(tInt, 1));
  const bg = `rgba(37, 99, 235, ${(0.05 + intensity * 0.57).toFixed(2)})`;
  const value = mode === 'count' ? cell.count : cell.avg_risk ?? 0;
  return (
    <div className="relative group">
      <Link
        to={`/projects/${pid}/live-events?query=${encodeURIComponent(ip)}`}
        className={`h-7 rounded flex items-center justify-center text-[10px] font-medium tabular-nums transition-transform group-hover:scale-105 ${
          intensity > 0.55 ? 'text-white' : 'text-soc-muted'
        }`}
        style={{ backgroundColor: bg }}
      >
        {value}
      </Link>
      <div className="hidden group-hover:block pointer-events-none absolute z-20 bottom-full left-0 mb-1.5 whitespace-nowrap bg-soc-tooltip text-white text-[10px] rounded-lg px-2.5 py-1.5 shadow-lg leading-relaxed">
        <div className="font-semibold font-mono">{ip}</div>
        <div>
          <span className="text-soc-accent-glow">type:</span> {cell.event_type} · <span className="text-soc-accent-glow">count:</span> {cell.count} ·{' '}
          <span className="text-soc-accent-glow">avg risk:</span> {cell.avg_risk ?? 0}
        </div>
        <div><span className="text-soc-accent-glow">last seen:</span> {cell.last_seen ? formatLocalDate(cell.last_seen) : '—'}</div>
      </div>
    </div>
  );
}

function CorrelationRow({ ip, types, cells, mode, cap, pid }) {
  return (
    <>
      <div className="flex items-center gap-1 text-xs font-mono truncate pr-2" title={ip}>
        {ip}
      </div>
      {types.map((t) => {
        const cell = cells[`${ip}||${t}`];
        if (!cell) return <div key={t} className="h-7 rounded bg-soc-panel/60" />;
        const tInt = mode === 'count' ? cell.count / cap : Math.min((cell.avg_risk ?? 0) / cap, 1);
        return <CorrCell key={t} ip={ip} cell={cell} mode={mode} tInt={tInt} pid={pid} />;
      })}
    </>
  );
}

export function ThreatIntelPage() {
  const { projectId } = useParams();
  const pid = Number(projectId);
  const queryClient = useQueryClient();
  const addToast = useToastStore((s) => s.addToast);

  const [createIncidentModal, setCreateIncidentModal] = useState({ open: false, event: null, initialSeverity: null });

  const { data } = useQuery({
    queryKey: ['events', pid, 'threat'],
    queryFn: () => api.events.list(pid, { size: '1000' }),
    enabled: !!pid,
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

  const { data: corrData, isLoading: corrLoading } = useQuery({
    queryKey: ['threat-correlation', pid],
    queryFn: () => api.threatIntel.correlation(pid),
    enabled: !!pid,
    refetchInterval: 30000,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['threat-indicators', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-matches', pid] });
    queryClient.invalidateQueries({ queryKey: ['threat-correlation', pid] });
  };

  const refreshMutation = useMutation({
    mutationFn: () => api.threatIntel.refresh(pid),
    onSuccess: (r) => {
      addToast(r.error ? `Feed refresh failed: ${r.error}` : `Feed refreshed — ${r.count} indicators`, r.error ? 'error' : 'success');
      invalidate();
    },
    onError: (err) => addToast(err.message, 'error'),
  });

  const agg = aggregate(data);
  const indicators = indData?.indicators ?? [];
  const indicatorValues = new Set(indicators.map((i) => i.value));
  const feed = indData?.feed;
  const matches = matchData?.events ?? [];
  const correlation = corrData ?? [];

  const toEvent = (m) => ({
    id: m.id,
    summary: m.summary,
    raw: {},
    event_type: m.event_type,
  });

  const openIncident = (m) => {
    const sev = m.event_type === 'critical' || m.event_type === 'high' ? m.event_type : null;
    setCreateIncidentModal({ open: true, event: toEvent(m), initialSeverity: sev });
  };

  const corrMatrix = useMemo(() => {
    const cells = {};
    const ipTotals = {};
    const typeTotals = {};
    (correlation || []).forEach((r) => {
      if (!r.ip || r.ip === 'unknown') return;
      const key = `${r.ip}||${r.event_type}`;
      cells[key] = r;
      ipTotals[r.ip] = (ipTotals[r.ip] || 0) + r.count;
      typeTotals[r.event_type] = (typeTotals[r.event_type] || 0) + r.count;
    });
    const ips = Object.keys(ipTotals)
      .sort((a, b) => ipTotals[b] - ipTotals[a])
      .slice(0, TOP_IPS);
    const types = Object.keys(typeTotals).sort((a, b) => typeTotals[b] - typeTotals[a]);
    let maxCount = 0;
    let maxAvg = 0;
    ips.forEach((ip) => {
      types.forEach((t) => {
        const cell = cells[`${ip}||${t}`];
        if (!cell) return;
        if (cell.count > maxCount) maxCount = cell.count;
        if (cell.avg_risk > maxAvg) maxAvg = cell.avg_risk;
      });
    });
    return { cells, ips, types, maxCount, maxAvg };
  }, [correlation]);

  const [corrMode, setCorrMode] = useState('count');
  const hasCorrelation = corrMatrix.ips.length > 0;
  const corrMax = corrMode === 'count' ? corrMatrix.maxCount : 100;
  const corrCap = Math.max(corrMax, 1);

  return (
    <div>
      <PageHeader title="Threat Intelligence" />

      {/* Feed / health status */}
      <div className="glass-card rounded-xl p-4 mb-4 flex flex-wrap items-center gap-x-6 gap-y-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-soc-text">Threat Feed</h2>
            <span className="badge-feed text-[10px] px-1.5 py-0.5 rounded">feed</span>
          </div>
          <p className="text-xs text-soc-muted mt-0.5">{feed?.source || 'loading…'}</p>
        </div>
        <div className="text-xs text-soc-muted-cool">
          Feed last updated: <span className="font-medium">{formatRelative(feed?.last_sync)}</span>
        </div>
        <div className="text-xs text-soc-muted-cool">
          <span className="font-medium">{feed?.count ?? '—'}</span> indicators loaded
        </div>
        {feed?.error && (
          <div className="text-xs text-red-600" title={feed.error}>
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

      {/* Known Threat IPs */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-soc-text">Known Threat IPs</h2>
          <span className={`text-xs px-2 py-0.5 rounded-full ${indicators.length > 0 ? 'bg-red-50 text-red-600 border border-red-200' : 'bg-soc-panel text-soc-muted'}`}>
            {indicators.length} indicators
          </span>
        </div>
        {indLoading ? (
          <div className="space-y-2">{[1, 2, 3].map((i) => <div key={i} className="h-9 bg-soc-panel rounded-lg animate-pulse" />)}</div>
        ) : indicators.length === 0 ? (
          <p className="text-xs text-soc-muted py-4 text-center">
            No indicators have matched this project's events yet — feed indicators will appear here once they do
          </p>
        ) : (
          <div className="overflow-x-auto">
            <div className="min-w-[640px]">
              <div className="grid grid-cols-[1.4fr_1fr_1fr_0.5fr_auto] gap-3 px-3 py-2 text-[10px] uppercase tracking-wide text-soc-muted border-b border-soc-border/60">
                <span>Indicator / Category</span>
                <span>First seen</span>
                <span>Last seen</span>
                <span>Hits</span>
                <span className="text-right">Actions</span>
              </div>
              <div className="divide-y divide-soc-border/60">
                {indicators.map((item) => (
                  <div
                    key={item.id}
                    className="grid grid-cols-[1.4fr_1fr_1fr_0.5fr_auto] gap-3 px-3 py-2 items-center text-sm"
                  >
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
                    <div className="flex items-center gap-1.5 justify-end">
                      <Link
                        to={`/projects/${pid}/live-events?query=${encodeURIComponent(item.value)}`}
                        className="text-xs bg-soc-panel hover:bg-soc-card text-soc-muted hover:text-soc-accent px-2 py-1 rounded shrink-0 transition-colors"
                        title="Jump to matching events"
                      >
                        View events
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Top IPs + Event Types */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div className="glass-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-3 text-soc-text">Top Source IPs</h2>
          {agg && agg.top_ips.length > 0 ? (
            <div className="space-y-2.5">
              {agg.top_ips.slice(0, 10).map((item) => {
                const flagged = indicatorValues.has(item.key);
                const pct = Math.round((item.count / agg.top_ips[0].count) * 100);
                return (
                  <div key={item.key} className="flex items-center gap-3 text-sm">
                    <span className="flex items-center gap-1.5 w-40 shrink-0 min-w-0">
                      {item.country && flagEmoji(item.country) && (
                        <span className="shrink-0">{flagEmoji(item.country)}</span>
                      )}
                      <span className="font-mono text-xs truncate">{item.key}</span>
                    </span>
                    <div className="flex-1 h-2 bg-soc-panel rounded-full overflow-hidden">
                      <div className="h-full bg-soc-accent/25 rounded-full" style={{ width: `${Math.max(pct, 2)}%` }} />
                    </div>
                    <span className="text-soc-muted text-xs w-10 text-right shrink-0">{item.count}</span>
                    {flagged ? (
                      <span className="text-xs text-soc-sage w-14 text-right shrink-0">✓ flagged</span>
                    ) : (
                      <span className="w-14 shrink-0" />
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-xs text-soc-muted py-4 text-center">No IP data</p>
          )}
        </div>

        <div className="glass-card rounded-xl p-4">
          <h2 className="text-sm font-semibold mb-3 text-soc-text">Event Types</h2>
          {agg && agg.event_types.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie
                    data={agg.event_types}
                    dataKey="count"
                    nameKey="key"
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={62}
                    paddingAngle={2}
                  >
                    {agg.event_types.map((_, i) => (
                      <Cell key={i} fill={COLORS[i % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
              <div className="mt-2 space-y-1.5">
                {agg.event_types.slice(0, 8).map((item) => (
                  <div key={item.key} className="flex items-center justify-between text-sm">
                    <span className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full" style={{ background: COLORS[agg.event_types.indexOf(item) % COLORS.length] }} />
                      <span className="text-xs">{item.key}</span>
                    </span>
                    <span className="text-soc-muted text-xs">{item.count}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="text-xs text-soc-muted py-4 text-center">No event type data</p>
          )}
        </div>
      </div>

      {/* Geo Breakdown */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <h2 className="text-sm font-semibold mb-3 text-soc-text">Geo Breakdown</h2>
        {agg && agg.countries.length > 0 ? (
          <div className="space-y-2.5 max-w-2xl">
            {agg.countries.slice(0, 10).map((item) => {
              const pct = Math.round((item.count / agg.countries[0].count) * 100);
              return (
                <div key={item.key} className="flex items-center gap-3 text-sm">
                  <span className="flex items-center gap-2 w-40 shrink-0">
                    {item.key !== 'unknown' && flagEmoji(item.key) && (
                      <span>{flagEmoji(item.key)}</span>
                    )}
                    <span className="text-xs">{item.key}</span>
                  </span>
                  <div className="flex-1 h-2 bg-soc-panel rounded-full overflow-hidden">
                    <div className="h-full bg-soc-teal/25 rounded-full" style={{ width: `${Math.max(pct, 2)}%` }} />
                  </div>
                  <span className="text-soc-muted text-xs w-12 text-right shrink-0">{item.count}</span>
                  <span className="text-soc-muted/70 text-xs w-9 text-right shrink-0">{pct}%</span>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-xs text-soc-muted py-4 text-center">No geo data yet</p>
        )}
      </div>

      {/* Matched Events */}
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
              </div>
            ))}
          </div>
        )}
      </div>

      {/* IP × Event Type correlation */}
      <div className="glass-card rounded-xl p-4 mb-4">
        <div className="flex items-center justify-between mb-3 gap-3">
          <h2 className="text-sm font-semibold text-soc-text">IP Correlation</h2>
          <div className="flex items-center gap-1.5">
            {['count', 'avg_risk'].map((mode) => (
              <button
                key={mode}
                onClick={() => setCorrMode(mode)}
                className={`px-2.5 py-1 rounded-full text-xs border transition-colors ${
                  corrMode === mode
                    ? 'bg-soc-accent border-soc-accent text-white'
                    : 'bg-soc-card border-soc-border text-soc-muted hover:text-soc-accent'
                }`}
              >
                {mode === 'count' ? 'Count' : 'Avg Risk'}
              </button>
            ))}
          </div>
        </div>
        {corrLoading ? (
          <div className="space-y-2">{[1, 2, 3].map((i) => <div key={i} className="h-9 bg-soc-panel rounded-lg animate-pulse" />)}</div>
        ) : !hasCorrelation ? (
          <p className="text-xs text-soc-muted py-4 text-center">
            No correlated IP activity yet — once events include a source IP, correlation will appear here.
          </p>
        ) : (
          <>
            <div className="text-[10px] text-soc-muted mb-2">
              Rows: top {corrMatrix.ips.length} source IPs · columns: event types — click a cell to open that IP in Live Events
            </div>
            <div className="overflow-x-auto pb-1">
              <div
                className="grid gap-1 min-w-[520px]"
                style={{ gridTemplateColumns: `150px repeat(${corrMatrix.types.length}, minmax(44px, 1fr))` }}
              >
                <div />
                {corrMatrix.types.map((t) => (
                  <div
                    key={t}
                    className="text-[10px] text-soc-muted truncate text-center px-0.5"
                    title={t}
                  >
                    {t}
                  </div>
                ))}
                {corrMatrix.ips.map((ip) => (
                  <CorrelationRow
                    key={ip}
                    ip={ip}
                    types={corrMatrix.types}
                    cells={corrMatrix.cells}
                    mode={corrMode}
                    cap={corrCap}
                    pid={pid}
                  />
                ))}
              </div>
              <div className="flex items-center gap-2 mt-3 text-[10px] text-soc-muted">
                <span>lower</span>
                <div className="w-24 h-2 rounded-full" style={{ background: 'linear-gradient(90deg, rgba(37,99,235,0.06), rgba(37,99,235,0.62))' }} />
                <span>higher {corrMode === 'count' ? 'event count' : 'avg risk score'}</span>
              </div>
            </div>
          </>
        )}
      </div>

      <CreateIncidentModal
        open={createIncidentModal.open}
        event={createIncidentModal.event}
        projectId={pid}
        initialSeverity={createIncidentModal.initialSeverity}
        onClose={() => setCreateIncidentModal({ open: false, event: null, initialSeverity: null })}
      />
    </div>
  );
}
