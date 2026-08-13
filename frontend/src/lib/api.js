const BASE = '/api';

export async function request(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const e = new Error(err.detail || 'Request failed');
    e.status = res.status;
    throw e;
  }
  return res.json();
}

export async function requestFile(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, { credentials: 'include', ...opts });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    const e = new Error(err.detail || 'Request failed');
    e.status = res.status;
    throw e;
  }
  return res.blob();
}

export const WS_BASE = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;

const WEBSITE_KEYS_STORAGE = 'soc_website_keys';

export function saveWebsiteKey(projectId, key) {
  try {
    const stored = JSON.parse(localStorage.getItem(WEBSITE_KEYS_STORAGE) || '{}');
    stored[String(projectId)] = key;
    localStorage.setItem(WEBSITE_KEYS_STORAGE, JSON.stringify(stored));
  } catch {
    // storage unavailable — the key just won't be remembered for later fills
  }
}

export function getWebsiteKey(projectId) {
  try {
    const stored = JSON.parse(localStorage.getItem(WEBSITE_KEYS_STORAGE) || '{}');
    return stored[String(projectId)] || null;
  } catch {
    return null;
  }
}

export const api = {
  auth: {
    register: (body) =>
      request('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
    login: (body) =>
      request('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
    logout: () => request('/auth/logout', { method: 'POST' }),
    me: () => request('/auth/me'),
    meRaw: () => fetch(`${BASE}/auth/me`, { credentials: 'include' }),
  },
  projects: {
    list: () => request('/projects'),
    get: (id) => request(`/projects/${id}`),
    create: (body) =>
      request('/projects', { method: 'POST', body: JSON.stringify(body) }),
    delete: (id) => request(`/projects/${id}`, { method: 'DELETE' }),
    createApiKey: (projectId, label) =>
      request(`/projects/${projectId}/api-keys`, { method: 'POST', body: JSON.stringify({ label }) }).then(
        (r) => ({
          id: r.id,
          label: r.label,
          key: r.key,
          created_at: r.created_at,
          script_tag: r.script_tag,
          ai_agent_prompt: r.ai_agent_prompt,
        })
      ),
    listApiKeys: (projectId) => request(`/projects/${projectId}/api-keys`),
    revokeApiKey: (keyId) =>
      request(`/api-keys/${keyId}`, { method: 'DELETE' }),
    integrationSnippet: (projectId, platform = 'website') =>
      request(`/projects/${projectId}/integration-snippet?platform=${platform}`).then((r) => ({
        snippet: r.snippet,
        script_tag: r.script_tag,
        ai_agent_prompt: r.ai_agent_prompt,
      })),
    websiteSetupPrompt: (projectId, apiKey) => {
      const headers = apiKey ? { 'X-API-Key': apiKey } : {};
      return request(`/projects/${projectId}/website-setup-prompt`, { headers }).then(
        (r) => ({ prompt: r.prompt })
      );
    },
    overview: (projectId, hours = 24) =>
      request(`/projects/${projectId}/overview?hours=${hours}`),
    sources: (projectId) => request(`/projects/${projectId}/sources`),
    cleanupHistory: (projectId) => request(`/projects/${projectId}/cleanup-history`),
  },
  events: {
    list: (projectId, params) => {
      const clean = {};
      for (const [k, v] of Object.entries(params || {})) {
        if (v !== undefined && v !== null && v !== '') clean[k] = v;
      }
      const q = Object.keys(clean).length ? '?' + new URLSearchParams(clean).toString() : '';
      return request(`/projects/${projectId}/events${q}`);
    },
    get: (eventId) => request(`/events/${eventId}`),
    cleanupPreview: (projectId, filters) =>
      request(`/projects/${projectId}/events/cleanup/preview`, {
        method: 'POST',
        body: JSON.stringify(filters),
      }).then((r) => ({
        count: r.count,
        sample: r.sample,
        oldest_match: r.oldest_match,
        newest_match: r.newest_match,
      })),
    cleanup: (projectId, filters, expectedCount) =>
      request(`/projects/${projectId}/events/cleanup`, {
        method: 'DELETE',
        body: JSON.stringify({ ...filters, expected_count: expectedCount }),
      }).then((r) => ({ deleted_count: r.deleted_count })),
  },
  agentLogs: {
    cleanupPreview: (projectId, filters) =>
      request(`/projects/${projectId}/agent-logs/cleanup/preview`, {
        method: 'POST',
        body: JSON.stringify(filters),
      }).then((r) => ({
        count: r.count,
        sample: r.sample,
        oldest_match: r.oldest_match,
        newest_match: r.newest_match,
      })),
    cleanup: (projectId, filters, expectedCount) =>
      request(`/projects/${projectId}/agent-logs/cleanup`, {
        method: 'DELETE',
        body: JSON.stringify({ ...filters, expected_count: expectedCount }),
      }).then((r) => ({ deleted_count: r.deleted_count })),
  },
  threatIntel: {
    flagged: (projectId, limit = 50) =>
      request(`/projects/${projectId}/threat-intel/flagged?limit=${limit}`),
    indicators: (projectId, source = 'all') =>
      request(`/projects/${projectId}/threat/indicators?source=${source}`),
    matches: (projectId, limit = 200) =>
      request(`/projects/${projectId}/threat/matches?limit=${limit}`),
    correlation: (projectId) =>
      request(`/projects/${projectId}/threat/correlation`),
    refresh: (projectId) =>
      request(`/projects/${projectId}/threat/refresh`, { method: 'POST' }),
  },
  incidents: {
    list: (projectId) => request(`/projects/${projectId}/incidents`),
    create: (projectId, body) =>
      request(`/projects/${projectId}/incidents`, { method: 'POST', body: JSON.stringify(body) }),
    get: (incidentId) => request(`/incidents/${incidentId}`),
    update: (incidentId, body) =>
      request(`/incidents/${incidentId}`, { method: 'PATCH', body: JSON.stringify(body) }),
    listEvidence: (incidentId) => request(`/incidents/${incidentId}/evidence`),
    addEvidence: (incidentId, body) =>
      request(`/incidents/${incidentId}/evidence`, { method: 'POST', body: JSON.stringify(body) }),
    addNote: (incidentId, body) =>
      request(`/incidents/${incidentId}/notes`, { method: 'POST', body: JSON.stringify(body) }),
    exportPdf: (incidentId) => requestFile(`/incidents/${incidentId}/export/pdf`),
  },
  agents: {
    createKey: (label, projectId) =>
      request('/agents/keys', { method: 'POST', body: JSON.stringify({ label, project_id: projectId }) }),
    listKeys: () => request('/agents/keys'),
    revokeKey: (keyId) =>
      request(`/agents/keys/${keyId}`, { method: 'DELETE' }),
    listLogs: (limit = 50, offset = 0) =>
      request(`/agents/logs?limit=${limit}&offset=${offset}`),
  },
};
