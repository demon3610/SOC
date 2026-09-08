# SOC Dashboard

A self-hosted **Security Operations Center (SOC)** — one place to watch what happens across your websites and servers, get alerted about attacks, investigate them, and track the response.

**In plain English:** you install a small agent on each machine (or add telemetry to a website). Those sources send their logs to this platform. The platform scores everything for danger, shows it live on a dashboard, connects related attacks together, and lets you open *incidents* — cases you investigate, mitigate, and close with a written record.

Built with a **React (Vite)** frontend, **FastAPI** backend, **MongoDB** (durable store), **Elasticsearch** (search accelerator), and native agents for **Windows (PowerShell)**, **Linux (Bash/journald)**, and **websites (AI-generated telemetry code)**.

---

## How it works (the 2-minute version)

```
  Website telemetry     Windows agent        Linux agent
   (page views,          (Event Logs)         (journald logs)
    JS errors)                │                      │
         │                    │                      │
         ▼                    ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    FASTAPI BACKEND                          │
│  check key → parse logs → score danger → match threat feed  │
│  → save everything → push live updates to browsers          │
└──────┬───────────────────────────────┬──────────────────────┘
       │                               │
       ▼                               ▼
  MongoDB (keeps              Elasticsearch (fast
  everything, forever)         search; optional)
       │                               │
       └───────────────┬───────────────┘
                       ▼
              React dashboard (:5173)
```

1. **Collect** — agents and websites POST small JSON events to the backend.
2. **Score** — every event gets a 0–100 risk score and a severity (critical / high / medium / low / info).
3. **Watch** — the dashboard streams new events live; nothing refreshes manually.
4. **Investigate** — suspicious activity becomes an *incident* with evidence, notes, and a mitigation checklist.
5. **Close** — incidents are resolved with a written resolution note, so the record shows *why*.

If Elasticsearch goes down, nothing breaks: the platform falls back to MongoDB automatically ("Degraded" badge) and catches up when search returns.

---

## Pages (user guide)

| Page | What it's for |
| :--- | :--- |
| **Workspace** | Your projects. One project per thing you monitor (a website, an office PC fleet, a server). Create, open, delete. |
| **Overview** | At-a-glance health: event volume chart, live activity, agent status dots (green < 2 min, amber < 10 min, red = stale), severity breakdown, recent incidents. |
| **Live Events** | The main feed. Search, severity pills, host chip, and a **stream dropdown**: *security feed* (default), *security only*, *heartbeats*, *raw agent logs*. Click any row for full details + one-click incident creation. The **Live/Disconnected** badge is the browser's live-update socket, not agent health. |
| **Threat Intel** | Bigger picture per time window (24h/7d/30d): threat-feed status, attack timeline (click a bar to see that bucket's events), MITRE ATT&CK tactic matrix, attack narratives (linked event chains), a **correlation graph** (IPs → hosts → users → techniques → incidents), top risk hosts, known threat IPs, geo breakdown, IOC allowlist, and inline event triage. Clicking a feed, host, or technique filters every panel. |
| **Incidents** | Your case queue. Filter by status/severity/assignee/technique/tag, sort by urgency or age, bulk-assign and bulk-change status, export PDF (single or zip). |
| **Incident Detail** | One case: editable title (auto-generated from context when blank, e.g. "Brute Force on SHUBHAM"), severity/status, linked hosts/IPs/users/techniques that jump into Threat Intel, evidence timeline (single events or whole attack chains), mitigation checklist with technique-based suggestions, threaded notes, related incidents, and a full activity log. Closing requires a resolution note. |
| **API Keys** | Two key types: **website keys** (browser ingest, rate-limited) and **agent keys** (one machine per key). Keys are shown **once** at creation — store them immediately. Revoke is instant and permanent. |
| **Integrations** | Connection instructions per project: the **AI agent prompt** for websites (paste into Cursor/Claude Code — it writes real telemetry code, never a script tag) and one-line installers for Windows/Linux agents. |
| **Data Cleanup** | Delete old events or raw agent logs past a cutoff. Preview always runs first and the delete button stays locked until it matches; type `DELETE` to arm. Mismatched previews are rejected (409) and every cleanup lands in an undeletable **Cleanup History**. |
| **Settings** | Edit display name, change password, see workspace stats, sign out. |
| **Help** | Searchable in-app guide with quick-start steps and troubleshooting. |

---

## Quickstart

### Option A — Docker Compose (recommended)

```bash
docker compose up -d --build
```

| Service | URL |
| :--- | :--- |
| Dashboard | http://localhost:5173 |
| API + Swagger UI | http://localhost:8000/docs |
| Mongo | localhost:27017 |
| Elasticsearch | localhost:9200 |

Rebuild after backend changes: `docker compose up -d --build backend`

### Option B — Local manual run

```bash
# Terminal 1 — backend (from backend/)
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 — frontend
cd frontend && npm install && npm run dev   # :5173
```

### Environment

Root `.env.example` documents every variable (SECRET_KEY, MONGO_URL, ELASTICSEARCH_HOSTS, CORS_ORIGINS, PUBLIC_BACKEND_URL, GEOIP_DB_PATH, THREAT_FEED_URL/REFRESH_HOURS). Compose ships working dev defaults; set a real `SECRET_KEY` before exposing the server beyond localhost (the backend logs a warning otherwise).

---

## Connecting sources

### Websites — AI telemetry prompt (recommended)

On the Integrations page, copy the **AI agent prompt** and paste it into an IDE agent. It adds a small `soc-monitor`-style module to the site that sends `page_view` and `js_error` events to `POST /ingest/event` with an `X-API-Key` header. The key alone identifies the project — no project ID is sent — and the module fails silently so a dead SOC never breaks the site.

### Windows — PowerShell (run as Administrator)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { irm http://localhost:8000/install.ps1 -OutFile $env:TEMP\soc-install.ps1; & $env:TEMP\soc-install.ps1 -ApiKey YOUR_AGENT_KEY -ApiBase http://localhost:8000; Remove-Item $env:TEMP\soc-install.ps1 }"
```

Installs a scheduled task tailing Security/Application/System logs with a `RecordId` cursor (`cursor.json`), so restarts never resend. One machine per key — a second box needs its own key.

### Linux — shell (systemd or cron fallback)

```bash
curl -sfL http://localhost:8000/install.sh | bash -s -- --api-key "YOUR_AGENT_KEY" --api-base "http://localhost:8000"
```

Runs `journal_watcher.py`, tails `journalctl -o json`, persists the journal cursor, POSTs batches to `/agents/logs/bulk` roughly every second (re-queues on failure).

### What counts as an "event worth seeing"

Agents ship *everything* (heartbeats, routine lines, real attacks) but only security-relevant entries are promoted to the security feed:

- **Windows** (by log + event ID): 4625 failed logon → high, 1102/104 log cleared → critical/high, 4724 password reset → high, 7045 new service → medium, 4624 logon → medium, and more (`ALLOWED_WINDOWS_EVENTS` in `services/event_filter.py`).
- **Linux** (by parsed action): `account_added` → high, `failed_login` → medium, `successful_login` / `sudo_command` / `process_exec` → info.
- **Websites**: a ~40-rule engine scores SQLi (80), XSS (80), SSRF (90), IDOR+redirect (60), command injection, open redirect, and more; benign traffic scores 0.

Everything else stays queryable as `heartbeat` / `lifecycle` (Live Events → *raw agent logs*). Nothing is ever dropped.

### Risk scores (0–100)

- Agent events start from severity: critical 90, high 70, medium 40, low 15, info 0.
- Website detections use their rule score directly (SSRF 90, SQLi/XSS 80, …).
- **+30** if the source IP is on the known-malicious feed.
- **Burst bonus**: 3+ auth failures from one IP/user in 10 min → +20; 5+ → +40 (capped at 100).

---

## Data model

MongoDB database `soc_platform`. Every agent entry and website event lands in exactly one per-source collection, distinguished by `category` (`security_event` | `heartbeat` | `lifecycle`; website docs carry no category):

| Collection | Purpose |
| :--- | :--- |
| `users` | Analysts; unique email, bcrypt password |
| `projects` | Tenant containers; every row of every other collection ties back to one |
| `api_keys` | Website keys (`soc_…`, hashed, one-time reveal) |
| `agent_keys` | Agent keys (`sak_…` prefix shown once), enrollment binding, heartbeat |
| `events_website` | All website events (page views, JS errors) |
| `events_windows` | All Windows entries — lifecycle, heartbeat AND security events |
| `events_linux` | All Linux entries — lifecycle, heartbeat AND security events |
| `incidents` | Cases (status, severity, tags, assignee, mitigation, notes, resolution) |
| `incident_evidence` | Attached event snapshots with source (`live_events`/`correlated_chain`) |
| `threat_indicators` | Per-project manual indicators |
| `threat_suppressions` | Per-project false-positive suppressions |
| `threat_feed_cache` | Downloaded feed snapshot (survives restarts) |
| `ioc_allowlist` | Per-project known-good infrastructure (never flags) |
| `audit_log` | Immutable trail of cleanups + incident activity — the product cannot delete it |
| `counters` | Auto-increment ID sequences |

Indexes cover login email, `(project_id, timestamp)` on every `events_*` collection, agent/project/evidence lookups, and the allowlist.

---

## Key API endpoints

Interactive docs at `http://localhost:8000/docs`. All project routes enforce ownership first; agent tokens never work as user tokens and vice versa.

| Area | Endpoints |
| :--- | :--- |
| Auth | `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`, `GET/PATCH /auth/me`, `POST /auth/change-password` |
| Projects | `GET/POST /projects`, `GET /projects/{id}`, `POST /projects/{id}/select`, `DELETE /projects/{id}`, `GET /projects/{id}/sources` |
| Website keys | `POST/GET /projects/{id}/api-keys`, `DELETE /api-keys/{id}` (revoke) |
| Agent keys | `POST/GET /agents/keys`, `DELETE /agents/keys/{id}` (revoke), `DELETE /agents/keys` (all mine), `GET /agents/status` |
| Ingest | `POST /ingest/event`, `POST /agents/enroll`, `POST /agents/logs`, `POST /agents/logs/bulk` |
| Events | `GET /projects/{id}/events` (`source`, `category`, `severity`, `host`, `query`), `GET /events/{id}` |
| Threat intel | `.../threat-intel/{tactics,timeline,top-hosts,known-ips,geo,graph,narratives,flagged}`, `.../threat/{indicators,correlation,matches,refresh}`, triage `PATCH .../threat-intel/events/{id}/triage`, allowlist CRUD, bucket drill-down, match feedback |
| Incidents | `GET/POST /projects/{id}/incidents` (filters + sort), `GET/PATCH /incidents/{id}`, `POST /incidents/{id}/resolve`, `GET /incidents/{id}/related`, `POST /projects/{id}/incidents/bulk`, notes, evidence (+chain), mitigation (+suggestions), activity, PDF export |
| Cleanup | preview + delete for `events` and `agent-logs` (with `expected_count` guard), `GET /projects/{id}/cleanup-history` |
| Integrations | `GET /projects/{id}/integration-snippet`, `GET /projects/{id}/website-setup-prompt`, `GET /agents/usp.js`, `/install.sh`, `/install.ps1` |
| Live | `WS /ws/projects/{id}/live` (user JWT via `?token=`), `GET /health` |

---

## Project structure

```text
.
├── agents/                       # Agent installers + Linux watcher
│   ├── install.sh                # Linux installer (systemd/cron)
│   ├── install.ps1               # Windows installer (scheduled task)
│   └── journal_watcher.py        # journald tailer (cursor, bulk POST, requeue)
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, lifespan, safe 500 handler
│   │   ├── config.py             # Env-driven configuration
│   │   ├── auth.py               # JWT (user vs agent scopes), bcrypt, cookies
│   │   ├── database.py           # Mongo client, collection helpers, indexes
│   │   ├── dependencies.py       # Ownership guards (project/incident)
│   │   ├── ws_manager.py         # WebSocket fan-out per project
│   │   ├── static/usp.js         # Legacy browser snippet artifact
│   │   ├── models/               # Pydantic schemas (user, project, keys, incident, …)
│   │   ├── routers/              # auth, projects, api_keys, agents, ingest,
│   │   │                         # events, incidents, threat, overview, ws
│   │   └── services/
│   │       ├── rules.py          # Website attack-detection engine (~40 rules)
│   │       ├── event_filter.py   # Security-relevance gating + severity tables
│   │       ├── log_parser.py     # Raw log → summary/parsed fields
│   │       ├── risk_engine.py    # Base + threat-match + burst scoring
│   │       ├── mitre.py          # ATT&CK tactic/technique mapping
│   │       ├── threat_feed.py    # Multi-feed malicious-IP loop (4 feeds)
│   │       ├── geoip.py          # Offline MaxMind lookups (optional DB)
│   │       ├── incident_metrics.py # Evidence-derived hosts/IPs/users/techniques
│   │       ├── prompt_templates.py # Integration prompts (single source of truth)
│   │       ├── pdf_report.py     # Incident PDF renderer
│   │       ├── audit.py          # Cleanup + incident activity trail
│   │       └── elastic.py        # ES client with Mongo fallback
│   ├── data/                     # Mounted volume (GeoLite2 .mmdb goes here)
│   ├── Dockerfile                # python:3.12-slim
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx               # Routes (all project pages gated on selection)
│   │   ├── pages/                # Workspace, Overview, LiveEvents, ThreatIntel,
│   │   │                         # Incidents, IncidentDetail, APIKeys, Integrations,
│   │   │                         # DataCleanup, Settings, Help, Login, Register, Explore
│   │   ├── components/           # Modals, layout (sidebar/topbar), UI bits
│   │   ├── hooks/                # useWebSocket (socket + HTTP-poll fallback)
│   │   ├── lib/                  # API client, time formatting, query client
│   │   └── stores/               # Zustand (auth, project, toasts)
│   ├── nginx.conf
│   └── Dockerfile
├── docker-compose.yml            # mongo 7 + elasticsearch 8.17 + backend + frontend
├── .env.example                  # All environment variables documented
└── README.md
```

---

## Threat intelligence details

- **Feed**: four public blocklists (Feodo Tracker, URLhaus, Spamhaus DROP, Tor exits), refreshed every 6 h into memory + `threat_feed_cache`. Hits set `enriched.threat_match` (+30 risk) and surface under flagged/matches/known-IPs.
- **Enrichment**: offline GeoIP via local `GeoLite2-City.mmdb` (optional; sections say so honestly when absent). No per-request external calls.
- **Allowlist vs suppression**: `ioc_allowlist` = known-good infra, never flags. Match feedback = per-project false-positive suppression. Different tools, both respected everywhere.
- **Event triage**: any matched event carries status (`new` → `false_positive`), severity override (or `auto` = risk bucket), assignee, and analyst notes — editable inline.
- **Correlation graph**: derived per window from real edges (ip→host→user→event type→technique→incident), capped at top nodes with a truncation notice, cached briefly.

---

## Troubleshooting

- **No events arriving?** Key must belong to the selected project; SOC URL reachable from the source; HTTPS page → HTTPS SOC (mixed-content blocks silently).
- **401/403 from ingest?** Wrong, revoked, or cross-project key — generate a fresh one under API Keys.
- **Agent dot red?** No heartbeat for 10+ min — check the scheduled task / timer on that machine. (The dot is liveness; the Live/Disconnected badge in Live Events is your *browser's* update socket — if it sticks, log out/in once.)
- **"Degraded" health?** Elasticsearch is down; Mongo fallback is active. Nothing is lost.
- **Cleanup "Nothing matches"?** All data is newer than the cutoff, or you're in the wrong project. A 409 after preview just means data moved — re-preview and confirm again.
- **Port conflicts** — API 8000, dashboard 5173, Mongo 27017, ES 9200.
- **Mongo inspection** — `mongosh soc_platform --quiet --eval "db.getCollectionNames().forEach(c => print(c + ': ' + db[c].countDocuments({})))"`.
- **Full teardown** (wipes volumes): `docker compose down -v`.
