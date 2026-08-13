# SOC Dashboard

A self-hosted, near-real-time **Security Operations Center (SOC)** platform for threat monitoring, log analysis, incident management, and agent oversight.

Built with a **React (Vite)** frontend, **FastAPI** backend, **MongoDB** (metadata + event persistence), **Elasticsearch** (full-text search & analytics), and native agents for **Windows (PowerShell)**, **Linux (Bash/journald)**, and **Websites (JavaScript snippet)**.

---

## System Architecture & Data Pipeline

```
              ┌──────────────────────┬─────────────────────┬─────────────────────┐
              │   Website Snippet    │   Windows Agent     │    Linux Agent      │
              │      (usp.js)        │   (PowerShell)      │  (Bash + journald)  │
              └──────────┬───────────┴─────────┬───────────┴──────────┬──────────┘
                         │                     │                      │
              POST /ingest/event      POST /agents/logs/bulk   POST /agents/logs/bulk
                         │                     │                      │
                         ▼                     ▼                      ▼
        ┌───────────────────────────────────────────────────────────────────────┐
        │                          FASTAPI BACKEND ENGINE                       │
        │     auth → validate API key → parse & normalize → severity → enrich    │
        │     (GeoIP, threat-feed) → risk score → persist → WebSocket broadcast  │
        └──────┬──────────────────────────────┬──────────────────────┬──────────┘
               │                              │                      │
               ▼                              ▼                      ▼
   ┌────────────────────────┐   ┌──────────────────────────┐   ┌────────────────────┐
   │     ELASTICSEARCH      │   │         MONGODB          │   │     WEBSOCKET      │
   │  (full-text search,    │   │ users, projects, api_    │   │  live event stream │
   │   events + agent-logs  │   │ keys, agent_keys,        │   │  /ws/projects/…    │
   │   indices)             │   │ events_website/windows/  │   └─────────┬──────────┘
   │                        │   │ linux, incidents         │             │
   └────────────────────────┘   └──────────────────────────┘   ┌─────────┴──────────┐
                                                                          ▼
                                                              ┌────────────────────┐
                                                              │  REACT DASHBOARD   │
                                                              │   :5173 (nginx)    │
                                                              └────────────────────┘
```

Every agent entry (heartbeat, lifecycle, security event) and every website event lands in **exactly one** per-source Mongo collection — `events_website` | `events_windows` | `events_linux` — **and** Elasticsearch. Lifecycle/heartbeat entries are no longer split into a separate collection: they are ordinary documents in the same per-source collection, distinguished by the `category` field (see *Data Model*). Live Events reads Mongo (unified, filterable by `source`, security events + website events only); the search box queries Elasticsearch. If Elasticsearch is down the pipeline degrades to Mongo-only — nothing is lost.

---

## Key Features

- **Near-real-time ingestion** — agent watchers push batches every ~1 s; the dashboard streams events over WebSockets (`/ws/projects/{id}/live`).
- **Per-source event storage** — `events_website`, `events_windows`, `events_linux` collections with `(project_id, timestamp)` indexes; the Events API merges them into one time-sorted feed with a `source` filter.
- **Resilient degraded mode** — Elasticsearch outage or slowness never produces 500s or data loss; Mongo is the durable store, ES is the search accelerator.
- **Persistent cursors, no duplicate spam** — Windows agent tracks `RecordId` in `cursor.json`; Linux agent tracks journal `__CURSOR` in `journal_cursor`; both flush to disk every ~1 s so restarts don't resend.
- **Multi-tenant isolation** — every event, API key and agent is tied to a project; users only see their own data. Every project-scoped route resolves ownership through the `get_owned_project` dependency *before* any query runs, and the **Connected Sources** panel (Live Events) shows exactly which keys/agents are feeding the project so isolation is visible, not just assumed.
- **Data Cleanup with preview-first deletion** — old security events and raw agent entries (heartbeat/lifecycle) can be removed per project, per source, per hostname, and per time cutoff, with two disjoint scopes: *Events* (security events + website docs) and *Raw agent logs* (heartbeat/lifecycle only). The delete endpoint is guarded by `expected_count` (409 if the data changed since the preview), stays in sync with Elasticsearch, and every executed cleanup is appended to a permanent `audit_log` collection (visible under *Cleanup History*) that the product can never delete — cleaning up security logs is itself audit-logged.
- **Structured log normalization** — raw lines are parsed server-side into `summary`, `parsed` fields (user, source IP, action, event ID) and `severity`; the raw text is kept for forensics.
- **Security-relevant gating** — only flagged Windows event IDs and Linux actions are promoted to `security_event` category (see *Severity & Risk Scoring*); everything still lands in the same per-source collection verbatim as `heartbeat` / `lifecycle` — nothing is lost.
- **Threat intelligence** — source IPs come from the real connection (or parsed log lines), matched against a periodically refreshed known-malicious-IP feed and optionally GeoIP-enriched offline.
- **Incident workspace** — convert events into incidents, attach evidence snapshots, track status.
- **Website Setup page** — the complete IDE-agent integration prompt (interfaces, batching pseudocode, troubleshooting table) rendered verbatim with the project's real server URL + API key filled in, with copy/download and a key-generation shortcut.

---

## Tech Stack

| Component | Technology | Description |
| :--- | :--- | :--- |
| Frontend | React 18, Vite, TailwindCSS, Framer Motion, TanStack Query, Zustand | Dark-mode SOC dashboard (served via nginx) |
| Backend | Python 3.12, FastAPI, Uvicorn, PyJWT | REST + WebSocket API, schema docs at `/docs` |
| Database | MongoDB 7 (pymongo) | Users, projects, keys, agents, events, incidents |
| Search | Elasticsearch 8.17 | High-throughput full-text log search |
| Agents | PowerShell 5.1+, Bash + journald, JavaScript | Lightweight native log shippers |

---

## Prerequisites

- **Docker Desktop** (primary path), or
- Python 3.10+, Node.js 18+ (manual path below)

---

## Quickstart

### Option A — Docker Compose (recommended)

```bash
docker compose up -d --build
```

| Service | URL |
| :--- | :--- |
| Dashboard (nginx) | http://localhost:5173 |
| API + Swagger UI | http://localhost:8000/docs |
| Mongo | localhost:27017 |
| Elasticsearch | localhost:9200 |

The compose stack wires `MONGO_URL`, `ELASTICSEARCH_HOSTS`, `SECRET_KEY`, `CORS_ORIGINS`, and mounts `backend/data` into the backend (for GeoLite2 `.mmdb`). Environment overrides live in a root `.env` / `backend/.env` — see `.env.example`.

Rebuild after backend changes:

```bash
docker compose up -d --build backend
```

### Option B — Local manual run

```bash
# Terminal 1 — backend
pip install -r backend/requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload   # from backend/

# Terminal 2 — frontend
cd frontend && npm install && npm run dev                            # :5173
```

### Default credentials

A fresh database is seeded with:

- **Email**: `admin@soc.local`
- **Password**: `admin`

(Seeded by `scripts/reset_dev.py`. You can also click **Register** at `/register`.)

---

## Data Model

MongoDB database `soc_platform`:

| Collection | Purpose |
| :--- | :--- |
| `users` | Analysts; `email` unique, `hashed_password` (bcrypt) |
| `projects` | Tenant containers; owner, name, snippet embed, api_base |
| `api_keys` | `sak_…` website keys with `project_id`, `created_by`, `revoked` |
| `agent_keys` | Registered agents: id, label, project_id, os_type, status, last_seen |
| `events_website` | **All** website-sourced events (page views, JS errors, rejections) |
| `events_windows` | **All** Windows agent entries — lifecycle, heartbeat AND security events (`category` distinguishes them) |
| `events_linux` | **All** Linux agent entries — lifecycle, heartbeat AND security events (`category` distinguishes them) |
| `incidents` | Incidents + `incident_evidence` snapshots |
| `counters` | Auto-increment sequences (`get_next_id`), one row per collection |
| `audit_log` | Immutable, product-undeletable record of every executed cleanup |

These are the **only three log-bearing collections** — the former unified `events` and `agent_logs` collections are retired (dropped; nothing writes to them, no code references them). Every agent entry is one document in its per-source collection; the `category` field decides which view it belongs to.

Indexes: `email` unique on users; `(project_id, timestamp)` on each `events_*` collection; `agent_id` on `events_windows` / `events_linux`.

### Canonical document shapes

**`events_website`** — one document per website-sourced event (no `category` — not needed):

```jsonc
{
  "id": "evt_3fa85f64…",            // string
  "project_id": 2,
  "source": "website",
  "event_type": "page_view" | "js_error" | "unhandled_rejection",
  "session_id": "…",
  "raw": { "url": "…", "referrer": "…", "user_agent": "…", "message"?: "…", "stack"?: "…", "line"?: 12, "column"?: 3 },
  "enriched": { "ip": "…", "geo"?: { "country": "…", "city": "…", "lat": 0, "lon": 0 }, "threat_match"?: true, "risk_score": 0 },
  "tags": ["website"],
  "timestamp": "2026-08-09T12:00:00.123+00:00"   // ISO 8601 UTC, tz-aware
}
```

**`events_windows`** — one document per Windows agent entry **and** per promoted security event (lifecycle, heartbeat AND security):

```jsonc
{
  "id": "agent_3fa85f64…",          // string (uuid)
  "project_id": 2,
  "agent_id": 2,
  "hostname": "DESKTOP-2MFRDIN",
  "source": "windows",
  "category": "lifecycle" | "heartbeat" | "security_event",
  "event_type": "critical" | "high" | "medium" | "low" | "info",   // severity
  "summary": "Failed logon for attacker from 203.0.113.7",          // human-readable one-liner
  "parsed": { "event_id"?: "4625", "provider"?: "Microsoft-Windows-Security-Auditing", "level"?: "Information", "log_name"?: "Security", "action"?: "failed_logon", "user"?: "…", "ip"?: "…" },
  "raw": { "log_name"?: "Security", "event_id"?: "4625", "record_id"?: "1814", "provider"?: "…", "message": "…", "level"?: "info", "stage"?: "event_log", "agent_id": 2, "hostname": "…", "trace_id": "…", "time_created"?: "…" },
  "enriched": { "ip"?: "…", "geo"?: {…}, "threat_match"?: true, "risk_score": 0 },
  "timestamp": "2026-08-09T12:00:00.123+00:00"
}
```

**`events_linux`** — mirrors `events_windows`, Linux-specific parsed/raw fields:

```jsonc
{
  "id": "agent_3fa85f64…",
  "project_id": 2,
  "agent_id": 1,
  "hostname": "web-01",
  "source": "linux",
  "category": "lifecycle" | "heartbeat" | "security_event",
  "event_type": "critical" | "high" | "medium" | "low" | "info",   // severity
  "summary": "Failed login for root from 198.51.100.9",
  "parsed": { "service"?: "sshd", "process"?: "sshd", "pid"?: 1234, "severity"?: "medium", "action"?: "failed_login", "user"?: "root", "ip"?: "198.51.100.9" },
  "raw": { "time"?: "…", "host"?: "…", "process"?: "…", "pid"?: "…", "service"?: "sshd", "severity"?: "3", "message": "Failed password for root from 198.51.100.9 port 22 ssh2", "level"?: "err", "stage"?: "event_log", "agent_id": 1, "hostname": "web-01", "trace_id": "…" },
  "enriched": { "ip"?: "…", "geo"?: {…}, "threat_match"?: true, "risk_score": 0 },
  "timestamp": "2026-08-09T12:00:00.123+00:00"
}
```

The `stage` values the agents send (`heartbeat`, `event_log`, `activity`, `install_complete`, `enroll_done`, `config_saved`, …) are mapped to `category` on ingest: `heartbeat` stays `heartbeat`; entries promoted by the security allow-list become `security_event`; **everything else — including install lifecycle noise — becomes `lifecycle`**. Nothing is dropped; the original `stage`/`level` are preserved under `raw`.

### Events API rules

- `GET /projects/{id}/events?source=windows` → queries only `events_windows` (fast, index-backed).
- `source=all` (default) → Python-merged union of all three collections, sorted by `(timestamp, id)` desc; `offset`/`size` applied after merge, `total` = sum of collection counts.
- The **Events surface shows only curated rows**: website documents plus agent documents with `category = security_event`. Heartbeat/lifecycle raw agent entries are excluded — they are browsed through `GET /agents/logs` and the *Raw agent logs* cleanup tab instead.
- `source` values outside `website|windows|linux|all` → `400`.

### Agent Logs (`GET /agents/logs`)

Lists **every** entry for the user's agents from `events_windows` + `events_linux` merged, newest first — **all categories** (heartbeat, lifecycle, security_event) are returned, and the `category` field lets the client filter client-side. The curated security-event surface is served by the Events API, so the two views never overlap.

---

## Agent Deployment

API keys come from **Settings → API Keys** (or `POST /projects/{id}/api-keys`). Set the key's OS type — it determines the events collection the agent's data lands in.

### 1. Website snippet (`usp.js`)

```html
<script src="http://localhost:8000/agents/usp.js" data-soc-key="YOUR_API_KEY" data-soc-host="http://localhost:8000"></script>
```

Tracks page views, sessions and console errors via `POST /ingest/event` / `/ingest/{project_id}/event` → `events_website`.

### 2. Windows agent (PowerShell)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "& { irm http://localhost:8000/install.ps1 -OutFile $env:TEMP\soc-install.ps1; & $env:TEMP\soc-install.ps1 -ApiKey YOUR_AGENT_KEY -ApiBase http://localhost:8000; Remove-Item $env:TEMP\soc-install.ps1 }"
```

Installs a background task streaming Security/Application/System logs; `RecordId` cursor persisted to `cursor.json` → `events_windows`.

### 3. Linux agent (Bash / systemd)

```bash
curl -sfL http://localhost:8000/install.sh | bash -s -- --api-key "YOUR_AGENT_KEY" --api-base "http://localhost:8000"
```

Installs `soc-agent.service` running `journal_watcher.py`, which tails `journalctl` (`-o json`), records the last `__CURSOR` in `/etc/soc-agent/journal_cursor`, and POSTs batches to `/agents/logs/bulk` every ~1 s (re-queuing on failure) → `events_linux`.

---

## Severity & Risk Scoring

**Severity** (`event_type`) is a security assessment, not a passthrough of the OS's own level label:

- Windows allow-list (`ALLOWED_WINDOWS_EVENTS`, in `services/event_filter.py`): e.g. 4625 failed logon → `high`, 1102 audit-log-cleared → `critical`, 104 event-log-cleared → `high`, 4724 password reset → `high`, 7045 new service → `medium`, 4624 logon → `medium`, 4634 logoff → `info`.
- Linux allow-list (`ALLOWED_LINUX_ACTIONS`): `account_added` → `high`, `failed_login` → `medium`, `successful_login`/`sudo_command`/`process_exec` → `info`. (`process_exec` entries come from auditd execve records — every command run in a real user session; daemon/cron spawns with `auid=-1` are skipped at the agent.)

**Risk score** (`services/risk_engine.py`) starts from the severity base (`critical` 90, `high` 70, `medium` 40, `low` 15, `info` 0) and adds:

- **+30** if the source IP matches the known-malicious feed (`enriched.threat_match`).
- **Burst correlation**: 3+ auth-failure events from the same IP/user within 10 min → +20; 5+ → +40 (cap 100). Queries run across all three `events_*` collections.

**Gating**: only allow-listed entries are promoted to `category = security_event` (and thereby the Events surface/ES/Live Events); everything else stays in the same per-source collection with `category = lifecycle` or `heartbeat` — nothing is lost.

---

## Threat Intelligence & Enrichment

### Real source-IP capture

`enriched.ip` is never client-claimed: website events take `X-Forwarded-For` (first value, when behind a proxy) else the socket peer; agent events take the parsed source IP from the log line.

### Known-malicious IP feed

`services/threat_feed.py` keeps an in-memory set of known-bad IPs, refreshed every 6 h by default from abuse.ch Feodo Tracker (free, no key; also tolerates CSV feeds like the SSL Blacklist). Matches set `enriched.threat_match: true` (+30 risk) and surface on the Threat Intelligence page.

```env
THREAT_FEED_URL=https://feodotracker.abuse.ch/downloads/ipblocklist.txt
THREAT_FEED_REFRESH_HOURS=6
```

Test path (backend shell): `from app.services.threat_feed import add_ip; add_ip("203.0.113.7")`.

### Offline GeoIP (optional)

Drop `GeoLite2-City.mmdb` into `backend/data/` (mounted at `/app/data` in Docker, `GEOIP_DB_PATH` already set) or set `GEOIP_DB_PATH` yourself. Events then carry `enriched.geo` and the Geo Breakdown chart populates. Private/reserved/invalid IPs are skipped silently.

---

## Project Structure

```text
.
├── agents/                       # Agent installers + Linux watcher
│   ├── install.sh                # Linux agent installer (systemd)
│   ├── install.ps1               # Windows agent installer
│   └── journal_watcher.py        # Linux journald watcher (cursor, bulk POST)
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, /docs redirect, typed /health
│   │   ├── config.py             # Env-driven configuration
│   │   ├── auth.py               # JWT + bcrypt helpers
│   │   ├── database.py           # Mongo client, events_* helpers, indexes
│   │   ├── ws_manager.py         # WebSocket connection manager
│   │   ├── static/usp.js         # Website tracking snippet
│   │   ├── models/               # Pydantic schemas
│   │   ├── routers/              # auth, projects, api_keys, agents, ingest,
│   │   │                         # events, incidents, ws, overview, threat
│   │   └── services/
│   │       ├── elastic.py        # ES client wrapper (graceful degradation)
│   │       ├── log_parser.py     # Raw log → normalized parsed/summary
│   │       ├── event_filter.py   # Security-relevance gating + severity tables
│   │       ├── prompt_templates.py # Website integration prompts (single source)
│   │       ├── severity.py       # classify_severity fallback helpers
│   │       ├── risk_engine.py    # Burst + threat-match risk scoring
│   │       ├── threat_feed.py    # Known-malicious IP feed loop
│   │       └── geoip.py          # Offline MaxMind lookups
│   ├── data/                     # Mounted into container (GeoLite2 .mmdb here)
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx               # Router + layout
│   │   ├── pages/                # Overview, LiveEvents, ThreatIntel, Incidents,
│   │   │                         # IncidentDetail, WebsiteSetup, Explore,
│   │   │                         # Workspace, APIKeys, Integrations, Settings,
│   │   │                         # Help, Login, Register
│   │   ├── components/           # Reusable UI (tables, modals, charts)
│   │   ├── hooks/                # useWebSocket
│   │   ├── lib/                  # API client, time formatting
│   │   └── stores/               # Zustand (authStore, projectStore)
│   ├── nginx.conf
│   └── Dockerfile
├── scripts/                      # Maintenance utilities (repo root)
│   ├── reset_dev.py              # Drop + reseed dev data (admin user, projects)
│   └── fix_db.py                 # Legacy-schema repair (password → hashed_password)
├── docker-compose.yml            # mongo + elasticsearch + backend + frontend
├── .env.example                  # Environment reference (backend/.env for local)
└── .dockerignore / .gitignore
```

---

## REST API Summary

Full interactive docs: **http://localhost:8000/docs** (`GET /` redirects there).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/register` | Create analyst account |
| `POST` | `/auth/login` | Login → JWT |
| `GET` | `/health` | Typed health: mongo + elasticsearch status |
| `GET/POST` | `/projects` | List / create projects |
| `GET` | `/projects/{id}` | Project detail + snippet |
| `GET` | `/projects/{id}/sources` | Connected Sources: every API key + agent key feeding this project (owned-project scoped) |
| `GET` | `/projects/{id}/integration-snippet` | Script tag + short AI-agent prompt |
| `GET` | `/projects/{id}/website-setup-prompt` | Full filled-in Website Setup prompt (`X-API-Key` header; 409 until a key exists) |
| `DELETE` | `/projects/{id}` | Delete project (cascades events + keys + agents; never touches `audit_log`) |
| `POST` | `/projects/{id}/api-keys` | Create project API key |
| `DELETE` | `/api-keys/{key_id}` | Revoke a key |
| `GET` | `/projects/{id}/events?source=all\|website\|windows\|linux` | Event feed (merged + time-sorted) |
| `POST` | `/projects/{id}/events/cleanup/preview` | Read-only preview of a cleanup: `{source, hostname?, before}` → `{count, sample (≤20), oldest_match, newest_match}` |
| `DELETE` | `/projects/{id}/events/cleanup` | Execute cleanup (same body + `expected_count`); 409 if the count drifted; deletes Mongo + ES; writes `audit_log` |
| `POST` | `/projects/{id}/agent-logs/cleanup/preview` | Read-only preview for raw agent entries — heartbeat/lifecycle docs in `events_windows`/`events_linux` (same contract, disjoint from the security-event cleanup) |
| `DELETE` | `/projects/{id}/agent-logs/cleanup` | Execute raw agent-entry cleanup (heartbeat/lifecycle only; same `expected_count` guard + audit) |
| `GET` | `/projects/{id}/cleanup-history` | Permanent cleanup audit trail (user, filters, count, when) — read-only, never cleanable |
| `GET` | `/projects/{id}/events/{event_id}` | Single event by id (owner-only) |
| `GET` | `/projects/{id}/threat-intel/flagged` | Known-bad indicator matches |
| `GET` | `/projects/{id}/overview` | Stats + time-series aggregates |
| `GET/POST` | `/projects/{id}/incidents` | List / create incidents |
| `PATCH` | `/projects/{id}/incidents/{incident_id}` | Update status/severity/notes |
| `POST` | `/projects/{id}/incidents/{incident_id}/evidence` | Attach evidence |
| `POST` | `/ingest/event` · `/ingest/{project_id}/event` | Website/event ingestion (API key) |
| `POST` | `/agents/enroll` | Register a new agent (API key) |
| `POST` | `/agents/logs` · `/agents/logs/bulk` | Single / batched agent log ingestion |
| `GET` | `/agents/logs` | Raw agent entry list (heartbeat + lifecycle + security_event, all categories, filterable by `category`) |
| `GET` | `/agents` · `/agents/{agent_id}/status` | Agent list / status |
| `DELETE` | `/agents/keys/{key_id}` | Delete an agent key |
| `WS` | `/ws/projects/{id}/live` | Live WebSocket event stream |
| `GET` | `/agents/usp.js` · `/install.sh` · `/install.ps1` | Agent artifacts |

---

## Troubleshooting & Resetting

- **Reset the dev database** (drops Mongo collections + ES index, reseeds admin user and demo projects):
  ```bash
  docker compose exec backend python -m scripts.reset_dev --yes
  ```
  (Repo-root `scripts/` is baked into the backend image; for local runs: `cd backend && python -m scripts.reset_dev --yes`.)
- **Legacy DB repair** (old rows stored `password` instead of `hashed_password`): `python -m scripts.fix_db`.
- **Backend is unhealthy** — check `docker compose ps`, then `docker compose logs backend`; ES health `GET localhost:9200/_cluster/health` (yellow = normal for a single node).
- **Port conflicts** — API needs 8000, dashboard 5173, Mongo 27017, ES 9200.
- **Mongo inspection**:
  ```powershell
  Get-Content check.js | docker exec -i soc-dashboard-main-mongo-1 mongosh --quiet soc_platform
  ```
- **Full teardown** (wipes volumes): `docker compose down -v`.
