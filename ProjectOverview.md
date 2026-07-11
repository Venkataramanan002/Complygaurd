# Fortress Lens — Project Overview

Fortress Lens is an enterprise-grade firewall analytics and network security monitoring platform. It ingests firewall configurations from multiple vendors (Palo Alto, Cisco ASA, FortiGate), parses rules and topology, scores risk, detects attack paths, and presents findings through an interactive dark-themed dashboard. The system also supports real-time syslog ingestion, SSH-based config collection, threat intelligence enrichment, compliance auditing, and change management workflows.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Tech Stack](#tech-stack)
3. [Backend](#backend)
   - [Entry Point](#entry-point)
   - [Ingestion Pipeline](#ingestion-pipeline)
   - [API Routers](#api-routers)
   - [Analysis Engines](#analysis-engines)
   - [Services](#services)
   - [Collectors](#collectors)
   - [Parsers](#parsers)
   - [Database](#database)
4. [Frontend](#frontend)
   - [Pages](#pages)
   - [Components](#components)
   - [API Layer](#api-layer)
   - [Design System](#design-system)
5. [Configuration](#configuration)
6. [Data Flow](#data-flow)
7. [Authentication](#authentication)
8. [Running the Project](#running-the-project)
9. [Environment Variables](#environment-variables)

---

## Architecture

```
                    +------------------+
                    |   Browser (SPA)  |
                    |  fortress-lens   |
                    +--------+---------+
                             |
                     HTTP / REST API
                             |
                    +--------+---------+
                    |  FastAPI Backend  |
                    |    (main.py)      |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
     +--------+---+  +------+------+  +----+--------+
     | 14 API     |  | 10 Analysis |  | 4 Collectors |
     | Routers    |  | Engines     |  | (SSH/Syslog/ |
     |            |  | (utils/)    |  |  API/SNMP)   |
     +--------+---+  +------+------+  +----+--------+
              |              |              |
              +--------------+--------------+
                             |
                    +--------+---------+
                    |  SQLAlchemy ORM   |
                    | SQLite (dev) or   |
                    | PostgreSQL (prod) |
                    +-------------------+
```

The application follows a clean layered architecture:

- **Frontend** — React SPA with shadcn/ui components, served by Vite
- **API Layer** — 14 FastAPI routers organized by domain (auth, compliance, threats, etc.)
- **Engine Layer** — Pure Python analysis modules for risk, compliance, attack paths, etc.
- **Data Layer** — Async SQLAlchemy with 25 models across 25 tables
- **Collection Layer** — SSH, syslog, REST API, and SNMP collectors for multi-vendor devices

---

## Tech Stack

### Backend
| Component | Technology |
|-----------|-----------|
| Framework | FastAPI + Uvicorn |
| ORM | SQLAlchemy 2.x (async) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Migrations | Alembic |
| Auth | JWT (python-jose) + bcrypt (passlib) |
| Data Processing | Pandas, openpyxl |
| PDF Generation | fpdf2 |
| SSH Automation | Netmiko + Paramiko |
| HTTP Client | aiohttp, requests |
| Config Format | YAML (PyYAML) |

### Frontend
| Component | Technology |
|-----------|-----------|
| Framework | React 18 + TypeScript |
| Build Tool | Vite 8 |
| UI Library | shadcn/ui (Radix UI + Tailwind CSS) |
| Data Fetching | TanStack Query v5 |
| Routing | React Router DOM v6 |
| Charts | Recharts + D3.js (force-directed graphs) |
| Animations | Framer Motion |
| Icons | Lucide React |
| Forms | React Hook Form + Zod |
| Notifications | Sonner toast |

---

## Backend

### Entry Point

**`main.py`** bootstraps the application:
1. Sets Windows-compatible asyncio event loop policy
2. Loads `.env` configuration
3. Initializes the database (auto-creates tables on startup)
4. Registers all 14 API routers onto the FastAPI app
5. Configures CORS middleware for frontend dev servers
6. Starts Uvicorn on the configured host/port

The core FastAPI app instance is defined in `backend_topology.py` and re-exported through `main.py`.

### Ingestion Pipeline

**`backend_topology.py`** handles the primary config upload and processing flow:

1. **Upload** (`POST /api/upload-config`) — Accepts `.xml` (Palo Alto), `.conf` (Cisco ASA / FortiGate), or data files (`.csv`, `.json`, `.xlsx`)
2. **Vendor Detection** — Auto-detects firewall vendor from file content and extension
3. **Background Processing** — Spawns an async task that:
   - Parses firewall rules and network topology from the config
   - Calculates risk scores for every rule using the risk engine
   - Derives projected connections and threats from rule shapes (tagged as `source=config_projection`)
   - Builds a zone adjacency graph and computes attack paths via DFS
   - Stores all results in the database
4. **Scoped Cleanup** — On re-upload, only config-projected data is cleared; real syslog and CSV-imported records are preserved

### API Routers

All routers live in the `api/` directory and are prefixed with `/api`:

| Router | File | Purpose |
|--------|------|---------|
| **Auth** | `auth.py` | JWT login/register, `/api/auth/me` for current user |
| **Enterprise** | `enterprise.py` | Executive dashboard, compliance scores, firewall health, compromise narratives |
| **IP Analysis** | `ip_analysis.py` | IP-to-IP vulnerability analysis, attack surface scoring |
| **Collector** | `collector_api.py` | Device polling, schedule management, collector status |
| **Backup** | `backup_api.py` | Config backup triggers, history, diff viewer, downloads |
| **Syslog** | `syslog_api.py` | Start/stop syslog server, status monitoring |
| **Lifecycle** | `lifecycle_api.py` | Rule ownership, certification reviews, recertification workflows |
| **Threat Intel** | `threat_intel_api.py` | IP reputation lookup (AbuseIPDB, OTX, VirusTotal) |
| **Change Mgmt** | `change_mgmt_api.py` | Change request workflow (draft, pending, approved, deployed, rollback) |
| **Drift Alerts** | `drift_alerts_api.py` | Config drift detection and alert management |
| **Hardening** | `hardening_api.py` | Device hardening assessment and scoring |
| **Simulation** | `simulation_api.py` | What-if rule simulation |
| **Reports** | `reports_api.py` | Report generation (PDF, JSON, HTML) |
| **Segmentation** | `segmentation_api.py` | Zone trust matrix and microsegmentation recommendations |

### Analysis Engines

All engines live in `utils/` and contain pure business logic with no web framework dependencies:

| Engine | File | What It Does |
|--------|------|-------------|
| **Risk Engine** | `risk_engine.py` | Deterministic rule risk scoring using CIDR analysis, port classification, "any" detection, shadow/unused detection |
| **Compliance Engine** | `compliance_engine.py` | Checks against PCI DSS 4.0, NIST 800-53, CIS Benchmarks, HIPAA, and SOX frameworks |
| **Hardening Engine** | `hardening_engine.py` | Multi-check device hardening assessment (rule hygiene, risk posture, access control, config quality) — grades A through F |
| **Attack Path Engine** | `attack_path_engine.py` | DFS graph traversal through zone adjacency to find attacker paths from entry points to targets |
| **Attack Surface Engine** | `attack_surface_engine.py` | Per-port risk scoring with lateral movement classification and bidirectional exposure detection |
| **Rule Anomaly Engine** | `rule_anomaly_engine.py` | Detects shadowed, redundant, overlapping, and duplicate rules via CIDR comparison |
| **Simulation Engine** | `simulation_engine.py` | Models the impact of adding/removing rules before deployment |
| **Policy Diff Engine** | `policy_diff_engine.py` | Compares before/after rule states to detect policy changes |
| **Segmentation Engine** | `segmentation_engine.py` | Builds trust relationships from firewall rules and generates microsegmentation recommendations |
| **Drift Detector** | `drift_detector.py` | Detects configuration drift between backup snapshots |
| **Report Generator** | `report_generator.py` | Generates formatted reports in PDF (fpdf2), JSON, and HTML |

### Services

| Service | File | Purpose |
|---------|------|---------|
| **Data Importer** | `data_importer.py` | Full CSV/JSON/Excel ingestion pipeline with validation, chunked processing, and multi-format support. Tags imported records with `source=csv_import` |
| **Threat Intel** | `threat_intel.py` | Multi-source IP reputation with weighted scoring (AbuseIPDB 40%, OTX 30%, VirusTotal 30%) and 24-hour caching |
| **SIEM Integrator** | `siem_integrator.py` | Forwards security events to SIEM platforms (Webhook, Syslog, Splunk HEC) in CEF format |
| **Alert Service** | `alert_service.py` | Creates and manages alerts in the database |
| **Validators** | `validators.py` | Data validation functions for IP addresses, ports, protocols, and other import fields |

### Collectors

| Collector | File | Purpose |
|-----------|------|---------|
| **API Client** | `api_client.py` | Multi-vendor REST/XML API collector for Palo Alto, Fortinet, and Cisco devices |
| **SSH Collector** | `ssh_collector.py` | SSH-based config backup using Netmiko — supports vendor-specific commands, file hashing, and change detection |
| **Syslog Server** | `syslog_server.py` | Async UDP+TCP syslog receiver with queue buffering, batch processing, and auto vendor detection. Tags records with `source=syslog` |
| **SNMP Poller** | `snmp_poller.py` | SNMP-based device health monitoring |

### Parsers

| Parser | File | Purpose |
|--------|------|---------|
| **Palo Alto** | `paloalto.py` | Parses Palo Alto XML configs into rules, topology, and zones |
| **Cisco ASA** | `cisco.py` | Parses Cisco ASA `.conf` files into rules and topology |
| **FortiGate** | `fortinet.py` | Parses FortiGate config files into rules and topology |
| **Config Parsers** | `config_parsers.py` | Unified parser interface with `derive_synthetic_data()` for generating projected connections from config |
| **GeoIP** | `geoip_resolver.py` | IP geolocation resolution |
| **User Agent** | `useragent_parser.py` | HTTP user-agent string parsing |

### Database

**`database/models.py`** defines 25 SQLAlchemy ORM models:

| Model | Table | Description |
|-------|-------|-------------|
| `Connection` | `connections` | Network connection log with 35+ fields (IPs, ports, protocol, bytes, zones, NAT, geo, threat flag, data source) |
| `Threat` | `threats` | Threat detection log (type, name, severity, risk score, file info, data source) |
| `User` | `users` | Persistent user accounts with bcrypt-hashed passwords and roles |
| `FirewallRule` | `firewall_rules` | Parsed firewall rules (source/dest IP, ports, protocol, action, hit count) |
| `RuleRiskAnalysis` | `rule_risk_analysis` | Per-rule risk scores with level, category, reason, and recommendation |
| `NetworkTopology` | `network_topology` | Device/zone/port/connectivity graph |
| `AttackPath` | `attack_paths` | Calculated attack paths with hops, risk, difficulty, and weakest link |
| `ConfigUpload` | `config_uploads` | Upload tracking with progress, errors, and warnings |
| `ConfigBackup` | `config_backups` | SSH-collected config versions with hash and change detection |
| `RuleOwner` | `rule_owners` | Rule ownership and certification tracking |
| `CertificationReview` | `certification_reviews` | Rule recertification decisions and justifications |
| `ThreatIntelCache` | `threat_intel_cache` | Cached IP reputation results with TTL |
| `ChangeRequest` | `change_requests` | Change workflow records (draft through deployed/rollback) |
| `ChangeComment` | `change_comments` | Discussion threads on change requests |
| `DriftEvent` | `drift_events` | Configuration drift detections with diff data |
| `Alert` | `alerts` | System alerts (drift, threat, compliance, health) |
| `SystemHealth` | `system_health` | Device CPU, memory, session, and interface metrics |
| `AdminAudit` | `admin_audit` | Administrative action audit trail |

**Connection setup** (`database/connection.py`):
- Defaults to SQLite (`firewall.db`) for zero-setup local development
- Switches to PostgreSQL when `DATABASE_URL` env var is set
- Uses async sessions throughout for non-blocking I/O
- Auto-creates all tables on startup

**Migrations**: Alembic is configured with 3 migration files for schema evolution.

---

## Frontend

The frontend is a React 18 single-page application built with TypeScript and Vite. It uses shadcn/ui components (built on Radix UI + Tailwind CSS) with a custom dark theme.

### Pages

The app has **18 pages** organized by security domain:

| Page | Route | Purpose |
|------|-------|---------|
| **Dashboard** | `/` | Executive overview — KPIs, risk score, threat count, compliance grades, firewall health, quick navigation cards. Orchestrates 8+ API calls with TanStack Query |
| **Live Traffic** | `/live-traffic` | Real-time connection table with pagination (15/page), IP search, action filters (Allow/Deny/Drop), auto-refresh toggle, detail dialog, CSV export |
| **Traffic Analysis** | `/traffic-analysis` | Top senders/receivers charts, east-west vs north-south traffic breakdown, application usage, zone flow matrix heatmap |
| **Threats** | `/threats` | Threat severity breakdown with bar + pie charts, severity filters, threat detail modal |
| **Analysis** | `/analysis` | 5-tab analysis suite: Reachability Analysis, Vulnerable Ports, Rule Impact, Rule Anomalies, Change Impact (what-if simulator) |
| **Attack Paths** | `/attack-paths` | D3 force-directed interactive attack path graph with node detail panel, risk filtering, and IP vulnerability analysis section |
| **Remediation** | `/remediation` | Task-based remediation tracker with priority filtering, progress ring, status cycling (open/in-progress/resolved), category breakdown |
| **Rule Lifecycle** | `/rule-lifecycle` | Rule ownership assignment, certification tracking, recertification workflows, status filters (pending/expired/decommissioned) |
| **Compliance** | `/compliance` | Multi-framework compliance dashboard (PCI DSS, NIST, CIS, HIPAA, SOX) with expandable check details, evidence, and PDF export |
| **Threat Intel** | `/threat-intel` | IP reputation lookup against external feeds, IOC summary, bulk connection enrichment |
| **Changes** | `/changes` | Change request management with full workflow (draft, pending, approved, deployed) plus approve/reject/rollback actions |
| **Alerts** | `/alerts` | Alert list with type/severity badges, status filters, acknowledge actions |
| **Hardening** | `/hardening` | Device hardening scores bar chart, grade cards (A-F), expandable pass/fail checks |
| **Reports** | `/reports` | Report generation (template + format selection), download history |
| **Integrations** | `/integrations` | SIEM target cards (Splunk HEC, Elastic, Webhook, Syslog) with connection testing |
| **FW Topology** | `/firewall-topology` | D3 force-directed network topology graph with interactive zoom/pan, color-coded zones, and device detail panel |
| **Devices** | `/devices` | Device collector management, polling controls, backup history with git-like diff viewer, add-device dialog |
| **404** | `*` | Catch-all not-found page |

### Components

**Layout:**
- `AppLayout.tsx` — Master layout with sidebar + sticky header + breadcrumb navigation + page entrance animation
- `AppSidebar.tsx` — Fixed 240px left sidebar with 17 nav items, dynamic user profile from `/api/auth/me`, and Fortress Lens branding

**Feature Components:**
- `UploadModal.tsx` — Drag-and-drop file upload with progress bar, vendor auto-detection, and supported format guide
- `CompromiseNarrative.tsx` — Expandable "How This Gets Exploited" panel with attacker profile, attack steps, systems at risk
- `IpVulnerabilitySection.tsx` — IP-to-IP attack surface analyzer with D3 SVG graph and per-port risk breakdown
- `SmartTooltip.tsx` — Context-aware tooltip that explains security terms based on page context

**UI Components:**
52 shadcn/ui components in `components/ui/` built on Radix UI — includes Accordion, Button, Card, Dialog, Dropdown Menu, Popover, Table, Tabs, Toast, Tooltip, and more. All customized with the project's dark theme.

### API Layer

**`src/lib/api.ts`** (~1,100 lines) provides:

- **60+ typed API functions** covering all backend endpoints
- **40+ TypeScript interfaces** for request/response types
- **Centralized `request<T>()` helper** with:
  - 30-second timeout
  - Automatic retry (2 attempts with exponential backoff on 5xx / network errors)
  - Content-type header injection
  - Error message extraction from response body
- **Base URL resolution**: `VITE_API_URL` env var > same-origin `/api` (Vite proxy) > `http://localhost:8000` fallback

### Design System

**Theme:** Dark-mode only, defined via CSS custom properties in `index.css`:
- Background: deep charcoal (`hsl(240, 10%, 3.9%)`)
- Primary: blue (`hsl(217.2, 91.2%, 59.8%)`)
- Destructive: red, Warning: orange, Success: green, Info: purple
- Typography: Inter (sans-serif) + JetBrains Mono (monospace)

**Interactive Polish:**
- `card-interactive` — Cards lift 2px with enhanced shadow on hover
- `btn-lift` — Buttons raise 1px with glow on hover
- `page-enter` — 250ms fade-in + slide-up on route transitions
- Sidebar nav items shift 0.5px right on hover
- All corners rounded-xl (cards), rounded-2xl (dialogs), rounded-lg (buttons)
- Smooth 150-200ms cubic-bezier transitions throughout

**Standardized Typography:** All text uses Tailwind's built-in scale (`text-xs`, `text-sm`, `text-base`, `text-lg`) — no arbitrary pixel sizes.

---

## Configuration

Configuration files live in `config/`:

| File | Purpose |
|------|---------|
| `devices.yaml` | Device definitions for collectors (name, host, vendor, auth type, poll interval). Credentials referenced via env vars |
| `threat_intel.yaml` | Threat intelligence feed configuration (AbuseIPDB, OTX, VirusTotal) with source weights and cache TTL |
| `siem.yaml` | SIEM export targets (Webhook, Syslog, Splunk HEC) |
| `syslog.yaml` | Syslog server listener configuration (ports, buffer sizes) |
| `snmp_oids.yaml` | SNMP OID definitions for health polling |

---

## Data Flow

```
                         ┌─────────────────┐
                         │  Config Upload   │
                         │ (.xml/.conf)     │
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │  Vendor Parser   │
                         │ (PAN/ASA/Forti)  │
                         └────────┬────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
     ┌────────▼───────┐  ┌───────▼───────┐  ┌────────▼───────┐
     │ Firewall Rules │  │ Network Topo  │  │ Projected Conn │
     │ + Risk Scores  │  │ (zones, devs) │  │ + Threats      │
     └────────┬───────┘  └───────┬───────┘  │ (source=config)│
              │                  │           └────────┬───────┘
              │                  │                    │
              └──────────────────┼────────────────────┘
                                 │
                         ┌───────▼────────┐
                         │   Database     │
                         │  (25 tables)   │
                         └───────┬────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
     ┌────────▼───────┐ ┌───────▼──────┐  ┌────────▼───────┐
     │ Analysis APIs  │ │ Dashboard    │  │ Syslog/CSV     │
     │ (risk, comply, │ │ (KPIs, charts│  │ (source=syslog │
     │  attack paths) │ │  topology)   │  │  or csv_import)│
     └────────────────┘ └──────────────┘  └────────────────┘
```

**Data Source Tracking:** Every connection and threat record carries a `source` field:
- `config_projection` — Derived from uploaded firewall config rules
- `syslog` — Ingested from real-time syslog feeds
- `csv_import` — Imported from user-uploaded traffic data files

This allows the system to distinguish between real observed traffic and projections from config analysis.

---

## Authentication

The auth system (`api/auth.py`) provides:

- **DB-backed user accounts** stored in the `users` table with bcrypt-hashed passwords
- **JWT tokens** (HS256, 8-hour expiry) issued on login
- **Default admin account** auto-created on first startup (credentials from `DEFAULT_ADMIN_PASSWORD` env var, defaults to `admin`)
- **Endpoints:**
  - `POST /api/auth/login` — Returns JWT token
  - `POST /api/auth/register` — Creates new user (roles: viewer, analyst, admin, auditor)
  - `GET /api/auth/me` — Returns current user profile (used by the sidebar)
- **Graceful degradation** — Endpoints remain accessible without auth for development; returns "anonymous" user when no token present

---

## Running the Project

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server (default: http://localhost:8000)
python main.py
```

The database initializes automatically on first run (SQLite by default, no setup required).

### Frontend

```bash
cd fortress-lens-main

# Install dependencies
npm install

# Development server (http://localhost:5173, proxies /api to :8000)
npm run dev

# Production build
npm run build
```

### Both Together

Run the backend on port 8000 and the frontend dev server on port 5173. The Vite dev server proxies all `/api` requests to the backend automatically.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./firewall.db` | Database connection string. Set to `postgresql+asyncpg://...` for production |
| `JWT_SECRET` | `dev-secret-change-me` | Secret key for JWT token signing. **Must be changed in production** |
| `DEFAULT_ADMIN_PASSWORD` | `admin` | Initial admin password created on first startup |
| `CORS_ORIGINS` | localhost variants | Comma-separated allowed origins, or `*` for all |
| `VITE_API_URL` | (auto-detected) | Frontend API base URL override |
| `HOST` | `0.0.0.0` | Backend listen address |
| `PORT` | `8000` | Backend listen port |

---

*Fortress Lens — Enterprise Firewall Analytics Platform*
