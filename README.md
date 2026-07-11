# Fortress Lens

A production-grade firewall configuration analysis tool. Upload firewall configs (Palo Alto, Cisco ASA, FortiGate) or traffic log data and get instant risk analysis, attack path simulation, threat detection, and remediation recommendations.

---

## Quick Start

### Windows
Double-click `START.bat`

### Linux / Mac (Local, no Docker)
Open two terminals:
1) Backend (from repo root):
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # then set JWT_SECRET and DEFAULT_ADMIN_PASSWORD
python main.py
```
2) Frontend:
```bash
cd fortress-lens-main
npm install
npm run dev
```

Then open **http://localhost:5173** and sign in.

---

## Authentication

Every `/api/*` endpoint except `/api/health` and `/api/auth/login` requires a
Bearer JWT. The frontend handles this automatically via its login page.

- **First run:** an `admin` account is created automatically with the password
  from `DEFAULT_ADMIN_PASSWORD` in `.env`. Change it after first login.
- **Creating users:** only admins can create accounts —
  `POST /api/auth/register` with an admin token
  (`{username, email, password, role}`, role: `viewer | analyst | auditor | admin`).
- **Login:** `POST /api/auth/login` with `{username, password}` returns
  `{access_token, role}`. Send it as `Authorization: Bearer <token>`.
- Login attempts are rate-limited to 5/minute per IP.

---

## Architecture

```
fortress-lens-main/   ← React + Vite frontend (port 5173)
  src/
    lib/api.ts         ← All API calls to the backend (SINGLE source of truth)
    pages/             ← Dashboard, LiveTraffic, Threats, Analysis, AttackPaths, Remediation
    components/
      upload/          ← UploadModal (config + data file uploads)
      layout/          ← AppLayout + AppSidebar

main.py               ← FastAPI entry point (port 8000)
backend_topology.py   ← All API endpoints
api/upload.py         ← /api/upload-data, /api/validate-upload, /api/download-template
parsers/              ← Palo Alto XML, Cisco ASA, FortiGate config parsers
utils/                ← risk_engine, attack_path_engine, template_generator
database/             ← SQLAlchemy models + async connection
```

---

## Manual Setup

### Backend

```bash
# From the project root
pip install -r requirements.txt
cp .env.example .env        # edit DATABASE_URL if needed
python main.py              # or: uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd fortress-lens-main
npm install
npm run dev                 # Vite dev server on :5173, proxies /api → :8000
```

---

## Uploading Data

The **Upload** button on the Dashboard opens a modal for data ingestion.

### 1. Firewall Config (XML / Conf)
Upload raw firewall configuration files to populate **Analysis**, **Topology**, **Risk**, and **Attack Paths**.

| Vendor | File type | Detection |
|--------|-----------|-----------|
| Palo Alto (PAN-OS) | `.xml` | Extension |
| Cisco ASA | `.conf` | Extension or `asa` in filename |
| FortiGate | Any | `forti` in filename |

**Note:** The backend calculates risk and attack paths strictly from the uploaded rules and topology.

### 2. Traffic / Log Data (CSV / JSON)
**Required for Live Traffic & Threats.**
Upload connection logs in `.csv`, `.json`, or `.xlsx` format to populate **Live Traffic** and **Threats**.
*   This application does **not** generate mock traffic data.
*   If no CSV is uploaded, the traffic and threat views will remain empty.
*   Use the "Download Template" feature in the API or check `test_upload.csv` for the schema.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/upload-config` | Upload + detect vendor, start background parse |
| `POST` | `/api/parse-config/{id}` | Re-trigger parse for an existing upload |
| `POST` | `/api/upload-data` | Ingest traffic/log CSV/JSON/XLSX |
| `POST` | `/api/validate-upload` | Validate a file before ingestion |
| `GET`  | `/api/download-template?format=csv\|json\|excel` | Download blank template |
| `GET`  | `/api/ingestion-status` | Latest upload status + progress |
| `GET`  | `/api/topology/summary` | Zone/rule/device counts |
| `GET`  | `/api/analytics/summary` | Connection counts, bytes, protocols |
| `POST` | `/api/analyze-rules` | Trigger background risk analysis |
| `GET`  | `/api/risk-analysis/summary` | Risk level counts + avg score |
| `GET`  | `/api/risky-rules` | Rules with score ≥ threshold |
| `GET`  | `/api/vulnerable-ports` | Exposed ports across topology |
| `POST` | `/api/analyze-reachability` | Zone reachability analysis |
| `POST` | `/api/analyze-attack-paths` | Trigger attack path calculation |
| `GET`  | `/api/attack-paths` | Fetch calculated attack paths |
| `GET`  | `/api/attack-paths/summary` | Critical/high path counts |
| `GET`  | `/api/malware-entry-points` | Identified entry point nodes |
| `GET`  | `/api/threats` | Threat log entries |
| `GET`  | `/api/connections` | Connection log entries |
| `GET`  | `/api/remediation` | Prioritised remediation items |
| `GET`  | `/api/rule-stats` | Total/enabled/disabled rule counts |
| `GET`  | `/api/health` | Health check |

Full interactive docs: **http://localhost:8000/docs**

---

## Frontend ↔ Backend Connection

The Vite dev server proxies all `/api/*` requests to `http://localhost:8000` via `vite.config.ts`:

```ts
proxy: {
  "/api": { target: "http://localhost:8000", changeOrigin: true }
}
```

**All API calls live in `src/lib/api.ts`** — one central file. Every page imports from there. The UI connects directly to the backend to display real data. If there is no data, the UI will intuitively prompt users to upload their configuration or logs. No mock data is used in production.

---

## Environment Variables

```env
# .env — JWT_SECRET and DEFAULT_ADMIN_PASSWORD are REQUIRED
JWT_SECRET=<long random string>                  # python -c "import secrets; print(secrets.token_hex(32))"
DEFAULT_ADMIN_PASSWORD=<initial admin password>
DATABASE_URL=sqlite+aiosqlite:///./firewall.db   # default SQLite
# DATABASE_URL=postgresql+asyncpg://user:pass@localhost/firewall  # for Postgres
# PORT=8000
# CORS_ORIGINS=https://your-frontend.example.com  # comma-separated; empty = localhost dev defaults
```

---

## Production Build


```bash
# Build frontend static files
cd fortress-lens-main
npm run build               # outputs to dist/

# Serve frontend via FastAPI static files (optional)
# Add to main.py: app.mount("/", StaticFiles(directory="fortress-lens-main/dist", html=True))

# Or deploy separately:
# Frontend → Vercel / Nginx
# Backend  → Gunicorn + Uvicorn workers behind Nginx
```

---

## Docker Deployment

- Backend port: `8000` (python:3.11-slim)
- Frontend port: `8501` (nginx:alpine, proxies `/api` to the backend)

### Prerequisites

```bash
docker --version
docker compose version
```

Compose reads `JWT_SECRET` and `DEFAULT_ADMIN_PASSWORD` from `.env` in the
project root — both are required. Ensure `firewall.db` exists before starting
(`touch firewall.db`), since it is bind-mounted into the container.

### Option A: Split Services (Recommended for local testing)

Runs backend and frontend as separate containers.

```bash
docker compose build backend frontend
docker compose up -d backend frontend
```

Open:

- Frontend: `http://localhost:8501`
- Backend API docs: `http://localhost:8000/docs`

Stop:

```bash
docker compose down
```

### Option B: Single Black-Box Container

Runs backend + frontend in one container using `start.sh`.

```bash
docker compose --profile blackbox build blackbox
docker compose --profile blackbox up -d blackbox
```

Open:

- App: `http://localhost:8501`
- API docs: `http://localhost:8000/docs`

Stop:

```bash
docker compose --profile blackbox down
```

### Logs and Health Checks

```bash
docker compose logs -f backend frontend
docker compose --profile blackbox logs -f blackbox
curl http://localhost:8000/api/health
```

### Docker Files Included

- `Dockerfile` (multi-stage with `backend-runtime`, `frontend-runtime`, `all-in-one-runtime` targets)
- `docker-compose.yml` (backend + frontend services + optional blackbox profile)
- `docker/nginx.frontend.conf` (frontend container proxy to backend service)
- `docker/nginx.local.conf` (all-in-one proxy to localhost backend)
- `START.sh` (runs backend and nginx in a single container)
- `.dockerignore` (build context cleanup)
