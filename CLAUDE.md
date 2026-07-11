# Fortress Lens — Claude Code Instructions

## Critical Rules

### NEVER modify sensitive files
- `.env` — Contains JWT_SECRET, DEFAULT_ADMIN_PASSWORD, DATABASE_URL, API keys
- `config/devices.yaml` — Contains device credentials and connection strings
- `config/threat_intel.yaml` — Contains third-party API keys
- `config/siem.yaml` — Contains SIEM target credentials
- Any file containing passwords, tokens, secrets, or private keys
- If a task requires changing a sensitive file, **ask the user first** and explain exactly what will change

### NEVER modify or delete the database without explicit user permission
- `firewall.db` (SQLite dev) or the PostgreSQL `firewall` database is the live data store
- Deleting it destroys all uploaded configs, rules, attack paths, and analysis
- Always ask before destructive DB operations (DELETE all, DROP, rm firewall.db)

### Every change must work — no half-done code
- After modifying backend: verify syntax + imports actually succeed
- After modifying frontend: verify `npx tsc --noEmit` passes
- After modifying upload pipeline: test with an actual sample config upload
- After modifying database models: verify columns exist in the live DB
- Never leave broken code — if a change breaks something, fix it before moving on
- No placeholder/stub/TODO code — every function must be complete and functional

---

## Architecture Overview

```
Browser (React SPA)  ──HTTP──▶  FastAPI Backend  ──SQL──▶  PostgreSQL / SQLite
     :5173                          :8000                    :5432
```

### Main backend entry point: `main.py`
- THE main file — bootstraps the entire application
- Sets Windows asyncio policy, loads `.env`, configures logging
- Imports the FastAPI app from `backend_topology.py`
- Mounts all 15 API routers
- Adds 5 security middleware layers (AuthGuard, SecurityHeaders, UploadSizeLimit, RateLimit, RequestLogging)
- AuthGuard enforces a Bearer JWT on every /api/* route except /api/health and
  /api/auth/login — testing endpoints with curl requires logging in first
- /api/auth/register requires an admin token (no open self-registration)
- Run with `uvicorn.run(app, ...)` — never the "main:app" import string, which
  re-imports the module and registers every router/middleware twice
- Configures CORS for frontend dev servers
- Runs on port 8000 via uvicorn (NO `reload=True` on Windows)

### `backend_topology.py`
- Defines the core FastAPI app instance
- Upload endpoint (`POST /api/upload-config`) with vendor auto-detection
- `process_config_background()` — the 5-step processing pipeline:
  1. Parse rules (5%→20%)
  2. Parse topology (20%→35%)
  3. Risk analysis (35%→55%)
  4. Synthetic connections & threats (55%→75%)
  5. Attack path calculation via DFS (75%→100%)
- Device-scoped deletion: re-uploading a device only wipes THAT device's data
- Attack path DFS capped at MAX_PATHS=10000, depth=6 to prevent MemoryError

---

## Database

### Current: PostgreSQL 18.3
- Host: localhost:5432, Database: `firewall`, User: postgres
- CONNECTION_URL in `.env` (URL-encoded password for special chars)
- 19 tables, all created via `Base.metadata.create_all()` on startup

### Key Models (database/models.py)
| Model | Table | Key Fields |
|-------|-------|------------|
| Connection | connections | src_ip, dst_ip, src_port, dst_port, protocol, action, source (config_projection/syslog/csv_import) |
| Threat | threats | threat_type, threat_name, severity, risk_score, source |
| FirewallRule | firewall_rules | device_name, rule_name, source_ip, dest_ip, dest_port, action, hit_count |
| RuleRiskAnalysis | rule_risk_analysis | rule_id (FK), risk_score (0-10), risk_level, risk_category, reason, recommendation |
| NetworkTopology | network_topology | device_name, device_type, zone, ip_address, connected_to, + switch fields (vlans, trunk_ports, stp_mode) + router fields (routing_protocol, bgp_asn, bgp_neighbors, nat_rules) |
| AttackPath | attack_paths | entry_point, target, path_hops (JSON), total_risk_score, weakest_link |
| ConfigUpload | config_uploads | filename, vendor, ingestion_status, progress_percent |
| User | users | username, hashed_password, role (admin/analyst/viewer/auditor) |

### Data source tracking
- `source` column on Connection and Threat: `config_projection | syslog | csv_import`
- On re-upload, only `config_projection` records for that device are wiped
- Syslog and CSV-imported data is never deleted on config upload

---

## Parsers

| Parser | File | Input | Output |
|--------|------|-------|--------|
| Palo Alto | `parsers/config_parsers.py` → `PaloAltoXMLParser` | `.xml` | Rules from `.//rulebase/security/rules/entry`, zones from `.//vsys/entry/zone/entry` |
| Cisco ASA | `parsers/config_parsers.py` → `CiscoASAParser` | `.conf` | Rules from `access-list` lines, zones from `nameif` |
| FortiGate | `parsers/config_parsers.py` → `FortinetParser` | `.conf` | Rules from `edit <id>` policy blocks, zones from `config system interface` |
| Cisco Switch | `parsers/switch_parser.py` → `CiscoSwitchParser` | `.conf` | VLANs, trunk/access ports, STP, port-security, ACLs, SVIs |
| Cisco Router | `parsers/router_parser.py` → `CiscoRouterParser` | `.conf` | Interfaces, OSPF/BGP/EIGRP, NAT, ACLs, static routes |

### Upload file naming convention
- `*.xml` → Palo Alto firewall
- `switch*.conf` or `sw-*.conf` → Cisco switch
- `router*.conf` or `rtr*.conf` or `rt-*.conf` → Cisco router
- `*.conf` or `asa*` → Cisco ASA firewall
- `forti*` → FortiGate firewall
- `*.csv / *.json / *.xlsx` → Data import (auto-detected by column signatures)

---

## Analysis Engines (utils/)

| Engine | File | What It Does |
|--------|------|-------------|
| Risk | `risk_engine.py` | Scores each rule 0-10: CIDR scope, port danger, "any" detection, shadow/unused detection |
| Compliance | `compliance_engine.py` | PCI DSS 4.0, NIST 800-53, CIS, HIPAA, SOX automated checks |
| Hardening | `hardening_engine.py` | Device hardening grades A-F: rule hygiene, risk posture, access control |
| Attack Path | `attack_path_engine.py` | DFS graph traversal through zone adjacency |
| Attack Surface | `attack_surface_engine.py` | Per-port risk with lateral movement classification |
| Rule Anomaly | `rule_anomaly_engine.py` | Shadowed, redundant, overlapping, duplicate rules via CIDR comparison |
| Simulation | `simulation_engine.py` | What-if: model adding/removing rules before deployment |
| Policy Diff | `policy_diff_engine.py` | Before/after rule state comparison |
| Segmentation | `segmentation_engine.py` | Zone trust matrix, microsegmentation recommendations |
| Drift Detector | `drift_detector.py` | Config drift between backup snapshots |
| Report Generator | `report_generator.py` | PDF, JSON, HTML reports with evidence chains |
| **Switch Analysis** | `switch_analysis_engine.py` | VLAN segmentation, STP security, port security, trunk audit |
| **Router Analysis** | `router_analysis_engine.py` | ACL audit, NAT exposure, routing protocol security, anti-spoofing |

---

## API Routers (all prefixed /api)

| Router | File | Key Endpoints |
|--------|------|--------------|
| Enterprise | `api/enterprise.py` | `/dashboard/executive-summary`, `/firewall-health`, `/attack-surface`, `/compliance-scores`, `/firewall-topology`, `/topology/full`, `/compromise-narrative`, `/rule-anomalies`, `/policy/what-if` |
| Auth | `api/auth.py` | `/auth/login`, `/auth/register`, `/auth/me` |
| IP Analysis | `api/ip_analysis.py` | `/ip-analysis/attack-surface` |
| Upload | `backend_topology.py` | `/upload-config`, `/upload-status/{id}`, `/ingestion-status`, `/risky-rules`, `/vulnerable-ports`, `/rule-stats`, `/analyze-reachability`, `/analyze-rules` |
| Collector | `api/collector_api.py` | Device polling, schedule management |
| Backup | `api/backup_api.py` | Config backup triggers, history, diff viewer |
| Syslog | `api/syslog_api.py` | Start/stop syslog server |
| Lifecycle | `api/lifecycle_api.py` | Rule ownership, certification, recertification |
| Threat Intel | `api/threat_intel_api.py` | IP reputation (AbuseIPDB, OTX, VirusTotal) |
| Change Mgmt | `api/change_mgmt_api.py` | Change request workflow |
| Drift Alerts | `api/drift_alerts_api.py` | Config drift detection |
| Hardening | `api/hardening_api.py` | Device hardening scores |
| Simulation | `api/simulation_api.py` | Rule simulation |
| Reports | `api/reports_api.py` | PDF/JSON/HTML report generation |
| Segmentation | `api/segmentation_api.py` | Zone trust matrix |
| Integrations | `api/integrations_api.py` | SIEM target management |
| **Device Analysis** | `api/device_analysis_api.py` | `/device-analysis/{device_name}` — switch/router security analysis |

---

## Frontend Pages (fortress-lens-main/src/pages/)

| Page | Route | Data Sources |
|------|-------|-------------|
| Dashboard | `/` | executive-summary, firewall-health, attack-surface, compliance-scores, rule-stats |
| Live Traffic | `/live-traffic` | connections (paginated, filterable) |
| Traffic Analysis | `/traffic-analysis` | connections aggregate charts |
| Threats | `/threats` | threats (severity breakdown) |
| Analysis | `/analysis` | 7 tabs: Reachability, Vulnerable Ports, Rule Impact, Anomalies, What-If, **Switch Analysis**, **Router Analysis** |
| Attack Paths | `/attack-paths` | attack-paths (D3 force graph) |
| Remediation | `/remediation` | risk-analysis tasks |
| Rule Lifecycle | `/rule-lifecycle` | rule owners, certification reviews |
| Compliance | `/compliance` | compliance-scores (PCI, NIST, CIS, HIPAA, SOX) |
| Threat Intel | `/threat-intel` | IP reputation lookups |
| Changes | `/changes` | change requests workflow |
| Alerts | `/alerts` | alerts list |
| Hardening | `/hardening` | hardening scores |
| Reports | `/reports` | report generation |
| Integrations | `/integrations` | SIEM targets |
| Network Topology | `/firewall-topology` | topology/full (D3 graph with FW/SW/RT shapes) |
| Devices | `/devices` | collector, backup management |

---

## Backend Rules
- Windows: always `asyncio.WindowsSelectorEventLoopPolicy()` before async imports
- Never `reload=True` with uvicorn on Windows
- PostgreSQL for production, SQLite fallback for dev
- Zone names in rules matched case-insensitively against topology zones
- All synthetic data tagged `source="config_projection"`

## Frontend Rules
- No emojis — use Lucide icons
- No arbitrary pixel font sizes — Tailwind scale only (text-xs, text-sm, text-base, text-lg)
- All data fetching via TanStack Query (staleTime: 30s, refetchOnWindowFocus: false)
- API calls through `src/lib/api.ts` request helper (retry, timeout, error handling)
- Cards use `card-interactive` class, buttons use `btn-lift`, pages use `page-enter` animation

## Ports
- Backend: 8000 (PORT env var)
- Frontend: 5173 (Vite dev, proxies /api → :8000)
- PostgreSQL: 5432
