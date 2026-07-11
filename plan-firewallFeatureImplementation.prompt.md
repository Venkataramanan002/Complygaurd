# Firewall Rule Reviewer — Feature Implementation Plan

## Industry Benchmark — 6 Top Firewall Analyzers Studied

| # | Product | Vendor | Signature Capability |
|---|---------|--------|---------------------|
| 1 | **Firewall Analyzer** | ManageEngine | Log analytics, bandwidth monitoring, VPN reports, compliance (PCI-DSS/ISO/NERC-CIP), real-time change notification |
| 2 | **SecureTrack+ / SecureChange+** | Tufin | Unified policy management, rule lifecycle (recertification/decommission), revision comparison, topology-based change design, path analysis |
| 3 | **Firewall Analyzer (AFA)** | AlgoSec | Hybrid network topology visualization, application-to-rule mapping, microsegmentation, risky rule identification, cleanup/optimization |
| 4 | **Policy Manager** | FireMon | Real-time SCI risk scoring, attack path simulation, 120+ vendor support, SiQL policy query language, automated change validation |
| 5 | **Skybox Security** (now Tufin) | Skybox/Tufin | Attack surface modeling, vulnerability-to-network mapping, exposure analysis, network model simulation |
| 6 | **Expedition** | Palo Alto Networks | Config migration, best-practice adoption scoring, rule conversion across vendors, policy optimization |

---

## Curated Feature Set — 7 Pillars (replacing the raw ~80 list)

Features marked **[EXISTING]** are already implemented. Features marked **[NEW]** replace weak/vague items. Features marked **[UPGRADE]** enhance stubs already present.

### Pillar 1 — Data Collection & Multi-Vendor Integration

| # | Feature | Status |
|---|---------|--------|
| 1 | REST/XML API polling for Palo Alto, Fortinet, Check Point, Cisco | **[UPGRADE]** `collectors/api_client.py` stub exists |
| 2 | Syslog server — real-time & batch log collection/parsing | **[UPGRADE]** `collectors/syslog_server.py` stub exists |
| 3 | SSH/CLI automated config backup & scraping (Paramiko/Netmiko) | **[NEW]** replaces "OT/IoT segmentation" |
| 4 | Multi-vendor config normalization pipeline (unified internal model) | **[EXISTING]** parsers exist but need Juniper + Check Point |
| 5 | Scheduled collection jobs with interval/cron configuration | **[NEW]** replaces "SD-WAN sync" |
| 6 | Juniper SRX & Check Point R80+ parser modules | **[NEW]** replaces "SASE orchestration" |

### Pillar 2 — Network Discovery & Topology

| # | Feature | Status |
|---|---------|--------|
| 7 | Multi-vendor auto-discovery (firewalls, routers, switches, WAFs, proxies) | **[NEW]** |
| 8 | Live interactive network topology map (D3 force-directed, pan/zoom/filter) | **[UPGRADE]** static topology exists on FirewallTopology page |
| 9 | End-to-end traffic path analysis between any two IPs | **[EXISTING]** `api/ip_analysis.py` IP-to-IP |
| 10 | Device inventory with automatic config versioning & backup history | **[NEW]** replaces "SDP configuration support" |
| 11 | East-West and North-South traffic flow visibility | **[UPGRADE]** zone data exists, needs directional classification |
| 12 | Zone trust matrix with interactive heatmap | **[NEW]** replaces "Natural language rule generator" |

### Pillar 3 — Policy Analysis & Optimization

| # | Feature | Status |
|---|---------|--------|
| 13 | Unified rule parsing & normalization (all vendors → common schema) | **[EXISTING]** `parsers/` |
| 14 | Shadow, redundant, unused, and duplicate rule detection | **[UPGRADE]** risk engine scores unused; needs full shadow/overlap detection |
| 15 | Automatic least-privilege optimization suggestions | **[UPGRADE]** recommendations exist; needs traffic-based tightening |
| 16 | Rule recertification & ownership workflow (FireMon/Tufin-style) | **[NEW]** replaces "AI-driven proactive optimization" |
| 17 | Rule reordering & consolidation engine | **[NEW]** replaces "Automated documentation generation" |
| 18 | Object & group cleanup — identify unused address objects/groups | **[NEW]** replaces "WAF rule management" |
| 19 | Policy revision diff — side-by-side comparison with impact highlights | **[NEW]** inspired by Tufin Change Browser |
| 20 | Router & switch ACL analysis (extend rule engine to ACLs) | **[NEW]** replaces "Container network policy" |

### Pillar 4 — Change Management & Automation

| # | Feature | Status |
|---|---------|--------|
| 21 | End-to-end change request workflow (request → risk check → approval → deploy) | **[NEW]** |
| 22 | Pre-change simulation & risk scoring (what-if on proposed rule) | **[NEW]** |
| 23 | Configuration push via SSH/REST (Netmiko/API) with dry-run mode | **[NEW]** replaces "PCAP replay" |
| 24 | Automatic rollback on deployment failure | **[NEW]** |
| 25 | Immutable change audit trail (who, what, when, why — admin_audit table upgrade) | **[UPGRADE]** schema exists, needs full UI and workflow |
| 26 | Configuration drift detection & alerting (compare live config vs last known-good) | **[NEW]** replaces "Failure injection" |
| 27 | Scheduled bulk change execution window | **[NEW]** replaces "Cloud egress cost optimization" |

### Pillar 5 — Compliance, Risk & Threat Intelligence

| # | Feature | Status |
|---|---------|--------|
| 28 | Automated compliance audits (NIST 800-53, CIS Benchmarks, PCI-DSS 4.0, HIPAA, SOX) | **[UPGRADE]** 3 frameworks exist, need full check engine |
| 29 | On-demand & scheduled compliance reports (PDF/HTML/JSON) | **[UPGRADE]** PDF exists, need HTML + scheduled jobs |
| 30 | Dynamic threat intelligence feed correlation (abuse.ch, AlienVault OTX, VirusTotal) | **[NEW]** replaces "Synthetic attack testing" |
| 31 | Vulnerability mapping — map CVEs to device firmware/rules | **[NEW]** inspired by Tufin VMA |
| 32 | Policy violation detection & real-time alerting | **[NEW]** |
| 33 | Attack path prediction with business impact overlay | **[UPGRADE]** attack paths exist, need asset value weighting |
| 34 | Pre-deployment attack simulation via packet crafting/rule testing | **[NEW]** replaces "Cloud NSG orchestration" |
| 35 | Regulatory export templates (SOC2, ISO 27001 Annex A, PCI-DSS Evidence Pack) | **[NEW]** |

### Pillar 6 — Monitoring & Alerting

| # | Feature | Status |
|---|---------|--------|
| 36 | Real-time configuration change monitoring (polling + diff) | **[NEW]** |
| 37 | SIEM integration hub (syslog-out, webhook, Splunk HEC, Elastic) | **[NEW]** replaces "HA & clustering" |
| 38 | Anomaly detection on traffic patterns (statistical baseline + deviation) | **[NEW]** |
| 39 | Proactive heartbeat-based device health alerts | **[UPGRADE]** system_health table exists, needs alert engine |
| 40 | Bandwidth analysis & top-talker reports (ManageEngine-style) | **[NEW]** |
| 41 | Self-healing rule suggestions (auto-generate fix for detected violations) | **[NEW]** |

### Pillar 7 — Platform & Hardening

| # | Feature | Status |
|---|---------|--------|
| 42 | Multi-tenancy with tenant isolation (per-org data scoping) | **[NEW]** |
| 43 | Role-based access control (RBAC) with JWT auth | **[NEW]** |
| 44 | RESTful API documentation (OpenAPI/Swagger auto-generated) | **[EXISTING]** FastAPI auto-generates, needs polish |
| 45 | Device hardening checks (CIS Benchmark scoring per device) | **[NEW]** |
| 46 | Default-deny policy enforcement & gap detection | **[NEW]** |
| 47 | TLS decryption policy management dashboard | **[NEW]** replaces "HA/failover" |
| 48 | Security profile attachment audit (IPS/AV/URL filtering on rules) | **[NEW]** |
| 49 | Comprehensive glanceable dashboard (unified risk, topology, alert overview) | **[UPGRADE]** dashboard exists, needs unified alerting panel |
| 50 | Identity-aware policy view (user/device/app context on rules) | **[NEW]** replaces "API gateway management" |

---

## 20 Detailed Implementation Prompts

Each prompt is designed to be self-contained: hand it to an AI coding agent with access to the project and it should be able to implement the feature end-to-end.

---

### PROMPT 1 — Syslog Collection Server & Real-Time Log Ingestion

> **Context**: The file `collectors/syslog_server.py` currently contains only stubs. The backend uses FastAPI (entry point `main.py`) with async SQLAlchemy (`database/connection.py`, `database/models.py`, `database/operations.py`). Traffic data is stored in the `connections` table and threats in the `threats` table. Parsers for Palo Alto syslog CSV, Cisco ASA regex, and FortiGate key-value exist in `parsers/paloalto.py`, `parsers/cisco.py`, and `parsers/fortinet.py`. The Palo Alto parser's `parse_syslog_line()` already handles TRAFFIC/THREAT/SYSTEM log types.
>
> **Task**: Build a production-grade async UDP+TCP syslog receiver in `collectors/syslog_server.py` that:
> 1. Listens on configurable ports (default UDP 514, TCP 1514) using Python's `asyncio` datagram and stream protocols.
> 2. Accepts incoming syslog messages (RFC 3164 and RFC 5424 format) and buffers them in an `asyncio.Queue` (max 50,000 entries).
> 3. A consumer coroutine drains the queue in batches of 500 messages every 2 seconds, auto-detects the vendor (Palo Alto CSV header, Cisco `%ASA-` pattern, FortiGate `logid=`), routes each line to the correct parser, and calls the existing `insert_connection()` / `insert_threat()` operations.
> 4. Add a new FastAPI router in `api/syslog_api.py` with endpoints: `POST /api/syslog/start` (start listening), `POST /api/syslog/stop`, `GET /api/syslog/status` (returns: listening ports, messages received, messages parsed, error count, queue depth, uptime).
> 5. Register this router in `main.py` alongside the existing `enterprise_router` and `upload_router`.
> 6. Add a `config/syslog.yaml` with configurable: `udp_port`, `tcp_port`, `buffer_size`, `batch_size`, `flush_interval_seconds`, `allowed_sources` (IP whitelist).
> 7. Create a frontend card on the existing **Dashboard** (`fortress-lens-main/src/pages/Index.tsx`) in the existing grid layout that shows: Syslog Status (Running/Stopped), messages/sec rate, total ingested, a Start/Stop toggle button. Use the same Card/Badge components from `shadcn/ui` and match the existing dark theme with indigo primary accents. Add the API calls to `fortress-lens-main/src/lib/api.ts`.
>
> **Constraints**: Do NOT modify any existing pages/components beyond adding the new card to the Dashboard grid. Follow the existing async pattern (`Depends(get_db)`, `AsyncSession`). Match the existing theme (TailwindCSS dark mode, rounded-xl cards, badge colors: green=active, red=stopped). After implementation, run the backend (`uvicorn main:app`) and confirm the `/api/syslog/status` endpoint returns valid JSON. Check for import errors, undefined variables, and type mismatches. Only proceed to frontend integration after backend endpoints respond correctly.

---

### PROMPT 2 — REST/XML API Collector for Palo Alto, Fortinet & Cisco

> **Context**: `collectors/api_client.py` contains stubs. The project already parses Palo Alto XML configs in `parsers/paloalto.py` (class `PaloAltoParser`). Device connection info structure is defined in `config/devices.yaml.example`. The `database/models.py` has `firewall_rules`, `network_topology`, `connections`, `threats`, and `system_health` tables.
>
> **Task**: Implement a multi-vendor REST/XML API collector in `collectors/api_client.py`:
> 1. **Palo Alto PAN-OS XML API**: Use `aiohttp` (already in requirements.txt) to call `https://<host>/api/?type=config&action=show&xpath=/config/devices/entry/vsys/entry/rulebase/security/rules` with API key auth. Parse the XML response using the existing `PaloAltoParser.parse_rules()` logic. Also poll `/api/?type=op&cmd=<show><system><info></info></system></show>` for system health data and insert via `insert_system_health()`.
> 2. **Fortinet FortiOS REST API**: `GET https://<host>/api/v2/cmdb/firewall/policy` with Bearer token. Map JSON response fields (`policyid`, `srcintf`, `dstintf`, `srcaddr`, `dstaddr`, `service`, `action`, `logtraffic`) to the `firewall_rules` model.
> 3. **Cisco ASA REST API** (device manager): `GET https://<host>/api/fdm/latest/policy/accesspolicies/{id}/accessrules` with token. Map to `firewall_rules`.
> 4. Create a unified `DeviceCollector` class with `async def poll(device_config) -> CollectionResult` that routes to the correct vendor implementation based on `device.vendor` field.
> 5. Add `config/devices.yaml` schema: `devices: [{name, host, vendor (paloalto|fortinet|cisco), auth_type (apikey|token|basic), credentials_env_var, poll_interval_minutes, enabled}]`.
> 6. New API endpoints in `api/collector_api.py`: `POST /api/collectors/poll-now` (trigger immediate poll for a device), `GET /api/collectors/status` (last poll time, records collected, errors per device), `POST /api/collectors/schedule` (start scheduled polling). Register in `main.py`.
> 7. Frontend: Add a **Device Management** page at route `/devices` in `fortress-lens-main/src/pages/Devices.tsx`. Show a table of configured devices (name, vendor, host, last poll, status, records). Add "Poll Now" button per device. Include an "Add Device" dialog (form fields: name, host, vendor dropdown, auth type, credentials, poll interval). Add this page to the sidebar navigation in `AppSidebar.tsx` with a `Server` icon from `lucide-react`. Wire all API calls through `api.ts`.
>
> **Constraints**: Use `aiohttp.ClientSession` with SSL verification disabled as an option (`verify_ssl` in config) for lab environments. Never log or expose credentials in API responses. All new UI must use existing shadcn/ui components (Dialog, Table, Badge, Button, Select, Input) and follow the current dark theme. After implementation, verify each vendor endpoint handler returns properly structured data by testing with `POST /api/collectors/poll-now`. Fix all errors before moving to the next vendor.

---

### PROMPT 3 — SSH/CLI Automated Config Backup & Retrieval

> **Context**: The project has no SSH collection capability yet. Existing parsers (`parsers/cisco.py`, `parsers/paloalto.py`, `parsers/fortinet.py`) accept raw text or XML config content. The `config/devices.yaml.example` defines device connection info. The `database/models.py` has `admin_audit` (change tracking) and `config_uploads` (upload metadata) tables.
>
> **Task**: Build an SSH/CLI config backup collector:
> 1. Add `netmiko` and `paramiko` to `requirements.txt`.
> 2. Create `collectors/ssh_collector.py` with class `SSHConfigCollector`:
>    - `async def backup_config(device) -> ConfigBackup`: Connect via SSH, execute vendor-specific commands (`show running-config` for Cisco, `show config running` for FortiGate, `set cli config-output-format set` + `show` for PAN-OS CLI).
>    - Store each backup as a versioned file: `data/backups/{device_name}/{timestamp}.conf`.
>    - Compute SHA-256 hash of config content. Compare against previous backup hash — if different, record a "config_changed" entry in `admin_audit` table with before/after hashes.
>    - Feed new configs through the existing parser pipeline → update `firewall_rules` and `network_topology`.
> 3. New DB model `config_backups` in `database/models.py`: `id`, `device_name`, `timestamp`, `file_path`, `file_hash`, `file_size`, `version_number`, `change_detected` (bool), `change_summary` (text).
> 4. Alembic migration in `alembic/versions/` for the new table.
> 5. API endpoints in `api/backup_api.py`: `POST /api/backups/trigger/{device_name}`, `GET /api/backups/history/{device_name}` (paginated list), `GET /api/backups/diff/{backup_id_a}/{backup_id_b}` (unified diff output), `GET /api/backups/download/{backup_id}`.
> 6. Frontend: Add a **Config Backups** tab on the new Devices page (`/devices`). Show backup history table (date, version #, hash, change detected badge, file size). "Backup Now" button. "Compare" button that opens a side-by-side diff viewer modal using `<pre>` blocks with green/red line highlighting (CSS classes `bg-green-900/30` for additions, `bg-red-900/30` for deletions — matching the existing dark theme).
>
> **Constraints**: SSH credentials must come from environment variables referenced in `devices.yaml`, never hardcoded. Use `asyncio.to_thread()` for blocking Netmiko calls. Create the `data/backups/` directory on startup. Test the diff endpoint returns valid unified diff output before building the frontend diff viewer. Scan for path traversal vulnerabilities in file download endpoint.

---

### PROMPT 4 — Advanced Rule Analysis Engine (Shadow, Redundant, Overlap, Duplicate Detection)

> **Context**: The existing risk engine (`utils/risk_engine.py`, function `calculate_rule_risk()`) scores rules on a 0-10 scale for: wildcard source/destination, any port, insecure services, unused rules, and shadowed rules (basic check). The `firewall_rules` table stores: `rule_position`, `source_ip`, `dest_ip`, `source_port`, `dest_port`, `protocol`, `action`, `hit_count`. The `rule_risk_analysis` table stores risk results. The Analysis page (`fortress-lens-main/src/pages/Analysis.tsx`) has 3 tabs (Reachability, Vulnerable Ports, Rule Impact).
>
> **Task**: Build a comprehensive rule anomaly detection engine:
> 1. Create `utils/rule_anomaly_engine.py` with class `RuleAnomalyEngine`:
>    - **Shadow detection**: For each rule R, check if any higher-priority rule H (lower `rule_position`) has a superset match on source, destination, port, and protocol. If H.action != R.action, R is fully shadowed: it will never fire.
>    - **Redundancy detection**: Two rules are redundant if they have identical source, destination, port, protocol, AND action. Report the lower-priority one as redundant.
>    - **Overlap detection**: Two rules partially overlap if their source/destination CIDRs overlap (use `ipaddress` module) and port ranges intersect but are not identical. Flag the conflict.
>    - **Duplicate detection**: Exact field-match duplicates across all fields.
>    - **Overly permissive detection**: Rules with `0.0.0.0/0` source AND destination AND any-port AND action=allow. Grade severity: critical.
>    - IP comparison must handle `any`, CIDR notation (`10.0.0.0/8`), ranges, host IPs, and named objects from `network_topology`.
>    - Return: `List[RuleAnomaly]` where each has: `anomaly_type` (shadow|redundant|overlap|duplicate|overly_permissive), `rule_id`, `conflicting_rule_id`, `severity`, `explanation`, `recommendation`.
> 2. New endpoint `GET /api/rule-anomalies?device_name=&anomaly_type=` in `api/enterprise.py` that runs the engine against `firewall_rules` for the specified device (or all devices).
> 3. Add a **4th tab "Rule Anomalies"** to the Analysis page. Show: anomaly type filter (multi-select badges), sortable table with columns (Rule Name, Position, Anomaly Type, Conflicting Rule, Severity Badge, Explanation, Action button "View Details"). Clicking a row expands to show both rules side-by-side with highlighted conflicting fields. Summary bar at top: total anomalies by type (donut chart using Recharts, matching existing chart styling).
>
> **Constraints**: CIDR overlap calculation must use Python's `ipaddress.ip_network(strict=False)` — do not reinvent subnet math. The engine must be tested with the existing rules in the DB from an uploaded config before connecting the frontend. Run the endpoint and verify JSON structure. Use the same Badge color scheme (critical=red, high=orange, medium=amber, low=green) as the existing risk level badges throughout the project.

---

### PROMPT 5 — Rule Lifecycle Management & Recertification Workflow

> **Context**: Inspired by Tufin SecureChange+ and FireMon Policy Manager. The existing `firewall_rules` table has no ownership or recertification fields. The `admin_audit` table tracks changes but has no approval workflow. The frontend Remediation page (`pages/Remediation.tsx`) shows task cards with status tracking (open → in-progress → resolved) — use this pattern as a template.
>
> **Task**: Build a rule recertification and lifecycle management system:
> 1. New DB models in `database/models.py`:
>    - `rule_owners`: `id`, `rule_id` (FK→firewall_rules), `owner_name`, `owner_email`, `department`, `assigned_date`, `last_certified_date`, `certification_due_date`, `status` (active|pending_review|expired|decommissioned).
>    - `certification_reviews`: `id`, `rule_id`, `reviewer_name`, `review_date`, `decision` (certify|modify|decommission), `justification`, `risk_accepted` (bool), `next_review_date`.
> 2. Alembic migration for both tables.
> 3. API endpoints in a new `api/lifecycle_api.py`:
>    - `POST /api/rules/{rule_id}/assign-owner` (body: owner_name, email, department)
>    - `GET /api/rules/due-for-review?days_until_due=30` — returns rules where certification expires within N days
>    - `POST /api/rules/{rule_id}/certify` (body: reviewer_name, decision, justification, next_review_months)
>    - `GET /api/rules/{rule_id}/lifecycle` — full history of ownership + review decisions
>    - `POST /api/rules/bulk-assign` — assign owner to multiple rules at once
>    - `GET /api/lifecycle/dashboard` — summary: total rules, certified %, expired %, due soon %, unowned %
> 4. Register router in `main.py`.
> 5. Frontend: New page **Rule Lifecycle** at route `/rule-lifecycle` in `pages/RuleLifecycle.tsx`. Layout:
>    - Top KPI bar: Total Rules | Certified | Expired | Due Soon | Unowned (use the same Card component pattern as the Dashboard KPIs).
>    - Filter bar: Status filter (all/active/pending/expired/decommissioned), search by rule name or owner.
>    - Table: Rule Name, Device, Owner, Department, Last Certified, Due Date, Status Badge, Actions (Certify | Assign | Decommission).
>    - "Certify" button opens a Dialog with: Decision radio (Certify/Modify/Decommission), Justification textarea, Next Review selector (3/6/12 months), Risk Accepted checkbox.
>    - "Assign Owner" button opens a Dialog with: Name input, Email input, Department select.
> 6. Add to sidebar navigation in `AppSidebar.tsx` with `ClipboardCheck` icon, positioned after "Remediation".
>
> **Constraints**: Use the existing Remediation page's task card pattern as a coding reference for status badges and filter behavior. All dates must use `date-fns` (already installed) for formatting. The certification_due_date should auto-calculate from `last_certified_date + review_period`. Follow existing dark theme. Test each API endpoint returns correct JSON before building frontend forms.

---

### PROMPT 6 — Policy Revision Diff & Change Impact Analysis

> **Context**: Inspired by Tufin SecureTrack+ "Revision Comparison" and AlgoSec's rule change impact. Config backups will be versioned (from Prompt 3's `config_backups` table). The existing parsers produce structured `firewall_rules` records. The `risk_engine.py` can score individual rules. The `attack_path_engine.py` can recalculate paths after rule changes.
>
> **Task**: Build a policy revision comparison and change impact system:
> 1. Create `utils/policy_diff_engine.py`:
>    - `def diff_rulesets(old_rules: List[FirewallRule], new_rules: List[FirewallRule]) -> PolicyDiff`: Compare two rulesets by rule_name as key. Return: `added_rules[]`, `removed_rules[]`, `modified_rules[{rule_name, field_changes: [{field, old_value, new_value}]}]`, `reordered_rules[]`, `unchanged_count`.
>    - `def assess_change_impact(diff: PolicyDiff, topology, existing_paths) -> ImpactAssessment`: For added/modified rules, run `calculate_rule_risk()` on each. For removed rules, check if any active connections matched that rule (query `connections` table). Recalculate attack paths with the new ruleset and compare against existing paths — report new paths opened or paths closed. Return: `risk_delta` (+/- score change), `new_attack_paths_opened`, `attack_paths_closed`, `affected_zones[]`, `connections_impacted_count`, `risk_verdict` (safe|caution|dangerous).
> 2. API endpoints in `api/enterprise.py`:
>    - `POST /api/policy/diff` (body: `{device_name, old_backup_id, new_backup_id}`) — returns the PolicyDiff JSON.
>    - `POST /api/policy/impact` (body: same) — returns ImpactAssessment JSON.
>    - `POST /api/policy/what-if` (body: `{device_name, proposed_rules: [{action, source_ip, dest_ip, ...}]}`) — simulate adding/removing these rules and return impact.
> 3. Frontend: Add a **"Change Impact"** tab (5th tab) to the Analysis page:
>    - Device selector + two version dropdowns (populated from backup history).
>    - "Compare" button → shows diff view: added rules in green background, removed in red, modified in amber with changed fields highlighted.
>    - Impact summary panel: risk delta (↑↓ with color), new attack paths badge, connections impacted count, zone impact list.
>    - "What-If Simulator" section below: form to define proposed rules (source IP, dest IP, port, protocol, action) → "Simulate" button → shows same impact visualization.
>
> **Constraints**: The diff function must handle rule renaming gracefully (fuzzy match on source+dest+port+protocol if rule_name doesn't match). Use existing Recharts for any delta visualizations. Do not modify existing diff-unrelated tabs on the Analysis page. Run backend diff endpoint with two known configs and verify the JSON structure before frontend work.

---

### PROMPT 7 — Compliance Audit Engine Expansion (NIST 800-53, CIS Benchmarks, PCI-DSS 4.0, HIPAA, SOX)

> **Context**: The existing endpoint `GET /api/compliance-scores` in `api/enterprise.py` returns deterministic scores for 3 frameworks (PCI DSS, ISO 27001, NIST CSF) based on rule counts, risk distribution, and basic policy checks. The logic is inline in the endpoint handler. This needs to be refactored into a pluggable engine and expanded.
>
> **Task**: Build a comprehensive compliance checking engine:
> 1. Create `utils/compliance_engine.py` with class `ComplianceEngine`:
>    - Base class `ComplianceFramework` with method `async def evaluate(rules, topology, connections, threats) -> ComplianceResult`.
>    - Subclasses for each framework, each defining specific `checks: List[ComplianceCheck]`:
>      - **PCI-DSS 4.0**: Requirement 1 (network segmentation checks — verify DMZ rules exist, no direct internet-to-cardholder-data paths), Req 1.2 (restrict inbound to only necessary), Req 1.3 (deny by default), Req 1.4 (personal firewall), Req 11 (vulnerability scans).
>      - **NIST 800-53**: AC-4 (information flow enforcement), SC-7 (boundary protection — verify perimeter rules), CM-7 (least functionality — flag unused wide-open rules), AU-2 (audit events — verify logging enabled on rules).
>      - **CIS Benchmarks**: Benchmark checks per vendor (e.g., "Ensure admin access restricted to management VLAN", "Ensure logging enabled on deny rules", "Ensure SNMP community strings are not default").
>      - **HIPAA**: Access controls on health data segments, audit trail requirements, encryption in transit checks.
>      - **SOX**: Change management verification, segregation of duties in admin_audit.
>    - Each check returns: `check_id`, `check_name`, `description`, `status` (pass|fail|warning|not_applicable), `evidence` (the specific rules/data that triggered pass/fail), `remediation_suggestion`.
>    - `ComplianceResult`: `framework`, `overall_score` (0-100), `status`, `total_checks`, `passed`, `failed`, `warnings`, `checks: List[CheckResult]`.
> 2. Refactor the existing `/api/compliance-scores` endpoint to use the new engine. Add `GET /api/compliance/{framework}/details` for per-check breakdown. Add `GET /api/compliance/report?framework=&format=pdf|html|json` for exportable reports.
> 3. Frontend: Upgrade the compliance section on the Dashboard to show all 5+ frameworks. Each framework card shows: score gauge (0-100 with color), pass/fail/warning counts, "View Details" link. Create `/compliance` page with: framework selector tabs, per-check expandable list (check name, status badge, evidence list, remediation text), "Export Report" button (PDF/HTML download). Add to sidebar with `ShieldCheck` icon.
>
> **Constraints**: Each compliance check must be data-driven — query the actual `firewall_rules`, `connections`, `network_topology` tables. No hardcoded pass/fail. Use the existing PDF generation pattern (`fpdf2` in `api/enterprise.py`'s export endpoint) for PDF reports. Match existing badge colors. Test each framework's `evaluate()` method independently against the current DB data before connecting to frontend.

---

### PROMPT 8 — Threat Intelligence Feed Integration

> **Context**: The `threats` table stores detected threats (`threat_type`, `threat_name`, `src_ip`, `dst_ip`, `severity`, `risk_score`). Currently threats come only from parsed firewall logs. There is no external threat intelligence enrichment. The project uses `aiohttp` and `requests` for HTTP.
>
> **Task**: Integrate external threat intelligence feeds:
> 1. Create `services/threat_intel.py` with class `ThreatIntelService`:
>    - **AbuseIPDB** check: `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}` — returns abuse confidence score, ISP, country, usage type, reports count.
>    - **AlienVault OTX** pulse check: `GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general` — returns pulse count, reputation score, related malware.
>    - **VirusTotal** IP report: `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}` — returns detection stats, associated files/URLs.
>    - Each source returns a normalized `ThreatIntelResult`: `ip`, `source`, `risk_score` (0-100), `is_malicious` (bool), `categories[]`, `country`, `isp`, `last_reported`, `reports_count`, `raw_data`.
>    - Aggregate across sources: combined risk = weighted average (AbuseIPDB 40%, OTX 30%, VT 30%).
>    - Cache results in a new `threat_intel_cache` table: `ip`, `source`, `result_json`, `queried_at`, `ttl_hours`. Respect TTL (default 24h) to avoid API rate limits.
> 2. New DB model `threat_intel_cache` and alembic migration.
> 3. API endpoints in `api/threat_intel_api.py`:
>    - `GET /api/threat-intel/check/{ip}` — check single IP across all feeds
>    - `POST /api/threat-intel/bulk-check` (body: `{ips: string[]}`) — batch check
>    - `GET /api/threat-intel/enrich-connections` — scan all unique source IPs in `connections` table against feeds, update threat scores
>    - `GET /api/threat-intel/ioc-summary` — top malicious IPs seen in traffic, aggregated scores
> 4. Add to `config/threat_intel.yaml`: API keys as env var references, enabled/disabled per source, rate limits, TTL.
> 5. Frontend: Add a **Threat Intelligence** page at `/threat-intel`. Layout: Search bar (enter IP → get instant enrichment card), IOC summary table (top 20 malicious IPs from traffic, with scores, flags, country). On the existing LiveTraffic page, add a threat score badge next to each connection's source IP (color-coded: >70 red, >40 orange, <40 gray "clean"). On the Threats page, add an "Enrich All" button that triggers bulk checking.
>
> **Constraints**: API keys must never be in source code — read from env vars via `os.environ`. Rate-limit API calls (AbuseIPDB: 1000/day, VT: 500/day, OTX: unlimited). The cache TTL must be respected. Handle API failures gracefully (return cached data or "unavailable" status). Match theme. Test each feed individually with a known malicious IP before integrating the frontend.

---

### PROMPT 9 — Change Management Workflow (Request → Approval → Deploy)

> **Context**: Inspired by Tufin SecureChange+ and FireMon's change automation. The project has an `admin_audit` table for change tracking and a Remediation page with task status workflow (open → in-progress → resolved) that can serve as a UI pattern reference. The risk engine can score proposed rules. The attack path engine can assess impact.
>
> **Task**: Build an end-to-end change management workflow:
> 1. New DB models in `database/models.py`:
>    - `change_requests`: `id`, `title`, `description`, `requester_name`, `requester_email`, `request_date`, `status` (draft|pending_review|approved|rejected|implementing|deployed|rolled_back|failed), `priority` (critical|high|medium|low), `device_name`, `change_type` (add_rule|modify_rule|delete_rule|reorder), `proposed_changes` (JSON — array of rule definitions), `risk_score` (auto-calculated), `risk_assessment` (JSON — impact analysis result), `reviewer_name`, `review_date`, `review_notes`, `deployment_date`, `rollback_data` (JSON — original state for undo).
>    - `change_comments`: `id`, `change_request_id` (FK), `author`, `comment`, `created_at`.
> 2. API endpoints in `api/change_mgmt_api.py`:
>    - `POST /api/changes` — create change request (auto-runs risk assessment on proposed rules using risk engine + attack path engine, stores result)
>    - `GET /api/changes?status=&priority=&device=` — list with filters
>    - `GET /api/changes/{id}` — full detail with comments and risk assessment
>    - `POST /api/changes/{id}/approve` (body: reviewer_name, notes)
>    - `POST /api/changes/{id}/reject` (body: reviewer_name, reason)
>    - `POST /api/changes/{id}/deploy` — pushes the change (for now: inserts/updates rules in DB, records in admin_audit). If change fails, auto-sets status to "failed".
>    - `POST /api/changes/{id}/rollback` — restores rollback_data and updates status
>    - `POST /api/changes/{id}/comment` — add comment
> 3. Frontend: New page **Change Management** at `/changes`. Layout:
>    - KPI bar: Open Requests | Pending Review | Deployed This Week | Rollbacks
>    - Filter bar: status tabs, priority filter, device filter, search
>    - Table: ID, Title, Requester, Device, Type, Priority Badge, Risk Score Badge, Status Badge, Date, Actions
>    - Detail view (slide-out panel or separate route `/changes/:id`): full change description, proposed rules table, risk assessment panel (risk score, attack paths impact, affected zones), comment thread, action buttons (Approve/Reject/Deploy/Rollback based on current status)
>    - "New Change Request" button → multi-step form: Step 1 (Title, Description, Device, Priority), Step 2 (Define proposed rules — add rows with source/dest/port/protocol/action), Step 3 (Auto risk assessment preview), Step 4 (Submit)
> 4. Add to sidebar with `GitPullRequest` icon after "Rule Lifecycle".
>
> **Constraints**: Status transitions must be enforced in the backend (e.g., can't deploy a rejected request, can't rollback a draft). The risk assessment must reuse existing `calculate_rule_risk()` and `calculate_attack_paths()` functions, not duplicate logic. Use the Remediation page's status badge pattern. All actions must create an `admin_audit` entry. Run the complete create→approve→deploy→rollback flow via API before building the frontend.

---

### PROMPT 10 — Configuration Drift Detection & Auto-Remediation Alerting

> **Context**: Config backups are versioned (Prompt 3). The `config_backups` table stores hashes and file paths. The `admin_audit` table tracks config changes. Device polling exists via API/SSH collectors. The `system_health` table has device metrics.
>
> **Task**: Build continuous configuration drift detection:
> 1. Create `utils/drift_detector.py` with class `DriftDetector`:
>    - `async def detect_drift(device_name) -> DriftReport`: Pull latest backup from `config_backups`. Collect current live config from device (via SSH or API collector). Compare hash. If different, parse both configs through the vendor parser, generate rule-level diff using `policy_diff_engine.py`.
>    - `DriftReport`: `device_name`, `drift_detected` (bool), `baseline_backup_id`, `live_config_hash`, `diffs: PolicyDiff`, `severity` (critical if security rules changed, medium if logging/management changed, low if cosmetic), `detected_at`.
> 2. New DB model `drift_events`: `id`, `device_name`, `detected_at`, `severity`, `drift_summary`, `diff_json`, `baseline_backup_id`, `acknowledged` (bool), `acknowledged_by`, `remediation_action` (none|auto_rollback|manual).
> 3. Scheduled drift checking: Add a background task that runs every 15 minutes (configurable in `config/drift.yaml`), checks all enabled devices, inserts `drift_events` for any detected drift.
> 4. Alerting: Create `services/alert_service.py` — when drift is detected, generate an alert. For now, store alerts in a new `alerts` DB table (`id`, `alert_type`, `severity`, `title`, `message`, `source_device`, `created_at`, `acknowledged`, `acknowledged_by`). Future: webhook/email integration.
> 5. API endpoints: `GET /api/drift/events?device_name=&severity=&acknowledged=`, `POST /api/drift/events/{id}/acknowledge`, `GET /api/drift/check-now/{device_name}`, `GET /api/alerts?type=&severity=&acknowledged=`, `POST /api/alerts/{id}/acknowledge`.
> 6. Frontend: Add an **Alerts** bell icon button in the header bar (`AppLayout.tsx`) with unacknowledged count badge. Clicking opens a dropdown panel showing recent alerts (title, severity badge, time, device). "View All" links to a new `/alerts` page with full alert table + acknowledge actions. Add drift status indicator on the Devices page for each device (green checkmark = no drift, red warning = drift detected).
>
> **Constraints**: Drift detection must not block the event loop — use `asyncio.to_thread()` for SSH operations. Alert badge must update without full page refresh (use React Query's `refetchInterval`). Severity colors must match established project convention. Test drift detection by manually modifying a backed-up config and running `check-now`.

---

### PROMPT 11 — Interactive Network Topology Map (D3 Force-Directed, Pan/Zoom/Filter)

> **Context**: The current `FirewallTopology.tsx` page shows static device cards and zone connection lists. The `GET /api/firewall-topology` endpoint returns `{firewalls[], connections[]}`. The `network_topology` table has: `device_name`, `device_type`, `zone`, `ip_address`, `connected_to` (JSON array), `is_entry_point`. The AttackPaths page already uses a D3 force-directed graph canvas — use that as the implementation reference pattern.
>
> **Task**: Replace the static topology view with a full interactive network map:
> 1. Backend: Enhance `GET /api/firewall-topology` to include: all `network_topology` devices (not just firewalls), their zone membership, interface IPs, connected_to links, device health status (join with `system_health`), rule counts per device. Add filter query params: `?device_type=&zone=&search=`.
> 2. Frontend — Rebuild `FirewallTopology.tsx`:
>    - **Canvas**: Full-width D3 force simulation with SVG. Nodes = devices (icon shape by type: shield for firewall, server for server, router icon for router, switch icon for switch). Color by zone (generate consistent HSL from zone name). Size by rule count.
>    - **Interactions**: Pan (drag background), zoom (scroll wheel), drag nodes to reposition. Click node → sidebar detail panel (device info, health metrics, rules summary, connected neighbors). Hover → tooltip with IP + zone + device type.
>    - **Edges**: Lines between connected devices. Color by trust level (green=high, amber=medium, red=low). Dashed lines for cross-zone connections. Edge tooltip showing shared rules count.
>    - **Controls panel** (top-right): Device type filter checkboxes, zone filter dropdown, search input (filters nodes by name/IP), layout toggle (force-directed vs hierarchical), "Fit to screen" button, "Export as PNG" button.
>    - **Minimap** (bottom-right corner): Small overview of entire topology for navigation.
>    - **Legend**: Color = zone, shape = device type, edge style = trust level.
>    - Keep the existing KPI cards at the top of the page.
> 3. Use the AttackPaths page's D3 force graph implementation (`pages/AttackPaths.tsx`, the SVG rendering and simulation setup) as the direct coding pattern. Extend it with the new interaction features.
>
> **Constraints**: Must handle 500+ nodes without performance degradation — use `d3-force` simulation with `alphaDecay(0.02)` and limit tick calculations. Do NOT add `d3` as a new dependency — use `d3-force`, `d3-zoom`, `d3-selection` (tree-shakeable). If those aren't installed, add only the specific d3 sub-packages. Match the existing dark theme canvas background. Test with the existing topology data before adding interaction features.

---

### PROMPT 12 — Bandwidth Analysis, Top-Talkers & Traffic Flow Reports

> **Context**: Inspired by ManageEngine Firewall Analyzer's bandwidth monitoring. The `connections` table has: `bytes_sent`, `bytes_received`, `packets_sent`, `packets_received`, `src_ip`, `dst_ip`, `protocol`, `zone_from`, `zone_to`, `app_name`, `timestamp`. The LiveTraffic page shows raw connections. The Dashboard shows protocol distribution charts.
>
> **Task**: Build bandwidth analysis and traffic flow reporting:
> 1. API endpoints in `api/enterprise.py`:
>    - `GET /api/traffic/top-talkers?limit=20&time_range=24h&direction=both` — top source/destination IPs by total bytes, with protocol breakdown.
>    - `GET /api/traffic/bandwidth-timeline?interval=1h&time_range=24h` — time-series: bytes in/out per interval, grouped by protocol.
>    - `GET /api/traffic/zone-flow-matrix` — zone-to-zone traffic volume matrix (zone_from × zone_to → total bytes).
>    - `GET /api/traffic/application-usage?limit=20` — top applications by bytes, with user counts.
>    - `GET /api/traffic/east-west-vs-north-south` — classify traffic: East-West (same zone or internal-to-internal) vs North-South (to/from external/internet zone). Return volumes and percentages.
> 2. Frontend: New page **Traffic Analysis** at `/traffic-analysis`:
>    - **Top Talkers**: Horizontal bar chart (Recharts) — IP on Y axis, bytes on X, color by direction (inbound blue, outbound orange).
>    - **Bandwidth Timeline**: Area chart — stacked by protocol (TCP blue, UDP green, ICMP yellow, other gray), time on X axis.
>    - **Zone Flow Matrix**: Heatmap grid — zones on both axes, cell color intensity by traffic volume. Click cell → filter to those zone-pair connections in LiveTraffic.
>    - **Application Usage**: Treemap or horizontal bar chart — app name + category, sized/colored by bytes.
>    - **East-West vs North-South**: Donut chart with two segments + percentage labels.
>    - Time range selector at top (1h, 6h, 24h, 7d, 30d) that re-fetches all data.
> 3. Add to sidebar with `BarChart3` icon, positioned after "Live Traffic".
>
> **Constraints**: All queries must use SQL aggregation (SUM, GROUP BY) in the database layer — do NOT load all rows into Python and aggregate in memory. Use the existing Recharts pattern from the Dashboard (same color palette, same card wrapper). The zone flow matrix heatmap can be built with a `<table>` styled with Tailwind + dynamic background-color intensity. Test each API endpoint's SQL performance with `EXPLAIN` on the query if there are more than 10k connections.

---

### PROMPT 13 — RBAC Authentication & Multi-Tenancy

> **Context**: The project currently has no authentication. All endpoints are open. The `admin_audit` table has `admin_username` but nothing enforces identity. FastAPI supports OAuth2 and JWT out of the box.
>
> **Task**: Add role-based access control with JWT authentication:
> 1. Add `python-jose[cryptography]`, `passlib[bcrypt]` to `requirements.txt`.
> 2. New DB models in `database/models.py`:
>    - `users`: `id`, `username`, `email`, `hashed_password`, `role` (admin|analyst|viewer|auditor), `tenant_id` (FK), `is_active`, `created_at`, `last_login`.
>    - `tenants`: `id`, `name`, `slug`, `created_at`, `is_active`. All data tables get a new nullable `tenant_id` column.
>    - `api_keys`: `id`, `user_id` (FK), `key_hash`, `label`, `permissions` (JSON), `expires_at`, `created_at`, `is_active`.
> 3. Alembic migration adding `tenant_id` to `connections`, `threats`, `firewall_rules`, `network_topology`, `system_health` tables (nullable, default null for backward compatibility).
> 4. Auth module `api/auth.py`:
>    - `POST /api/auth/login` (username + password) → returns JWT access token (1h expiry) + refresh token (7d).
>    - `POST /api/auth/refresh` → new access token from valid refresh token.
>    - `POST /api/auth/register` (admin-only) → create new user.
>    - `GET /api/auth/me` → current user profile.
>    - Dependency `get_current_user(token)` → validates JWT, returns User. Dependency `require_role(roles)` → role check.
>    - All existing API endpoints wrapped with `Depends(get_current_user)`. Role restrictions: admin=all, analyst=read+write data, viewer=read only, auditor=read+export.
> 5. A default admin user is auto-created on first startup if no users exist (username: `admin`, password from `ADMIN_PASSWORD` env var or generated and logged once).
> 6. Tenant scoping: A middleware or dependency that reads `tenant_id` from the JWT and adds `WHERE tenant_id = :tid` to all data queries (or `tenant_id IS NULL` for backward compatibility).
> 7. Frontend: Add a login page at `/login`. Redirect unauthenticated users. Store JWT in memory (not localStorage — XSS protection). Add user avatar/menu in the header (`AppLayout.tsx`) with: username, role badge, logout button. Add `/admin/users` page (admin-only) for user management: CRUD table with role selector.
>
> **Constraints**: Passwords must use bcrypt with cost factor 12. JWT secret from `JWT_SECRET` env var (error if not set in production). Refresh tokens stored as hashed values only. Never return passwords in API responses. Implement CSRF protection for cookie-based auth or stick to Bearer token auth. Add `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` headers. Test the full login→authenticated request→token refresh→logout flow before building the frontend login page.

---

### PROMPT 14 — Device Hardening Checks (CIS Benchmark Scoring)

> **Context**: Inspired by FireMon's real-time risk scoring and CIS Benchmarks. The project parses device configs (Palo Alto XML, Cisco ASA, FortiGate). The `firewall_rules` and `network_topology` tables store device data. Config backups store raw configs.
>
> **Task**: Build a device hardening assessment engine:
> 1. Create `utils/hardening_engine.py` with class `HardeningEngine`:
>    - Per-vendor check suites. Each check: `check_id`, `category`, `description`, `severity`, `check_function`.
>    - **Universal checks** (all vendors):
>      - Default-deny policy: verify last rule in ruleset is deny-all. FAIL if not present.
>      - Admin access restriction: verify management access rules restrict source to specific management VLAN/IPs.
>      - SNMP community strings: parse config for `snmp-server community` (Cisco) or equivalent — flag if "public" or "private" detected.
>      - Logging on deny rules: verify deny rules have logging enabled (check `log` attribute in parsed rules).
>      - Unused rules: flag rules with `hit_count=0` and age > 90 days.
>      - Weak crypto: scan config for DES, 3DES, MD5 references — recommend AES-256/SHA-256.
>      - Telnet enabled: flag if telnet management is configured.
>      - Password complexity: check password policy config blocks.
>    - **Palo Alto specific**: Security profiles (IPS/AV/URL/WildFire) attached to allow rules, decryption policy enabled, GlobalProtect config, logging to SIEM configured.
>    - **Cisco specific**: `enable secret` vs `enable password`, `service password-encryption`, `no ip http server`, `ntp authentication`.
>    - **FortiGate specific**: `admin-restrict-local`, `strong-crypto enable`, `auto-firmware-upgrade`.
>    - Scoring: Each check has weight (1-5). Device score = (passed_weight_sum / total_weight_sum) × 100. Grade: A (≥90), B (≥75), C (≥60), D (≥40), F (<40).
> 2. API endpoints: `GET /api/hardening/{device_name}` (full check results), `GET /api/hardening/summary` (all devices with grades), `POST /api/hardening/check-now/{device_name}` (force re-check).
> 3. Frontend: Add a **Hardening** tab on the Devices page. Show: grade badge per device (A+ green through F red), expandable check list (✅/❌ per check with description and remediation), overall posture bar chart (devices on X, score on Y). CIS Benchmark reference links in check descriptions.
>
> **Constraints**: Checks must work against the parsed data in DB AND raw config text (from backups) where structured parsing doesn't capture the needed field. Store check results in a `hardening_results` table (avoid re-running expensive checks on every page load). Use the existing grade/score pattern from the `getFirewallHealth()` endpoint. Match theme. Test checks against an uploaded Palo Alto config before connecting the frontend.

---

### PROMPT 15 — Pre-Change Simulation & What-If Rule Testing

> **Context**: The risk engine scores rules. The attack path engine calculates zone-to-zone paths. The policy diff engine (Prompt 6) assesses change impact. The change management workflow (Prompt 9) needs risk assessment before approval.
>
> **Task**: Build a what-if simulation engine for proposed rule changes:
> 1. Create `utils/simulation_engine.py` with class `RuleSimulator`:
>    - `async def simulate_add_rule(proposed_rule, device_name) -> SimulationResult`: Load all current rules for the device. Insert proposed rule at the specified position. Run: (a) shadow check — does any existing rule shadow this new rule? (b) conflict check — does this rule conflict with (override) any existing rule? (c) risk score of the new rule alone. (d) calculate new attack paths with the rule included vs without — delta. (e) compliance impact — will this rule cause any compliance check to fail?
>    - `async def simulate_remove_rule(rule_id) -> SimulationResult`: Remove rule from working set. Check: (a) any connections in the last 30 days that matched this rule? (b) attack paths that relied on this rule being deny — do new attack paths open? (c) compliance impact — does removing a deny rule break default-deny compliance?
>    - `async def simulate_modify_rule(rule_id, changes) -> SimulationResult`: Apply changes to a copy of the rule. Run same analysis as add_rule.
>    - `SimulationResult`: `risk_score_before`, `risk_score_after`, `risk_delta`, `new_attack_paths: List[AttackPath]`, `closed_attack_paths: List[AttackPath]`, `shadowed_by: Optional[RuleRef]`, `conflicts_with: List[RuleRef]`, `compliance_violations: List[str]`, `affected_connections_count`, `verdict` (safe|warning|dangerous), `explanation: str`.
> 2. API: `POST /api/simulate/add-rule`, `POST /api/simulate/remove-rule/{rule_id}`, `POST /api/simulate/modify-rule/{rule_id}`.
> 3. Frontend: Integrate into the Change Management "New Change Request" flow (Step 3 from Prompt 9). When the user defines proposed rules and clicks "Assess Risk", call the simulation API and show: verdict badge (green/amber/red), risk delta metric, before/after attack path count, conflict list, compliance warnings. Also add a standalone "What-If Lab" section to the Analysis page's new "Change Impact" tab.
>
> **Constraints**: Simulation must NOT modify the database — work on in-memory copies of the ruleset. The simulation should complete in under 5 seconds for 1000 rules (profile and optimize if needed). Reuse existing `calculate_rule_risk()` and `calculate_attack_paths()` — do not re-implement scoring logic. Test each simulation type independently before integrating with the change workflow frontend.

---

### PROMPT 16 — Real-Time Alerts Dashboard & Notification Engine

> **Context**: The `alerts` table is created in Prompt 10. Multiple features generate alerts: drift detection, compliance violations, threat intel hits, device health degradation. The `system_health` table has CPU/memory/session metrics. The Dashboard needs a unified alert view.
>
> **Task**: Build a centralized alert and notification system:
> 1. Expand `services/alert_service.py`:
>    - `AlertEngine` class with `register_alert_source(name, check_fn, interval, severity_fn)`.
>    - Built-in alert sources:
>      - **Device Health**: CPU > 80%, Memory > 85%, Sessions > 90% capacity → high alert; CPU > 95% → critical.
>      - **Rule Risk**: New rule with risk_score ≥ 8 ingested → critical alert.
>      - **Compliance**: Any framework score drops below 60 → high alert.
>      - **Threat Spike**: More than 10 critical-severity threats in 5 minutes → critical alert.
>      - **Config Drift**: drift_detected = true → alert (severity from DriftReport).
>    - Alert deduplication: same alert_type + source_device + message within 1 hour → update existing, don't create duplicate.
>    - Alert lifecycle: created → acknowledged → resolved. Auto-resolve after condition clears (e.g., CPU drops back below 80%).
> 2. WebSocket endpoint `ws://localhost:8000/ws/alerts` that pushes new alerts to connected frontends in real-time. Use FastAPI's WebSocket support.
> 3. API: `GET /api/alerts/summary` (count by severity and state), `GET /api/alerts?...` (paginated list), `POST /api/alerts/{id}/acknowledge`, `POST /api/alerts/{id}/resolve`, `DELETE /api/alerts/resolved` (clear old resolved alerts).
> 4. Frontend:
>    - **Alert bell** in header: Connects via WebSocket. Shows red dot with unacknowledged count. Dropdown shows last 10 alerts with severity icon and time.
>    - **Alerts page** at `/alerts`: Filter by type, severity, status. Table: Time, Type, Severity Badge, Device, Message, Status, Actions (Acknowledge/Resolve). Sound notification option for critical alerts (browser Notification API with user permission).
>    - **Dashboard integration**: Add an "Active Alerts" card in the Dashboard grid showing: critical count (red), high count (orange), medium (yellow), with "View All" link.
>
> **Constraints**: WebSocket must handle reconnection — frontend should auto-reconnect with exponential backoff. Alert deduplication must be handled in the backend, not the frontend. Use the existing Badge color scheme. Do not add sound without user opting in (respect browser permissions). Test the WebSocket connection independent of the full alert engine first.

---

### PROMPT 17 — Comprehensive PDF/HTML Report Generator

> **Context**: The existing `GET /api/export/pdf` endpoint generates a basic PDF using `fpdf2`. Compliance, risk, topology, attack paths, and traffic data all exist in the database. Reports are needed for audits and management.
>
> **Task**: Build a comprehensive report generation system:
> 1. Create `utils/report_generator.py` with class `ReportGenerator`:
>    - Templates: `executive_summary`, `compliance_audit`, `risk_assessment`, `change_log`, `full_security_posture`.
>    - Each template defines sections, data queries, and chart inclusions.
>    - **Executive Summary**: Overall risk score, top 5 findings, compliance overview, attack surface metrics, trend comparison (if historical data available), recommendations.
>    - **Compliance Audit** (per framework): Framework score, check-by-check results with evidence, remediation priorities, signature/date fields.
>    - **Risk Assessment**: Rule-level risk breakdown, attack paths, threat summary, device hardening grades.
>    - **Change Log**: All changes in date range from `admin_audit` and `change_requests`, with impact assessments.
>    - **Full Security Posture**: All of the above combined.
> 2. Output formats:
>    - **PDF**: Using `fpdf2` with company logo placeholder, headers/footers, page numbers, table of contents. Charts rendered as embedded images (use Matplotlib to generate chart PNGs server-side for PDF embedding).
>    - **HTML**: Standalone HTML file with inline CSS (email-safe), same content as PDF.
>    - **JSON**: Raw structured data for programmatic consumption.
> 3. API: `POST /api/reports/generate` (body: `{template, format, date_range, options}`), `GET /api/reports/list` (generated reports history), `GET /api/reports/download/{report_id}`.
> 4. Store generated reports: `data/reports/{report_id}.{ext}`. New DB table `generated_reports`: `id`, `template`, `format`, `generated_at`, `generated_by`, `file_path`, `file_size`.
> 5. Frontend: Add "Generate Report" button on the Dashboard. Opens a Dialog: Template selector (radio), Format selector (PDF/HTML/JSON), Date range picker, "Generate" button. Show progress. Generated reports appear in a `/reports` page with download links.
>
> **Constraints**: Add `matplotlib` to `requirements.txt` for server-side chart generation (used only for PDF chart images, NOT for frontend). PDF must be well-formatted with proper page breaks between sections. HTML must render correctly in Outlook/Gmail preview (inline CSS only). Test PDF generation with real DB data and verify it opens correctly before building the frontend trigger.

---

### PROMPT 18 — Zone Trust Matrix & Microsegmentation Recommendations

> **Context**: Inspired by AlgoSec's microsegmentation and FireMon's zone governance. The `network_topology` table has zone info. `firewall_rules` define zone-to-zone allowed traffic. `connections` show actual traffic flows. The `attack_path_engine.py` builds zone adjacency graphs.
>
> **Task**: Build zone trust analysis and microsegmentation:
> 1. Create `utils/segmentation_engine.py`:
>    - `def build_zone_trust_matrix(rules, connections) -> ZoneTrustMatrix`: For each zone pair, calculate: (a) rules count allowing traffic, (b) rules count denying traffic, (c) actual connections volume, (d) trust_level (high if mostly allowed + high traffic, low if mostly denied, medium otherwise), (e) risk_classification (critical if untrusted→trusted with broad access, safe if properly segmented).
>    - `def recommend_microsegmentation(rules, connections, topology) -> List[SegmentationRecommendation]`: Analyze current zone model and recommend: (a) overly broad zones that should be split (zone with >50 devices of mixed types), (b) missing deny rules between untrusted zones, (c) lateral movement reduction rules (block common lateral ports between server segments), (d) Zero Trust gaps (any allow-all between internal zones).
>    - Each recommendation: `id`, `priority`, `current_state`, `recommended_action`, `affected_zones[]`, `estimated_risk_reduction`, `implementation_steps[]`.
> 2. API endpoints: `GET /api/zones/trust-matrix`, `GET /api/zones/segmentation-recommendations`, `GET /api/zones/{zone_name}/details` (devices, rules, traffic volume).
> 3. Frontend: Add to the Analysis page as a **6th tab "Segmentation"**:
>    - **Zone Trust Matrix**: Interactive heatmap grid (zones on both axes). Cell color: green (properly segmented) → yellow (moderate access) → red (overly permissive). Click a cell → popup showing rules between those zones, traffic volume, risk assessment.
>    - **Microsegmentation Recommendations**: Card list sorted by priority. Each card: recommendation title, affected zones (badges), estimated risk reduction percentage, implementation steps (numbered list), "Create Change Request" button (pre-fills a change management request from Prompt 9).
>    - **Zone Detail Panel**: Click a zone name → slide-in panel with: device list, inbound/outbound rule summary, traffic metrics, connected zones.
>
> **Constraints**: Trust matrix must be symmetric — show both directions. The heatmap should use CSS background-color with dynamic opacity based on traffic volume (not a charting library — keep it lightweight). Recommendations must be data-driven from actual rule/connection analysis, not generic. Use existing Card/Badge/Dialog components. Test the trust matrix endpoint returns a proper 2D matrix structure before building the heatmap UI.

---

### PROMPT 19 — SIEM Integration Hub (Syslog Forwarding, Webhook, Splunk HEC)

> **Context**: The project generates alerts, detects drift, runs compliance checks, and tracks changes. Enterprise environments need this data forwarded to SIEM platforms (Splunk, Elastic, QRadar). The existing `services/alert_service.py` manages alerts.
>
> **Task**: Build a SIEM integration output hub:
> 1. Create `services/siem_integrator.py` with class `SIEMIntegrator`:
>    - **Syslog Forwarder**: Send CEF (Common Event Format) messages via UDP/TCP syslog to configured SIEM collectors. CEF fields: `CEF:0|FortressLens|FirewallReviewer|1.0|{event_id}|{event_name}|{severity}|src={src_ip} dst={dst_ip} ...`.
>    - **Webhook**: POST JSON payloads to configurable URLs (for Slack, Teams, PagerDuty, generic webhooks). Payload: `{event_type, severity, device, message, timestamp, details}`. Support custom headers for authentication.
>    - **Splunk HEC** (HTTP Event Collector): POST to `https://<splunk>:8088/services/collector` with HEC token. Format: Splunk JSON event structure with `sourcetype=fortress_lens`.
>    - **Elastic**: POST to Elasticsearch bulk API `/_bulk` with proper index naming (`fortress-lens-alerts-YYYY.MM`).
>    - Each integration: configurable, enable/disable per event type (alerts, compliance_changes, config_drift, threat_intel, change_management).
> 2. Configuration: `config/siem.yaml` with integration targets: `[{type: syslog|webhook|splunk_hec|elastic, enabled, endpoint, auth (env var ref), event_filters: [alert, drift, compliance]}]`.
> 3. Hook into existing alert creation flow: When `AlertEngine` creates an alert, call `SIEMIntegrator.forward(event)`. Same for compliance changes, drift events, change management status transitions.
> 4. API endpoints: `GET /api/integrations` (list configured targets), `POST /api/integrations/test/{target_id}` (send a test event), `GET /api/integrations/stats` (events sent, errors, last success per target).
> 5. Frontend: New page **Integrations** at `/integrations`:
>    - Configuration cards per target: name, type badge, endpoint (masked), status (connected/error), events sent count, last success time. "Test Connection" button. "Enable/Disable" toggle.
>    - Add integration form: Type selection, endpoint URL, auth config, event type checkboxes.
> 6. Add to sidebar with `Plug` icon.
>
> **Constraints**: Credentials must reference env vars in YAML, never store raw secrets. Syslog messages must follow CEF format standard precisely. Webhook calls must have a 5-second timeout and retry once on failure. Use `aiohttp` for async HTTP calls. Test each integration type with a mock endpoint before connecting to real SIEMs. Do not block the main alert flow if a SIEM target is down — fire-and-forget with error logging.

---

### PROMPT 20 — Unified Glanceable Dashboard Overhaul

> **Context**: The current Dashboard (`pages/Index.tsx`) shows: KPI cards, upload bar, protocol distribution chart, threat table, compliance cards, health grade, attack surface metrics, topology overview. It uses 10+ TanStack React Query hooks with stale-time configs. The design uses shadcn/ui Cards with the dark theme.
>
> **Task**: Overhaul the dashboard into a comprehensive, glanceable security operations center view:
> 1. **New layout structure** (keep all existing data, reorganize + add):
>    - **Row 1 — Critical KPIs**: Large metric cards in a 5-card grid: Total Devices (with health color), Active Alerts (with severity breakdown mini-bar), Overall Risk Score (circular gauge 0-100), Compliance Posture (lowest framework score), Attack Paths (critical count in red).
>    - **Row 2 — Live Activity Strip**: Horizontal scrolling strip of recent events (last 10 alerts + last 10 connections + last 5 threats) — each as a mini-card with icon, message, timestamp. Color-coded left border by severity. Auto-scrolls if user hasn't interacted.
>    - **Row 3 — Left Column (60%)**: Network topology mini-map (simplified version from Prompt 11 — show device nodes with zone coloring, no interaction needed, just visual), below it the zone trust matrix thumbnail (5×5 heatmap if ≤5 zones, summarized otherwise).
>    - **Row 3 — Right Column (40%)**: Threat timeline sparkline (last 24h, threats/hour), compliance framework scores (horizontal bar per framework), firewall health grades per device (letter + color).
>    - **Row 4**: Top 5 risky rules (compact table), top 5 attack paths (compact table), top 5 talkers (compact bar chart).
>    - **Persistent elements**: Upload button (top-right, existing), Refresh button (existing), alert bell (from Prompt 16), time range selector (new — applies to all time-sensitive widgets).
> 2. All data should come from existing API endpoints where possible. Add `GET /api/dashboard/unified` that returns a single payload with all dashboard data (reduces HTTP round-trips from 10+ to 1 single call). Backend fetches from existing functions and assembles the response.
> 3. Auto-refresh: The unified endpoint is polled every 30 seconds. Individual cards show a subtle "last updated" timestamp.
> 4. Responsive: On mobile (< 768px), collapse to single column. On tablet (768-1024px), 2-column layout. Desktop: full layout.
>
> **Constraints**: Do NOT remove any existing Dashboard data — only reorganize and augment. The unified API endpoint must call existing query functions, not duplicate SQL. Keep the current theme: dark background, rounded-xl cards, indigo primary, green/amber/red severity colors. Dashboard must fully render on first load within 2 seconds (optimize: single API call, lazy-load charts). Use Recharts for all charts (already installed). Test the `/api/dashboard/unified` endpoint returns complete data before refactoring the frontend layout.

---

## UNIVERSAL RULES FOR ALL PROMPTS

1. **Theme Consistency**: Every new page/component MUST use the existing dark theme: Tailwind dark mode, shadcn/ui components, indigo primary color, green/amber/red severity palette, rounded-xl cards, 4px spacing unit. Check `index.css` and `tailwind.config.ts` for the exact color tokens.

2. **Bug-First Policy**: After implementing each backend endpoint, test it via direct HTTP request (`curl` or browser) and verify it returns correct JSON with no 500 errors. Fix all backend bugs before starting frontend work. After frontend integration, check the browser console for errors, verify data displays correctly, and fix before moving to the next prompt.

3. **Real Data Only**: All features must query the actual database tables (`connections`, `threats`, `firewall_rules`, `network_topology`, `system_health`, `attack_paths`, `rule_risk_analysis`). No mock data, no hardcoded values, no `Math.random()`. If the database is empty, the UI should show "No data available — upload a firewall configuration to get started" with an upload button.

4. **Additive Only**: Do NOT modify existing working features, pages, or components beyond what is explicitly described. New features are additions. If an existing page needs a new tab or section, add it without altering the existing tabs/sections.

5. **Sidebar Navigation**: Every new page must be added to `AppSidebar.tsx` with an appropriate `lucide-react` icon, in the logical position specified in the prompt.

6. **API Client**: All new frontend API calls must go through `fortress-lens-main/src/lib/api.ts` using the existing `request<T>()` helper pattern. Add proper TypeScript types for request/response.

7. **Database Migrations**: Every new table or column must have an Alembic migration file in `alembic/versions/`.
