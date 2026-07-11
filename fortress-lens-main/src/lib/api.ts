/**
 * Firewall Analytics — API Service Layer
 *
 * How the base URL is resolved (in priority order):
 *  1. VITE_API_URL env var — set in .env.local, e.g. VITE_API_URL=http://127.0.0.1:8000
 *  2. Same-origin /api     — Vite dev proxy in development, nginx proxy in production
 */

function normalizeApiBase(raw: string) {
  const trimmed = raw.trim().replace(/\/+$/, "");
  return trimmed.endsWith("/api") ? trimmed : `${trimmed}/api`;
}

const BASE = (() => {
  // Injected at build time by Vite from .env / .env.local
  const envUrl = (import.meta as Record<string, unknown>).env
    ? ((import.meta as {env: Record<string,string>}).env.VITE_API_URL ?? "").trim()
    : "";
  if (envUrl) return normalizeApiBase(envUrl);
  return "/api";
})();

// ─── Auth token ─────────────────────────────────────────────────────────────

const TOKEN_KEY = "fortress_token";

export const getToken = () => localStorage.getItem(TOKEN_KEY);
export const setToken = (token: string) => localStorage.setItem(TOKEN_KEY, token);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function handleUnauthorized() {
  clearToken();
  if (window.location.pathname !== "/login") {
    window.location.assign("/login");
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const MAX_RETRIES = 2;
  const TIMEOUT_MS = 30_000;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(`${BASE}${path}`, {
        headers: { "Content-Type": "application/json", ...authHeaders(), ...options?.headers },
        signal: controller.signal,
        ...options,
      });
      if (!res.ok) {
        if (res.status === 401 && path !== "/auth/login") {
          handleUnauthorized();
        }
        const text = await res.text().catch(() => res.statusText);
        const err = new Error(`API ${path} → ${res.status}: ${text}`);
        // Retry on 5xx server errors only
        if (res.status >= 500 && attempt < MAX_RETRIES) {
          await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
          continue;
        }
        throw err;
      }
      return res.json() as Promise<T>;
    } catch (err) {
      // Retry on network/timeout errors
      if (attempt < MAX_RETRIES && (err instanceof TypeError || (err as Error).name === "AbortError")) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      throw err;
    } finally {
      clearTimeout(timeoutId);
    }
  }
  throw new Error(`API ${path} → exhausted retries`);
}

// ─── Types ──────────────────────────────────────────────────────────────────

export interface IngestionStatus {
  filename: string;
  ingestion_progress: number;
  configs_processed_count: number;
  last_ingestion_time: string;
  total_errors_count: number;
  total_warnings_count: number;
  unsupported_configs_count: number;
}

export interface TopologySummary {
  total_zones: number;
  total_firewall_rules: number;
  total_routing_entries: number;
  firewalls_count: number;
  routers_count: number;
  switches_count: number;
  vlans_count: number;
  subnets_count: number;
}

export interface AnalyticsSummary {
  total_connections: number;
  total_bytes: number;
  protocols: Array<{ protocol: string; count: number }>;
}

export interface RiskSummary {
  by_level: { critical: number; high: number; medium: number; low: number };
  by_category: {
    shadowed: number;
    unused: number;
    insecure_service: number;
    overly_permissive: number;
  };
  overall_avg_score: number;
}

export interface RiskyRule {
  id: string;
  device_name: string;
  rule_name: string;
  source: string;
  destination: string;
  protocol: string;
  action: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  recommendation: string;
  cvss_color: string;
}

export interface AttackPath {
  id: string;
  entry_point: string;
  target: string;
  hops: number;
  total_risk_score: number;
  risk_level: string;
  path_nodes?: string[];
}

export interface AttackPathSummary {
  critical_paths_count: number;
  high_risk_paths_count: number;
  average_path_risk: number;
}

export interface MalwareEntryPoint {
  node_id: string;
  device_name: string;
  zone: string;
  ip_address: string;
  is_active_threat_vector: boolean;
}

export interface VulnerablePort {
  port: number;
  service: string;
  risk_level: string;
  reason: string;
  exposed_devices: string[];
  zones: string[];
  recommendation: string;
}

export interface RemediationItem {
  rule_id: string;
  rule_name: string;
  device_name: string;
  risk_score: number;
  risk_level: string;
  category: string;
  recommendation: string;
}

export interface RuleStats {
  total: number;
  by_action: Record<string, number>;
  enabled: number;
  disabled: number;
}

export interface Connection {
  id: string;
  timestamp: string;
  src_ip?: string;
  dst_ip?: string;
  protocol?: string;
  bytes_sent?: number;
  bytes_received?: number;
  action?: string;
}

export interface Threat {
  id: string;
  timestamp: string;
  name?: string;           // backend returns 'name' (mapped from threat_name)
  threat_name?: string;    // raw field alias
  severity?: string;
  src_ip?: string;         // backend returns src_ip
  source_ip?: string;      // kept for compatibility
  dst_ip?: string;
  threat_type?: string;
  risk_score?: number;
  device_name?: string;
  action?: string;
}

export interface UploadConfigResponse {
  upload_id: string;
  vendor: string;
  filename?: string;
  message?: string | null;
  processed_rows?: number | null;
  errors_count?: number | null;
}

export interface UploadConfigBatchItem extends UploadConfigResponse {
  filename: string;
  type?: "config" | "data";
}

export interface UploadConfigBatchResponse {
  files_processed: number;
  results: UploadConfigBatchItem[];
}

export interface ValidationResult {
  valid: boolean;
  total: number;
  validRows: number;
  invalidRows: number;
  errors: string[];
}

export interface ReachabilityResult {
  reachable_devices: Array<{
    id: string;
    name: string;
    type: string;
    zone: string;
    confidence: string;
    allowed_ports: number[];
    traffic_volume_30d: number;
  }>;
  anomalies: string[];
}

// ─── Dashboard ──────────────────────────────────────────────────────────────

export const getIngestionStatus = () =>
  request<IngestionStatus>("/ingestion-status");

export const getTopologySummary = () =>
  request<TopologySummary>("/topology/summary");

export const getAnalyticsSummary = () =>
  request<AnalyticsSummary>("/analytics/summary");

// ─── Upload / Config ────────────────────────────────────────────────────────

export async function uploadConfig(
  fileOrFiles: File | File[]
): Promise<UploadConfigResponse | UploadConfigBatchResponse> {
  const form = new FormData();
  const files = Array.isArray(fileOrFiles) ? fileOrFiles : [fileOrFiles];
  if (files.length === 1) {
    form.append("file", files[0]);
  } else {
    for (const file of files) {
      form.append("files", file);
    }
  }
  const res = await fetch(`${BASE}/upload-config`, { method: "POST", body: form, headers: authHeaders() });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(text);
  }
  return res.json();
}

export async function parseConfig(uploadId: string): Promise<{ message: string }> {
  const res = await fetch(`${BASE}/parse-config/${uploadId}`, { method: "POST", headers: authHeaders() });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function uploadData(file: File): Promise<unknown> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/upload-data`, { method: "POST", body: form, headers: authHeaders() });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(text);
  }
  return res.json();
}

export async function validateUpload(file: File): Promise<ValidationResult> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/validate-upload`, { method: "POST", body: form, headers: authHeaders() });
  if (!res.ok) throw new Error(await res.text());
  const raw = await res.json();
  // Normalise to the shape the UI expects
  return {
    valid: raw.valid ?? true,
    total: raw.total ?? 0,
    validRows: raw.valid_rows ?? raw.validRows ?? 0,
    invalidRows: raw.invalid_rows ?? raw.invalidRows ?? 0,
    errors: raw.errors ?? [],
  };
}

export const downloadTemplate = (format: "csv" | "json" | "excel") =>
  window.open(`${BASE}/download-template?format=${format}`, "_blank");

// ─── Risk / Analysis ────────────────────────────────────────────────────────

export const getRiskSummary = () =>
  request<RiskSummary>("/risk-analysis/summary");

export const getRiskyRules = (minScore = 0, limit = 100) =>
  request<RiskyRule[]>(`/risky-rules?min_score=${minScore}&limit=${limit}`);

export const triggerRuleAnalysis = () =>
  request<{ message: string }>("/analyze-rules", { method: "POST" });

export const getVulnerablePorts = () =>
  request<VulnerablePort[]>("/vulnerable-ports");

export const analyzeReachability = (sourceZone: string) =>
  request<ReachabilityResult>("/analyze-reachability", {
    method: "POST",
    body: JSON.stringify({ source_zone: sourceZone }),
  });

export const getRuleStats = () => request<RuleStats>("/rule-stats");

// ─── Attack Paths ────────────────────────────────────────────────────────────

export const getAttackPaths = (minRisk = 0, limit = 50) =>
  request<AttackPath[]>(`/attack-paths?min_risk=${minRisk}&limit=${limit}`);

export const getAttackPathSummary = () =>
  request<AttackPathSummary>("/attack-paths/summary");

export const triggerAttackPathAnalysis = (
  entryPoint: string,
  target: string,
  maxHops = 10
) =>
  request<{ message: string }>("/analyze-attack-paths", {
    method: "POST",
    body: JSON.stringify({
      entry_point: entryPoint,
      target,
      max_hops: maxHops,
    }),
  });

export const getMalwareEntryPoints = () =>
  request<MalwareEntryPoint[]>("/malware-entry-points");

// ─── Threats / Live Traffic ──────────────────────────────────────────────────

export const getThreats = (limit = 100) =>
  request<Threat[]>(`/threats?limit=${limit}`);

export const getConnections = (limit = 100) =>
  request<Connection[]>(`/connections?limit=${limit}`);

// ─── Remediation ────────────────────────────────────────────────────────────

export const getRemediation = () => request<RemediationItem[]>("/remediation");

// ─── Attack Graph (full topology) ────────────────────────────────────────────

export interface GraphNode {
  id: string;
  label: string;
  device_name: string;
  device_type: string;
  ip_address: string;
  is_entry_point: boolean;
  is_target: boolean;
  ports_open: number[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  rule_name: string;
  rule_id: string;
  port: string;
  protocol: string;
  action: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  recommendation: string;
  is_deny: boolean;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: {
    total_nodes: number;
    total_edges: number;
    allow_edges: number;
    deny_edges: number;
    high_risk_edges: number;
  };
}

export const getAttackGraph = () => request<AttackGraph>("/attack-graph");

// ─── Enterprise: Executive Summary ──────────────────────────────────────────

export interface ExecutiveSummaryResponse {
  summary: string;
  risk_score: number;
  risk_trend: string;
  top_findings: Array<{
    rule_name: string;
    risk_score: number;
    risk_level: string;
    reason: string;
    device: string;
  }>;
}

export const getExecutiveSummary = () =>
  request<ExecutiveSummaryResponse>("/dashboard/executive-summary");

// ─── Enterprise: Compliance ─────────────────────────────────────────────────

export interface ComplianceScoreData {
  framework: string;
  score: number;
  status: string;
  findings: number;
  details: string[];
}

export const getComplianceScores = () =>
  request<ComplianceScoreData[]>("/compliance-scores");

// ─── Enterprise: Firewall Health ────────────────────────────────────────────

export interface FirewallHealthData {
  score: number;
  grade: string;
  breakdown: Record<string, number>;
  recommendations: string[];
}

export const getFirewallHealth = () =>
  request<FirewallHealthData>("/firewall-health");

// ─── Enterprise: Attack Surface ─────────────────────────────────────────────

export interface AttackSurfaceData {
  exposed_ports: number;
  internet_facing_rules: number;
  crown_jewel_assets: number;
  total_attack_paths: number;
  critical_paths: number;
  entry_points: number;
}

export const getAttackSurface = () =>
  request<AttackSurfaceData>("/attack-surface");

// ─── Enterprise: Firewall Topology ──────────────────────────────────────────

export interface FirewallTopologyData {
  firewalls: Array<{
    device_name: string;
    device_type: string;
    vendor: string;
    zones: string[];
    ip_address: string;
    rules_count: number;
    is_entry_point: boolean;
  }>;
  connections: Array<{
    source: string;
    target: string;
    type: string;
    shared_zones: string[];
    trust_level: string;
  }>;
  chain_detected: boolean;
  chain_details?: string;
}

export const getFirewallTopology = () =>
  request<FirewallTopologyData>("/firewall-topology");

// ─── Enterprise: Export ─────────────────────────────────────────────────────

export function downloadPDFReport() {
  window.open(`${BASE}/export/pdf`, "_blank");
}

export function downloadCSVExport() {
  window.open(`${BASE}/export/csv`, "_blank");
}

// ─── IP-to-IP Vulnerability Analysis ────────────────────────────────────────

export interface IPEntry {
  ip: string;
  label: string;
  zone?: string;
  device_type?: string;
  is_firewall: boolean;
}

export interface IPListResponse {
  ips: IPEntry[];
  total: number;
}

export interface VulnNode {
  id: string;
  ip: string;
  label: string;
  zone?: string;
  device_type?: string;
  is_firewall: boolean;
  is_source: boolean;
  is_target: boolean;
}

export interface VulnEdge {
  id: string;
  source_node: string;
  target_node: string;
  rule_name: string;
  port: string;
  protocol: string;
  risk_score: number;
  risk_level: string;
  compromise_method: string;
  compromisability: number;
  remediations: string[];
}

export interface IPVulnerabilityResponse {
  source?: IPEntry;
  target?: IPEntry;
  nodes: VulnNode[];
  edges: VulnEdge[];
  overall_risk: number;
  risk_level: string;
  path_exists: boolean;
  hop_count: number;
  summary: string;
  source_found: boolean;
  target_found: boolean;
}

export const getFirewallIPs = () =>
  request<IPListResponse>("/topology/ips");

export const analyzeIPVulnerability = (source_ip: string, target_ip: string) =>
  request<IPVulnerabilityResponse>("/ip-vulnerability", {
    method: "POST",
    body: JSON.stringify({ source_ip, target_ip }),
  });

// ─── Attack Surface Analysis (CSV + XML) ─────────────────────────────────────

export interface AttackSurfacePortDetail {
  port: string;
  service: string;
  protocol: string;
  access_type: string;
  base_risk: number;
  modifier: number;
  total: number;
  lateral_movement: boolean;
  attack_vector: string;
  explanation: string;
}

export interface AttackSurfaceGraphNode {
  id: string;
  ip: string;
  is_source: boolean;
  is_target: boolean;
}

export interface AttackSurfaceGraphEdge {
  source: string;
  target: string;
  port: string;
  protocol: string;
  risk_score: number;
  access_type: string;
}

export interface AttackSurfaceGraph {
  nodes: AttackSurfaceGraphNode[];
  edges: AttackSurfaceGraphEdge[];
}

export interface AttackSurfaceResponse {
  source_ip: string;
  destination_ip: string;
  path_exists: boolean;
  risk_score: number;
  risk_level: string;            // Low / Medium / High / Critical
  allowed_ports: AttackSurfacePortDetail[];
  explanation: string[];
  lateral_movement_risk: string; // None / Possible / High
  lateral_movement_paths: string[];
  attack_vectors: string[];
  bidirectional_exposure: boolean;
  graph: AttackSurfaceGraph;
}

export const analyzeAttackSurface = (source_ip: string, target_ip: string) =>
  request<AttackSurfaceResponse>("/attack-surface", {
    method: "POST",
    body: JSON.stringify({ source_ip, target_ip }),
  });

// ─── Syslog Collection ────────────────────────────────────────────────────────

export interface SyslogStatus {
  running: boolean;
  udp_port: number;
  tcp_port: number;
  messages_received: number;
  messages_parsed: number;
  messages_failed: number;
  connections_inserted: number;
  threats_inserted: number;
  queue_depth: number;
  messages_per_second: number;
  uptime_seconds: number;
}

export const getSyslogStatus = () =>
  request<SyslogStatus>("/syslog/status");

export const startSyslog = () =>
  request<SyslogStatus & { message: string }>("/syslog/start", { method: "POST" });

export const stopSyslog = () =>
  request<SyslogStatus & { message: string }>("/syslog/stop", { method: "POST" });

// ─── Device Collectors ────────────────────────────────────────────────────────

export interface DeviceInfo {
  name: string;
  host: string;
  vendor: string;
  auth_type: string;
  poll_interval_minutes: number;
  enabled: boolean;
  verify_ssl: boolean;
}

export interface DeviceStatus {
  name: string;
  host: string;
  vendor: string;
  enabled: boolean;
  poll_interval_minutes: number;
  last_poll: string | null;
  last_poll_success: boolean | null;
  rules_collected: number;
  health_collected: boolean;
  last_error: string | null;
}

export interface CollectorStatusResponse {
  scheduling_active: boolean;
  devices: DeviceStatus[];
}

export interface PollResult {
  device_name: string;
  vendor: string;
  success: boolean;
  rules_collected: number;
  health_collected: boolean;
  error: string | null;
  timestamp: string;
}

export interface AddDevicePayload {
  name: string;
  host: string;
  vendor: string;
  auth_type: string;
  credentials_env_var: string;
  poll_interval_minutes: number;
  enabled: boolean;
  verify_ssl: boolean;
}

export const getCollectorStatus = () =>
  request<CollectorStatusResponse>("/collectors/status");

export const pollDevice = (device_name: string) =>
  request<PollResult>("/collectors/poll-now", {
    method: "POST",
    body: JSON.stringify({ device_name }),
  });

export const toggleCollectorSchedule = () =>
  request<{ message: string; scheduling_active: boolean }>("/collectors/schedule", { method: "POST" });

export const getDeviceList = () =>
  request<{ devices: DeviceInfo[] }>("/collectors/devices");

export const addDevice = (payload: AddDevicePayload) =>
  request<{ message: string }>("/collectors/devices", {
    method: "POST",
    body: JSON.stringify(payload),
  });

// ─── Config Backups ───────────────────────────────────────────────────────────

export interface BackupEntry {
  id: string;
  timestamp: string;
  file_hash: string;
  file_size: number;
  version_number: number;
  change_detected: boolean;
  change_summary: string;
}

export interface BackupHistoryResponse {
  device_name: string;
  backups: BackupEntry[];
}

export interface BackupDiffResponse {
  backup_a: { id: string; version: number; hash: string; timestamp: string };
  backup_b: { id: string; version: number; hash: string; timestamp: string };
  diff: string;
  additions: number;
  deletions: number;
}

export interface BackupTriggerResult {
  device_name: string;
  success: boolean;
  version_number: number;
  file_hash: string;
  file_size: number;
  change_detected: boolean;
  change_summary: string;
  error: string | null;
}

export const triggerBackup = (deviceName: string) =>
  request<BackupTriggerResult>(`/backups/trigger/${deviceName}`, { method: "POST" });

export const getBackupHistory = (deviceName: string, limit = 50) =>
  request<BackupHistoryResponse>(`/backups/history/${deviceName}?limit=${limit}`);

export const getBackupDiff = (idA: string, idB: string) =>
  request<BackupDiffResponse>(`/backups/diff/${idA}/${idB}`);

export const downloadBackup = (backupId: string) =>
  window.open(`${BASE}/backups/download/${backupId}`, "_blank");

// ─── Rule Anomaly Detection ──────────────────────────────────────────────────

export interface RuleAnomaly {
  anomaly_type: string;
  rule_id: string;
  rule_name: string;
  rule_position: number;
  device_name: string;
  conflicting_rule_id: string | null;
  conflicting_rule_name: string | null;
  conflicting_rule_position: number | null;
  severity: string;
  explanation: string;
  recommendation: string;
  rule_source: string;
  rule_dest: string;
  rule_port: string;
  rule_protocol: string;
  rule_action: string;
  conflicting_source: string;
  conflicting_dest: string;
  conflicting_port: string;
  conflicting_protocol: string;
  conflicting_action: string;
}

export interface AnomalySummary {
  total: number;
  by_type: Record<string, number>;
  by_severity: Record<string, number>;
}

export interface RuleAnomalyResponse {
  anomalies: RuleAnomaly[];
  summary: AnomalySummary;
}

// ─── Rule Lifecycle Management ────────────────────────────────────────────────

export interface LifecycleDashboard {
  total_rules: number;
  certified: number;
  expired: number;
  due_soon: number;
  unowned: number;
  decommissioned: number;
  certified_pct: number;
  expired_pct: number;
  due_soon_pct: number;
  unowned_pct: number;
}

export interface LifecycleRule {
  rule_id: string;
  rule_name: string;
  device_name: string;
  action: string;
  source_ip: string;
  dest_ip: string;
  owner_name: string | null;
  owner_email: string | null;
  department: string | null;
  last_certified_date: string | null;
  certification_due_date: string | null;
  status: string;
}

export const getLifecycleDashboard = () =>
  request<LifecycleDashboard>("/lifecycle/dashboard");

export const getLifecycleRules = (status?: string, search?: string) => {
  const params = new URLSearchParams();
  if (status && status !== "all") params.set("status", status);
  if (search) params.set("search", search);
  const qs = params.toString();
  return request<{ rules: LifecycleRule[]; total: number }>(`/lifecycle/rules${qs ? `?${qs}` : ""}`);
};

export const assignRuleOwner = (ruleId: string, owner: { owner_name: string; owner_email: string; department: string }) =>
  request<{ message: string }>(`/rules/${ruleId}/assign-owner`, { method: "POST", body: JSON.stringify(owner) });

export const certifyRule = (ruleId: string, review: { reviewer_name: string; decision: string; justification: string; next_review_months: number; risk_accepted: boolean }) =>
  request<{ message: string }>(`/rules/${ruleId}/certify`, { method: "POST", body: JSON.stringify(review) });

export const bulkAssignOwner = (payload: { rule_ids: string[]; owner_name: string; owner_email: string; department: string }) =>
  request<{ message: string }>("/rules/bulk-assign", { method: "POST", body: JSON.stringify(payload) });

export const getRuleAnomalies = (deviceName?: string, anomalyType?: string) => {
  const params = new URLSearchParams();
  if (deviceName) params.set("device_name", deviceName);
  if (anomalyType) params.set("anomaly_type", anomalyType);
  const qs = params.toString();
  return request<RuleAnomalyResponse>(`/rule-anomalies${qs ? `?${qs}` : ""}`);
};

// ─── Policy Diff & Impact ─────────────────────────────────────────────────────

export interface PolicyDiffResponse {
  added_rules: Array<Record<string, unknown>>;
  removed_rules: Array<Record<string, unknown>>;
  modified_rules: Array<{ rule_name: string; rule_id: string; field_changes: Array<{ field: string; old_value: string; new_value: string }> }>;
  reordered_rules: Array<{ rule_name: string; old_position: number; new_position: number }>;
  unchanged_count: number;
  total_old: number;
  total_new: number;
}

export interface ImpactResponse {
  risk_delta: number;
  new_attack_paths_opened: number;
  attack_paths_closed: number;
  affected_zones: string[];
  connections_impacted_count: number;
  risk_verdict: string;
  added_risk_scores: Array<{ rule_name: string; risk_score: number; risk_level: string; reason: string }>;
  removed_rule_impacts: Array<{ rule_name: string; connections_affected: number; action_was: string }>;
}

export interface WhatIfResponse {
  proposed_rules: Array<Record<string, string>>;
  diff_summary: { added: number; removed: number; modified: number };
  impact: ImpactResponse;
}

export const getPolicyDiff = (device_name: string, old_backup_id: string, new_backup_id: string) =>
  request<PolicyDiffResponse>("/policy/diff", { method: "POST", body: JSON.stringify({ device_name, old_backup_id, new_backup_id }) });

export const getPolicyImpact = (device_name: string, old_backup_id: string, new_backup_id: string) =>
  request<ImpactResponse>("/policy/impact", { method: "POST", body: JSON.stringify({ device_name, old_backup_id, new_backup_id }) });

export const simulateWhatIf = (device_name: string, proposed_rules: Array<{ action: string; source_ip: string; dest_ip: string; dest_port: string; protocol: string; rule_name: string }>) =>
  request<WhatIfResponse>("/policy/what-if", { method: "POST", body: JSON.stringify({ device_name, proposed_rules }) });

// ─── Compliance Engine ────────────────────────────────────────────────────────

export interface ComplianceCheck {
  check_id: string;
  check_name: string;
  description: string;
  status: string;
  evidence: string[];
  remediation_suggestion: string;
}

export interface ComplianceFrameworkResult {
  framework: string;
  overall_score: number;
  status: string;
  total_checks: number;
  passed: number;
  failed: number;
  warnings: number;
  checks: ComplianceCheck[];
}

export const getComplianceAll = () =>
  request<{ frameworks: ComplianceFrameworkResult[] }>("/compliance/all");

export const getComplianceDetails = (framework: string) =>
  request<ComplianceFrameworkResult>(`/compliance/${framework}/details`);

// ─── Threat Intelligence ──────────────────────────────────────────────────────

export interface ThreatIntelSource {
  ip: string;
  source: string;
  risk_score: number;
  is_malicious: boolean;
  categories: string[];
  country: string;
  isp: string;
  last_reported: string;
  reports_count: number;
}

export interface ThreatIntelCheckResult {
  ip: string;
  combined_score: number;
  is_malicious: boolean;
  sources: ThreatIntelSource[];
  status: string;
}

export interface IOCSummaryEntry {
  ip: string;
  max_score: number;
  sources: string[];
  country: string;
  is_malicious: boolean;
}

export const checkThreatIntel = (ip: string) =>
  request<ThreatIntelCheckResult>(`/threat-intel/check/${ip}`);

export const bulkCheckThreatIntel = (ips: string[]) =>
  request<{ results: ThreatIntelCheckResult[]; checked_count: number }>("/threat-intel/bulk-check", { method: "POST", body: JSON.stringify({ ips }) });

export const enrichConnections = () =>
  request<{ total_ips_checked: number; malicious_count: number; results: ThreatIntelCheckResult[] }>("/threat-intel/enrich-connections");

export const getIOCSummary = () =>
  request<{ iocs: IOCSummaryEntry[]; total: number }>("/threat-intel/ioc-summary");

// ─── Change Management ────────────────────────────────────────────────────────

export interface ChangeRequestData {
  id: string;
  title: string;
  description: string;
  requester_name: string;
  status: string;
  priority: string;
  device_name: string;
  change_type: string;
  proposed_changes: Array<Record<string, string>>;
  risk_score: number;
  risk_assessment: Record<string, unknown>;
  reviewer_name: string | null;
  review_date: string | null;
  review_notes: string | null;
  deployment_date: string | null;
  request_date: string;
  comments?: Array<{ id: string; author: string; comment: string; created_at: string }>;
}

export interface ChangeDashboard {
  total: number;
  pending_review: number;
  deployed_this_week: number;
  rollbacks: number;
}

export const getChangeDashboard = () => request<ChangeDashboard>("/changes/dashboard");
export const getChanges = (status?: string) => {
  const qs = status ? `?status=${status}` : "";
  return request<{ changes: ChangeRequestData[]; total: number }>(`/changes${qs}`);
};
export const getChangeDetail = (id: string) => request<ChangeRequestData>(`/changes/${id}`);
export const createChange = (data: { title: string; description: string; requester_name: string; priority: string; device_name: string; change_type: string; proposed_changes: Array<Record<string, string>> }) =>
  request<{ id: string }>("/changes", { method: "POST", body: JSON.stringify(data) });
export const approveChange = (id: string, reviewer_name: string, notes: string) =>
  request<{ message: string }>(`/changes/${id}/approve`, { method: "POST", body: JSON.stringify({ reviewer_name, notes }) });
export const rejectChange = (id: string, reviewer_name: string, notes: string) =>
  request<{ message: string }>(`/changes/${id}/reject`, { method: "POST", body: JSON.stringify({ reviewer_name, notes }) });
export const deployChange = (id: string) =>
  request<{ message: string }>(`/changes/${id}/deploy`, { method: "POST" });
export const rollbackChange = (id: string) =>
  request<{ message: string }>(`/changes/${id}/rollback`, { method: "POST" });
export const addChangeComment = (id: string, author: string, comment: string) =>
  request<{ message: string }>(`/changes/${id}/comment`, { method: "POST", body: JSON.stringify({ author, comment }) });

// ─── Drift & Alerts ───────────────────────────────────────────────────────────

export interface AlertData {
  id: string;
  alert_type: string;
  severity: string;
  title: string;
  message: string;
  source_device: string;
  created_at: string;
  acknowledged: boolean;
}

export const getAlerts = (acknowledged?: boolean) => {
  const qs = acknowledged !== undefined ? `?acknowledged=${acknowledged}` : "";
  return request<{ alerts: AlertData[] }>(`/alerts${qs}`);
};

export const getUnreadAlertCount = () =>
  request<{ count: number }>("/alerts/unread-count");

export const acknowledgeAlert = (id: string, by: string) =>
  request<{ message: string }>(`/alerts/${id}/acknowledge`, { method: "POST", body: JSON.stringify({ acknowledged_by: by }) });

export const checkDriftNow = (deviceName: string) =>
  request<{ device_name: string; drift_detected: boolean; severity: string; drift_summary: string }>(`/drift/check-now/${deviceName}`);

export const getDriftEvents = () =>
  request<{ events: Array<{ id: string; device_name: string; detected_at: string; severity: string; drift_summary: string; acknowledged: boolean }> }>("/drift/events");

// ─── Enhanced Topology ────────────────────────────────────────────────────────

export interface TopoNode {
  id: string;
  device_name: string;
  device_type: string;
  zone: string;
  ip_address: string;
  is_entry_point: boolean;
  connected_to: string[];
  ports_open: number[];
  rules_count: number;
  health: { cpu: number; memory: number; sessions: number } | null;
  subnet?: string;
  vlan_id?: number;
  // Switch-specific
  vlans?: { id: number; name: string; state?: string }[];
  trunk_ports?: { port: string; allowed_vlans?: number[]; native_vlan?: number; neighbor?: string }[];
  access_ports?: { port: string; vlan_id?: number; status?: string }[];
  stp_mode?: string;
  stp_root_for?: number[];
  port_security?: { port: string; max_mac: number; violation_mode: string; sticky?: boolean }[];
  // Router-specific
  interfaces?: { name: string; ip?: string; subnet?: string; status?: string; speed?: string; description?: string; zone?: string; nat?: string; mode?: string }[];
  routing_protocol?: string;
  ospf_area?: string;
  bgp_asn?: number;
  bgp_neighbors?: { neighbor_ip: string; remote_asn: number; state?: string; description?: string }[];
  static_routes?: { network: string; mask: string; next_hop: string; metric?: number }[];
  nat_rules?: { type: string; inside_ip?: string; outside_ip?: string; acl?: string; interface?: string; pool?: string }[];
  // Link info
  link_type?: string;
  link_speed?: string;
  neighbor_device?: string;
}

export interface TopoEdge {
  source: string;
  target: string;
  same_zone: boolean;
  trust_level: string;
  link_type?: string;
}

export interface FullTopologyResponse {
  nodes: TopoNode[];
  edges: TopoEdge[];
  zones: string[];
  device_types: string[];
  total_nodes: number;
  total_edges: number;
}

// ─── Traffic Analysis ─────────────────────────────────────────────────────────

export const getTopTalkers = (limit = 20) =>
  request<{ senders: Array<{ ip: string; total_bytes: number; connections: number }>; receivers: Array<{ ip: string; total_bytes: number; connections: number }> }>(`/traffic/top-talkers?limit=${limit}`);

export const getZoneFlowMatrix = () =>
  request<{ flows: Array<{ zone_from: string; zone_to: string; total_bytes: number; connections: number }>; zones: string[] }>("/traffic/zone-flow-matrix");

export const getAppUsage = (limit = 20) =>
  request<{ applications: Array<{ app_name: string; category: string; total_bytes: number; user_count: number }> }>(`/traffic/application-usage?limit=${limit}`);

export const getEastWestNorthSouth = () =>
  request<{ east_west_bytes: number; north_south_bytes: number; east_west_pct: number; north_south_pct: number }>("/traffic/east-west-vs-north-south");

// ─── Auth (Prompt 13) ─────────────────────────────────────────────────────────

export const login = (username: string, password: string) =>
  request<{ access_token: string; token_type: string; role: string }>("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });

export const getAuthMe = () =>
  request<{ username: string; email: string; role: string }>("/auth/me");

// ─── Device Analysis (Switch & Router) ──────────────────────────────────────

export interface DeviceFinding {
  check: string;
  severity: string;
  status: string;
  description: string;
  recommendation: string;
  category: string;
  affected_ports?: string[];
  affected_peers?: string[];
  mappings?: string[];
}

export interface DeviceAnalysisReport {
  device_name: string;
  device_type: string;
  score: number;
  grade: string;
  total_checks: number;
  passed: number;
  failed: number;
  warnings: number;
  findings: DeviceFinding[];
  summary: Record<string, string | number>;
}

export interface AllDeviceAnalysisResponse {
  devices: DeviceAnalysisReport[];
  total: number;
  switches: number;
  routers: number;
}

export const getAllDeviceAnalysis = (deviceType?: string) =>
  request<AllDeviceAnalysisResponse>(deviceType ? `/device-analysis?device_type=${deviceType}` : "/device-analysis");

export const getDeviceAnalysis = (deviceName: string) =>
  request<DeviceAnalysisReport>(`/device-analysis/${encodeURIComponent(deviceName)}`);

export const registerUser = (data: { username: string; email: string; password: string; role: string }) =>
  request<{ message: string }>("/auth/register", { method: "POST", body: JSON.stringify(data) });

// ─── Hardening (Prompt 14) ────────────────────────────────────────────────────

export interface HardeningCheck {
  check_id: string;
  check_name: string;
  status: string;
  severity: string;
  description: string;
  remediation: string;
}

export interface HardeningResult {
  device_name: string;
  score: number;
  grade: string;
  checks: HardeningCheck[];
}

export const getHardeningSummary = () =>
  request<{ devices: Array<{ device_name: string; score: number; grade: string }> }>("/hardening/summary");

export const getHardeningDetail = (deviceName: string) =>
  request<HardeningResult>(`/hardening/${deviceName}`);

// ─── Simulation (Prompt 15) ───────────────────────────────────────────────────

export const simulateAddRule = (device_name: string, rule: Record<string, string>) =>
  request<{ risk_score_after: number; risk_delta: number; verdict: string; explanation: string }>("/simulate/add-rule", { method: "POST", body: JSON.stringify({ device_name, proposed_rule: rule }) });

// ─── Reports (Prompt 17) ──────────────────────────────────────────────────────

export const generateReport = (template: string, format: string) =>
  request<{ report_id: string; format: string }>("/reports/generate", { method: "POST", body: JSON.stringify({ template, format, options: {} }) });

export const listReports = () =>
  request<{ reports: Array<{ report_id: string; template: string; format: string; file_size: number; generated_at: string }> }>("/reports/list");

export const downloadReport = (reportId: string) =>
  window.open(`${BASE}/reports/download/${reportId}`, "_blank");

// ─── Segmentation (Prompt 18) ─────────────────────────────────────────────────

export const getZoneTrustMatrix = () =>
  request<{ zones: string[]; matrix: Array<{ zone_from: string; zone_to: string; allow_rules: number; deny_rules: number; traffic_bytes: number; trust_level: string; risk_level: string }> }>("/zones/trust-matrix");

export const getSegmentationRecommendations = () =>
  request<{ recommendations: Array<{ id: string; priority: string; current_state: string; recommended_action: string; affected_zones: string[]; estimated_risk_reduction: number }> }>("/zones/segmentation-recommendations");

// ─── SIEM Integrations (Prompt 19) ────────────────────────────────────────────

export const getIntegrations = () =>
  request<{ targets: Array<{ name: string; type: string; endpoint: string; enabled: boolean; events_sent: number }> }>("/integrations");

export const testIntegration = (targetName: string) =>
  request<{ message: string }>(`/integrations/test/${targetName}`, { method: "POST" });

// ─── Unified Dashboard (Prompt 20) ────────────────────────────────────────────

export const getUnifiedDashboard = () =>
  request<Record<string, unknown>>("/dashboard/unified");

export const getFullTopology = (deviceType?: string, zone?: string, search?: string) => {
  const params = new URLSearchParams();
  if (deviceType) params.set("device_type", deviceType);
  if (zone) params.set("zone", zone);
  if (search) params.set("search", search);
  const qs = params.toString();
  return request<FullTopologyResponse>(`/topology/full${qs ? `?${qs}` : ""}`);
};
