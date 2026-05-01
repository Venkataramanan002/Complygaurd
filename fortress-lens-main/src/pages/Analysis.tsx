import { useState, useEffect, useRef, useMemo } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { Play, ChevronDown, ChevronUp, AlertTriangle, Loader2, BarChart3, Skull, Shield, Info, Layers, Router, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SmartTooltip } from "@/components/ui/SmartTooltip";
import { CompromiseNarrativeCard } from "@/components/CompromiseNarrative";
import { analyzeReachability, getVulnerablePorts, getRiskyRules, triggerRuleAnalysis, getRuleAnomalies, simulateWhatIf, getAllDeviceAnalysis, type VulnerablePort, type RiskyRule, type RuleAnomaly, type AnomalySummary, type WhatIfResponse, type DeviceAnalysisReport, type DeviceFinding } from "@/lib/api";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";

const tabs = ["Reachability Analysis", "Vulnerable Ports", "Rule Impact", "Rule Anomalies", "Change Impact", "Switch Analysis", "Router Analysis"];

const SeverityBadge = ({ level }: { level: string }) => {
  const cls = level === "critical" ? "badge-critical" : level === "high" ? "badge-high" : level === "medium" ? "badge-medium" : "badge-low";
  return <span className={`${cls} px-2 py-0.5 rounded-full text-xs font-semibold uppercase`}>{level}</span>;
};

export default function Analysis() {
  const qc = useQueryClient();
  const [activeTab, setActiveTab]   = useState(0);
  const [selectedZone, setZone]     = useState("All");
  const [portFilter, setPortFilter] = useState("All");
  const [expandedPort, setExpandedPort]   = useState<number | null>(null);
  const [expandedRule, setExpandedRule]   = useState<string | null>(null);

  const [reachDevices, setReachDevices]   = useState<{ id: string; name: string; zone: string; confidence: string; allowed_ports: number[] }[]>([]);
  const [loadingReach, setLoadingReach]   = useState(false);
  const [analysisTriggered, setTriggered] = useState(false);

  const { data: livePorts = [], isLoading: loadingPorts } = useQuery({
    queryKey: ["vulnerablePorts"],
    queryFn: getVulnerablePorts,
    staleTime: 60_000,
  });

  const { data: liveRules = [], isLoading: loadingRules } = useQuery({
    queryKey: ["riskyRules"],
    queryFn: () => getRiskyRules(1, 100),
    staleTime: 60_000,
  });

  // Anomaly tab state
  const [anomalies, setAnomalies] = useState<RuleAnomaly[]>([]);
  const [anomalySummary, setAnomalySummary] = useState<AnomalySummary | null>(null);
  const [loadingAnomalies, setLoadingAnomalies] = useState(false);
  const [anomalyFilter, setAnomalyFilter] = useState<Set<string>>(new Set());
  const [expandedAnomaly, setExpandedAnomaly] = useState<string | null>(null);
  const [anomaliesLoaded, setAnomaliesLoaded] = useState(false);

  // What-If simulator state
  const [wifDevice, setWifDevice] = useState("paloalto-fw-01");
  const [wifRules, setWifRules] = useState([{ action: "allow", source_ip: "", dest_ip: "", dest_port: "", protocol: "tcp", rule_name: "" }]);
  const [wifResult, setWifResult] = useState<WhatIfResponse | null>(null);
  const [wifLoading, setWifLoading] = useState(false);

  // Device analysis queries (switches & routers)
  const { data: switchAnalysis, isLoading: loadingSwitchAnalysis } = useQuery({
    queryKey: ["deviceAnalysis", "switch"],
    queryFn: () => getAllDeviceAnalysis("switch"),
    staleTime: 60_000,
    enabled: activeTab === 5,
  });

  const { data: routerAnalysis, isLoading: loadingRouterAnalysis } = useQuery({
    queryKey: ["deviceAnalysis", "router"],
    queryFn: () => getAllDeviceAnalysis("router"),
    staleTime: 60_000,
    enabled: activeTab === 6,
  });

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  async function handleRunReachability() {
    setLoadingReach(true);
    try {
      const res = await analyzeReachability(selectedZone);
      if (res.reachable_devices.length > 0) setReachDevices(res.reachable_devices);
    } catch { /* stay empty */ }
    setLoadingReach(false);
  }

  async function handleLoadAnomalies() {
    setLoadingAnomalies(true);
    try {
      const res = await getRuleAnomalies();
      setAnomalies(res.anomalies);
      setAnomalySummary(res.summary);
      setAnomaliesLoaded(true);
    } catch { /* empty */ }
    setLoadingAnomalies(false);
  }

  async function handleAnalyzeRules() {
    setTriggered(true);
    await triggerRuleAnalysis().catch(() => {});
    setTimeout(() => {
      qc.invalidateQueries({ queryKey: ["riskyRules"] });
    }, 3000);
  }

  const zones = ["All", ...Array.from(new Set(reachDevices.map((d) => d.zone)))];
  const filteredDevices = selectedZone === "All" ? reachDevices : reachDevices.filter((d) => d.zone === selectedZone);
  const criticalDevices = reachDevices.filter((d) => d.confidence === "critical");

  const filteredPorts = portFilter === "All" ? livePorts : livePorts.filter((p) => p.risk_level === portFilter.toLowerCase());

  const riskColor = (score: number) => score >= 8 ? "text-destructive" : score >= 6 ? "text-warning" : score >= 4 ? "text-primary" : "text-success";

  return (
    <AppLayout title="Analysis" breadcrumb={["Firewall Analytics"]}>
      {/* ── Guidance Banner ── */}
      <div className="bg-primary/5 border border-primary/20 rounded-xl p-4 mb-6 flex items-start gap-3">
        <Info className="h-4 w-4 text-primary shrink-0 mt-0.5" />
        <div>
          <p className="text-xs font-semibold text-primary mb-1">How to Use This Page</p>
          <p className="text-xs text-muted-foreground leading-relaxed">
            <strong>Step 1:</strong> Check <em>Vulnerable Ports</em> to see which services are exposed to risk.{" "}
            <strong>Step 2:</strong> Review <em>Rule Impact</em> to identify the most dangerous firewall rules.{" "}
            <strong>Step 3:</strong> Use <em>Reachability</em> to test which devices can reach each other across zones.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-1 mb-6 bg-card rounded-xl p-1 shadow-card w-fit">
        {tabs.map((tab, i) => (
          <button key={tab} onClick={() => setActiveTab(i)}
            className={`px-4 py-2 rounded-lg text-xs font-medium transition-smooth ${activeTab === i ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}>
            {tab}
          </button>
        ))}
      </div>

      {/* Tab 1: Reachability */}
      {activeTab === 0 && (
        <div>
          <div className="flex items-center gap-3 mb-6">
            <select value={selectedZone} onChange={(e) => setZone(e.target.value)}
              className="h-8 px-3 rounded-lg bg-secondary border border-border text-xs text-foreground">
              {zones.map((z) => <option key={z}>{z}</option>)}
            </select>
            <Button size="sm" className="h-8 text-xs" onClick={handleRunReachability} disabled={loadingReach}>
              {loadingReach ? <Loader2 className="h-3 w-3 animate-spin mr-1.5" /> : <Play className="h-3 w-3 mr-1.5" />}
              Run Analysis
            </Button>
          </div>

          {criticalDevices.length > 0 && (
            <div className="bg-destructive/5 border border-destructive/20 rounded-xl p-4 mb-4 flex items-start gap-3">
              <AlertTriangle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-destructive mb-1">{criticalDevices.length} critical anomalies detected</p>
                <p className="text-xs text-muted-foreground">{criticalDevices.map((a) => a.name).join(", ")}</p>
              </div>
            </div>
          )}

          {filteredDevices.length === 0 ? (
            <div className="bg-card rounded-xl p-12 shadow-card text-center">
              <BarChart3 className="h-10 w-10 text-muted-foreground mx-auto mb-4" />
              <p className="text-sm font-medium text-foreground mb-2">No reachability data</p>
              <p className="text-xs text-muted-foreground">Click "Run Analysis" after uploading a config to map zone reachability.</p>
            </div>
          ) : (
            <div className="grid grid-cols-3 gap-4">
              {filteredDevices.map((device) => (
                <div key={device.id} className="bg-card rounded-xl p-4 shadow-card">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-sm font-semibold text-foreground">
                      <SmartTooltip term={device.name} context={`Device in zone ${device.zone}`} severity={device.confidence} page="Analysis">
                        {device.name}
                      </SmartTooltip>
                    </h4>
                    <SeverityBadge level={device.confidence} />
                  </div>
                  <p className="text-xs text-muted-foreground mb-3">
                    Zone:{" "}
                    <SmartTooltip term={device.zone} context="Network security zone" page="Analysis">
                      {device.zone}
                    </SmartTooltip>
                  </p>
                  {device.allowed_ports?.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {device.allowed_ports.slice(0, 6).map((port) => (
                        <SmartTooltip key={port} term={`Port ${port}`} context={`Open port on ${device.name}`} severity={device.confidence} page="Analysis">
                          <span className="text-xs bg-secondary px-1.5 py-0.5 rounded font-mono cursor-help">{port}</span>
                        </SmartTooltip>
                      ))}
                      {device.allowed_ports.length > 6 && <span className="text-xs text-muted-foreground">+{device.allowed_ports.length - 6}</span>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Vulnerable Ports */}
      {activeTab === 1 && (
        <div>
          {loadingPorts ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground py-8"><Loader2 className="h-4 w-4 animate-spin" />Loading…</div>
          ) : livePorts.length === 0 ? (
            <div className="bg-card rounded-xl p-12 shadow-card text-center">
              <p className="text-sm font-medium text-foreground mb-2">No vulnerable ports found</p>
              <p className="text-xs text-muted-foreground">Upload a config and run analysis to identify exposed ports.</p>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-3 mb-6">
                <select value={portFilter} onChange={(e) => setPortFilter(e.target.value)}
                  className="h-8 px-3 rounded-lg bg-secondary border border-border text-xs text-foreground">
                  {["All","Critical","High","Medium","Low"].map((f) => <option key={f}>{f}</option>)}
                </select>
                <span className="text-xs text-muted-foreground">{filteredPorts.length} exposed port{filteredPorts.length !== 1 ? "s" : ""} found</span>
              </div>
              <div className="space-y-2">
                {filteredPorts.map((port) => (
                  <div key={port.port} className="bg-card rounded-xl shadow-card overflow-hidden">
                    <button className="w-full flex items-center justify-between p-4 text-left" onClick={() => setExpandedPort(expandedPort === port.port ? null : port.port)}>
                      <div className="flex items-center gap-3">
                        <SmartTooltip term={`Port ${port.port}`} context={`${port.service} — ${port.reason}`} severity={port.risk_level} page="Analysis">
                          <span className="font-mono text-sm text-primary font-bold cursor-help">{port.port}</span>
                        </SmartTooltip>
                        <SmartTooltip term={port.service} context={`Service on port ${port.port}`} severity={port.risk_level} page="Analysis">
                          <span className="text-xs font-medium text-foreground cursor-help">{port.service}</span>
                        </SmartTooltip>
                        <SeverityBadge level={port.risk_level} />
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-muted-foreground">{port.exposed_devices?.length ?? 0} device{(port.exposed_devices?.length ?? 0) !== 1 ? "s" : ""}</span>
                        {expandedPort === port.port ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </div>
                    </button>
                    {expandedPort === port.port && (
                      <div className="px-4 pb-4 pt-0 border-t border-border space-y-2">
                        <p className="text-xs text-muted-foreground">
                          <span className="text-foreground font-medium">Reason:</span>{" "}
                          <SmartTooltip term={port.reason} context={`Port ${port.port} exposure reason`} severity={port.risk_level} page="Analysis">
                            {port.reason}
                          </SmartTooltip>
                        </p>
                        <p className="text-xs text-muted-foreground">
                          <span className="text-foreground font-medium">Recommendation:</span>{" "}
                          <SmartTooltip term={port.recommendation} context={`Fix for port ${port.port}`} page="Remediation">
                            {port.recommendation}
                          </SmartTooltip>
                        </p>
                        {port.exposed_devices?.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {port.exposed_devices.map((d) => <span key={d} className="text-xs bg-secondary px-1.5 py-0.5 rounded font-mono">{d}</span>)}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* Tab 3: Rule Impact */}
      {activeTab === 2 && (
        <div>
          <div className="flex items-center gap-3 mb-6">
            <Button size="sm" variant="outline" className="h-8 text-xs" onClick={handleAnalyzeRules} disabled={analysisTriggered}>
              {analysisTriggered ? <><Loader2 className="h-3 w-3 animate-spin mr-1.5" />Analysing…</> : <><Play className="h-3 w-3 mr-1.5" />Re-analyse Rules</>}
            </Button>
            <span className="text-xs text-muted-foreground">{liveRules.length} rule{liveRules.length !== 1 ? "s" : ""}</span>
          </div>
          {loadingRules ? (
            <div className="flex items-center gap-2 text-xs text-muted-foreground py-8"><Loader2 className="h-4 w-4 animate-spin" />Loading rule analysis…</div>
          ) : liveRules.length === 0 ? (
            <div className="bg-card rounded-xl p-12 shadow-card text-center">
              <p className="text-sm font-medium text-foreground mb-2">No rules analysed yet</p>
              <p className="text-xs text-muted-foreground">Upload a config — risk analysis runs automatically. Click Re-analyse to refresh.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {liveRules.map((rule) => (
                <div key={rule.id} className="bg-card rounded-xl shadow-card overflow-hidden">
                  <button className="w-full flex items-center justify-between p-4 text-left" onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}>
                    <div className="flex items-center gap-3">
                      <SmartTooltip term={`Risk Score ${Number(rule.risk_score).toFixed(1)}`} context={`Risk score for rule ${rule.rule_name} — ${Number(rule.risk_score) >= 8 ? "Very dangerous" : Number(rule.risk_score) >= 6 ? "Significant risk" : Number(rule.risk_score) >= 4 ? "Moderate risk" : "Low risk"}`} severity={rule.risk_level} page="Analysis">
                        <span className={`text-sm font-bold tabular-nums cursor-help ${riskColor(Number(rule.risk_score))}`}>
                          {Number(rule.risk_score).toFixed(1)}
                        </span>
                      </SmartTooltip>
                      <SmartTooltip term={rule.rule_name} context={`Firewall rule on ${rule.device_name}`} severity={rule.risk_level} page="Analysis">
                        <span className="text-xs font-medium text-foreground cursor-help">{rule.rule_name}</span>
                      </SmartTooltip>
                      <SeverityBadge level={rule.risk_level} />
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-muted-foreground">{rule.device_name}</span>
                      {expandedRule === rule.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </div>
                  </button>
                  {expandedRule === rule.id && (
                    <div className="px-4 pb-4 pt-0 border-t border-border space-y-2">
                      <p className="text-xs text-muted-foreground">
                        <span className="text-foreground font-medium">Reason:</span>{" "}
                        <SmartTooltip term={rule.reason} context={`Reason for rule ${rule.rule_name}`} severity={rule.risk_level} page="Analysis">
                          {rule.reason}
                        </SmartTooltip>
                      </p>
                      <p className="text-xs text-muted-foreground">
                        <span className="text-foreground font-medium">Recommendation:</span>{" "}
                        <SmartTooltip term={rule.recommendation} context={`Fix for rule ${rule.rule_name}`} page="Remediation">
                          {rule.recommendation}
                        </SmartTooltip>
                      </p>
                      <p className="text-xs text-muted-foreground">
                        <span className="text-foreground font-medium">Source:</span>{" "}
                        <SmartTooltip term={rule.source} context={`Source address/port for rule ${rule.rule_name}`} page="Analysis">
                          {rule.source}
                        </SmartTooltip>
                        {" → "}
                        <SmartTooltip term={rule.destination} context={`Destination address/port for rule ${rule.rule_name}`} page="Analysis">
                          <span className="font-medium text-foreground cursor-help">{rule.destination}</span>
                        </SmartTooltip>
                      </p>
                      <p className="text-xs text-muted-foreground">
                        <span className="text-foreground font-medium">Protocol:</span>{" "}
                        <SmartTooltip term={rule.protocol} context={`Protocol for rule ${rule.rule_name}`} page="Analysis">
                          {rule.protocol}
                        </SmartTooltip>
                      </p>
                      {/* Enhanced Compromise Narrative — only for high/critical rules */}
                      <CompromiseNarrativeCard findingKey={`rule-${rule.id}`} riskLevel={rule.risk_level} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {/* Tab 5: Change Impact / What-If */}
      {activeTab === 4 && (
        <div>
          <div className="bg-card rounded-xl p-5 shadow-card mb-6">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold text-foreground">What-If Rule Simulator</h3>
              <span className="text-xs bg-primary/10 text-primary px-2 py-0.5 rounded-full font-medium">Simulate before deploying</span>
            </div>
            <div className="mb-3">
              <label className="text-xs text-muted-foreground mb-1 block">Device Name</label>
              <input value={wifDevice} onChange={e => setWifDevice(e.target.value)} className="h-8 px-3 rounded-lg bg-secondary border border-border text-xs text-foreground w-64" />
            </div>
            <p className="text-xs text-muted-foreground mb-2">Define proposed rules to see their security impact:</p>
            {wifRules.map((r, i) => (
              <div key={i} className="grid grid-cols-6 gap-2 mb-2">
                <input placeholder="Rule name" value={r.rule_name} onChange={e => { const nr = [...wifRules]; nr[i] = { ...nr[i], rule_name: e.target.value }; setWifRules(nr); }} className="h-7 px-2 rounded bg-secondary border border-border text-xs text-foreground" />
                <input placeholder="Source IP" value={r.source_ip} onChange={e => { const nr = [...wifRules]; nr[i] = { ...nr[i], source_ip: e.target.value }; setWifRules(nr); }} className="h-7 px-2 rounded bg-secondary border border-border text-xs text-foreground font-mono" />
                <input placeholder="Dest IP" value={r.dest_ip} onChange={e => { const nr = [...wifRules]; nr[i] = { ...nr[i], dest_ip: e.target.value }; setWifRules(nr); }} className="h-7 px-2 rounded bg-secondary border border-border text-xs text-foreground font-mono" />
                <input placeholder="Port" value={r.dest_port} onChange={e => { const nr = [...wifRules]; nr[i] = { ...nr[i], dest_port: e.target.value }; setWifRules(nr); }} className="h-7 px-2 rounded bg-secondary border border-border text-xs text-foreground font-mono" />
                <select value={r.protocol} onChange={e => { const nr = [...wifRules]; nr[i] = { ...nr[i], protocol: e.target.value }; setWifRules(nr); }} className="h-7 px-2 rounded bg-secondary border border-border text-xs text-foreground">
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="any">Any</option>
                </select>
                <select value={r.action} onChange={e => { const nr = [...wifRules]; nr[i] = { ...nr[i], action: e.target.value }; setWifRules(nr); }} className="h-7 px-2 rounded bg-secondary border border-border text-xs text-foreground">
                  <option value="allow">Allow</option>
                  <option value="deny">Deny</option>
                </select>
              </div>
            ))}
            <div className="flex gap-2 mt-3">
              <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setWifRules([...wifRules, { action: "allow", source_ip: "", dest_ip: "", dest_port: "", protocol: "tcp", rule_name: "" }])}>+ Add Rule</Button>
              <Button size="sm" className="h-7 text-xs" disabled={wifLoading || !wifDevice} onClick={async () => {
                setWifLoading(true);
                try {
                  const res = await simulateWhatIf(wifDevice, wifRules.filter(r => r.source_ip || r.dest_ip));
                  setWifResult(res);
                } catch { /* empty */ }
                setWifLoading(false);
              }}>
                {wifLoading ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <Play className="h-3 w-3 mr-1" />}
                Simulate Impact
              </Button>
            </div>
          </div>

          {/* Impact Results */}
          {wifResult && (
            <>
              <div className="grid grid-cols-4 gap-4 mb-6">
                <div className={`bg-card rounded-xl p-4 shadow-card border ${
                  wifResult.impact.risk_verdict === "dangerous" ? "border-red-800/30" :
                  wifResult.impact.risk_verdict === "caution" ? "border-yellow-700/30" : "border-emerald-700/30"
                }`}>
                  <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-1">Risk Verdict</p>
                  <p className={`text-xl font-bold capitalize ${
                    wifResult.impact.risk_verdict === "dangerous" ? "text-destructive" :
                    wifResult.impact.risk_verdict === "caution" ? "text-warning" : "text-success"
                  }`}>{wifResult.impact.risk_verdict}</p>
                </div>
                <div className="bg-card rounded-xl p-4 shadow-card">
                  <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-1">Risk Delta</p>
                  <p className={`text-xl font-bold tabular-nums ${wifResult.impact.risk_delta > 0 ? "text-destructive" : wifResult.impact.risk_delta < 0 ? "text-success" : "text-foreground"}`}>
                    {wifResult.impact.risk_delta > 0 ? "+" : ""}{wifResult.impact.risk_delta}
                  </p>
                </div>
                <div className="bg-card rounded-xl p-4 shadow-card">
                  <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-1">Paths Opened</p>
                  <p className="text-xl font-bold tabular-nums text-warning">{wifResult.impact.new_attack_paths_opened}</p>
                </div>
                <div className="bg-card rounded-xl p-4 shadow-card">
                  <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-1">Paths Closed</p>
                  <p className="text-xl font-bold tabular-nums text-success">{wifResult.impact.attack_paths_closed}</p>
                </div>
              </div>

              {wifResult.impact.added_risk_scores.length > 0 && (
                <div className="bg-card rounded-xl p-4 shadow-card mb-6">
                  <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-3">Added Rule Risk Scores</p>
                  {wifResult.impact.added_risk_scores.map((s, i) => (
                    <div key={i} className="flex items-center gap-3 p-2 rounded-lg hover:bg-primary/5 mb-1">
                      <span className={`text-sm font-bold tabular-nums ${s.risk_score >= 6 ? "text-destructive" : s.risk_score >= 3 ? "text-warning" : "text-success"}`}>{s.risk_score.toFixed(1)}</span>
                      <span className="text-xs font-medium text-foreground">{s.rule_name}</span>
                      <SeverityBadge level={s.risk_level} />
                      <span className="text-xs text-muted-foreground flex-1 truncate">{s.reason}</span>
                    </div>
                  ))}
                </div>
              )}

              {wifResult.impact.affected_zones.length > 0 && (
                <div className="bg-card rounded-xl p-4 shadow-card">
                  <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-2">Affected Zones</p>
                  <div className="flex flex-wrap gap-2">
                    {wifResult.impact.affected_zones.map(z => (
                      <span key={z} className="text-xs bg-primary/10 text-primary px-2 py-0.5 rounded-full font-medium">{z}</span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Tab 4: Rule Anomalies */}
      {activeTab === 3 && (
        <div>
          {!anomaliesLoaded ? (
            <div className="bg-card rounded-xl p-12 shadow-card text-center">
              <AlertTriangle className="h-10 w-10 text-warning mx-auto mb-3" />
              <p className="text-sm font-semibold text-foreground mb-2">Rule Anomaly Detection</p>
              <p className="text-xs text-muted-foreground mb-4">Analyze rules for shadows, redundancies, overlaps, duplicates, and overly permissive entries.</p>
              <Button size="sm" onClick={handleLoadAnomalies} disabled={loadingAnomalies}>
                {loadingAnomalies ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" /> : <Play className="h-3.5 w-3.5 mr-1.5" />}
                Run Anomaly Detection
              </Button>
            </div>
          ) : (
            <>
              {/* Summary bar with donut */}
              <div className="grid grid-cols-3 gap-4 mb-6">
                <div className="bg-card rounded-xl p-4 shadow-card col-span-1">
                  <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-2">Anomalies by Type</p>
                  {anomalySummary && Object.keys(anomalySummary.by_type).length > 0 ? (
                    <ResponsiveContainer width="100%" height={160}>
                      <PieChart>
                        <Pie data={Object.entries(anomalySummary.by_type).map(([k, v]) => ({ name: k, value: v }))} cx="50%" cy="50%" innerRadius={35} outerRadius={60} dataKey="value" paddingAngle={2}>
                          {Object.keys(anomalySummary.by_type).map((_, i) => (
                            <Cell key={i} fill={["hsl(0,70%,50%)", "hsl(30,90%,50%)", "hsl(45,90%,50%)", "hsl(142,70%,45%)", "hsl(262,83%,58%)"][i % 5]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 11 }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <p className="text-xs text-muted-foreground text-center mt-8">No anomalies found</p>
                  )}
                </div>
                <div className="bg-card rounded-xl p-4 shadow-card col-span-2">
                  <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-3">Summary</p>
                  <div className="grid grid-cols-3 gap-3 mb-3">
                    <div className="text-center p-3 bg-black/20 rounded-xl">
                      <p className="text-2xl font-bold tabular-nums text-foreground">{anomalySummary?.total ?? 0}</p>
                      <p className="text-xs text-muted-foreground">Total Anomalies</p>
                    </div>
                    <div className="text-center p-3 bg-black/20 rounded-xl">
                      <p className="text-2xl font-bold tabular-nums text-destructive">{(anomalySummary?.by_severity?.critical ?? 0) + (anomalySummary?.by_severity?.high ?? 0)}</p>
                      <p className="text-xs text-muted-foreground">Critical + High</p>
                    </div>
                    <div className="text-center p-3 bg-black/20 rounded-xl">
                      <p className="text-2xl font-bold tabular-nums text-warning">{anomalySummary?.by_severity?.medium ?? 0}</p>
                      <p className="text-xs text-muted-foreground">Medium</p>
                    </div>
                  </div>
                  {/* Type filter badges */}
                  <div className="flex flex-wrap gap-2">
                    {["shadow", "redundant", "overlap", "duplicate", "overly_permissive"].map(t => {
                      const count = anomalySummary?.by_type?.[t] ?? 0;
                      const active = anomalyFilter.size === 0 || anomalyFilter.has(t);
                      return (
                        <button key={t} onClick={() => {
                          setAnomalyFilter(prev => {
                            const next = new Set(prev);
                            if (next.has(t)) next.delete(t); else next.add(t);
                            return next;
                          });
                        }} className={`text-xs font-medium px-2.5 py-1 rounded-full transition-smooth ${active ? "bg-primary/20 text-primary border border-primary/30" : "bg-secondary text-muted-foreground border border-transparent"}`}>
                          {t.replace("_", " ")} ({count})
                        </button>
                      );
                    })}
                    {anomalyFilter.size > 0 && (
                      <button onClick={() => setAnomalyFilter(new Set())} className="text-xs text-muted-foreground underline">Clear filters</button>
                    )}
                  </div>
                  <Button size="sm" className="mt-3 h-7 text-xs" variant="outline" onClick={handleLoadAnomalies} disabled={loadingAnomalies}>
                    {loadingAnomalies ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <BarChart3 className="h-3 w-3 mr-1" />}
                    Re-run
                  </Button>
                </div>
              </div>

              {/* Anomalies table */}
              <div className="bg-card rounded-xl shadow-card overflow-hidden">
                <div className="space-y-0">
                  {anomalies
                    .filter(a => anomalyFilter.size === 0 || anomalyFilter.has(a.anomaly_type))
                    .map(a => (
                    <div key={`${a.rule_id}-${a.anomaly_type}-${a.conflicting_rule_id}`} className="border-b border-border/50">
                      <button onClick={() => setExpandedAnomaly(expandedAnomaly === a.rule_id + a.anomaly_type ? null : a.rule_id + a.anomaly_type)} className="w-full flex items-center gap-3 p-4 text-left hover:bg-primary/5 transition-smooth">
                        <span className="text-xs font-medium text-foreground w-36 truncate">{a.rule_name}</span>
                        <span className="text-xs text-muted-foreground tabular-nums w-12">#{a.rule_position}</span>
                        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                          a.anomaly_type === "shadow" ? "bg-orange-900/30 text-orange-400" :
                          a.anomaly_type === "redundant" ? "bg-yellow-900/30 text-yellow-400" :
                          a.anomaly_type === "overlap" ? "bg-blue-900/30 text-blue-400" :
                          a.anomaly_type === "duplicate" ? "bg-green-900/30 text-green-400" :
                          "bg-red-900/30 text-red-400"
                        }`}>
                          {a.anomaly_type.replace("_", " ")}
                        </span>
                        {a.conflicting_rule_name && (
                          <span className="text-xs text-muted-foreground truncate flex-1">vs {a.conflicting_rule_name} (#{a.conflicting_rule_position})</span>
                        )}
                        <SeverityBadge level={a.severity} />
                        {expandedAnomaly === a.rule_id + a.anomaly_type ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
                      </button>
                      {expandedAnomaly === a.rule_id + a.anomaly_type && (
                        <div className="px-4 pb-4 space-y-3">
                          <p className="text-xs text-muted-foreground leading-relaxed">{a.explanation}</p>
                          <p className="text-xs text-primary"><strong>Recommendation:</strong> {a.recommendation}</p>
                          {/* Side-by-side rule comparison */}
                          {a.conflicting_rule_id && (
                            <div className="grid grid-cols-2 gap-3 mt-2">
                              <div className="bg-black/20 rounded-lg p-3">
                                <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-2">This Rule: {a.rule_name}</p>
                                <div className="space-y-1 text-xs">
                                  <div className="flex justify-between"><span className="text-muted-foreground">Source:</span><span className={`font-mono ${a.rule_source === a.conflicting_source ? "text-foreground" : "text-warning"}`}>{a.rule_source}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Dest:</span><span className={`font-mono ${a.rule_dest === a.conflicting_dest ? "text-foreground" : "text-warning"}`}>{a.rule_dest}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Port:</span><span className={`font-mono ${a.rule_port === a.conflicting_port ? "text-foreground" : "text-warning"}`}>{a.rule_port}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Protocol:</span><span className="font-mono">{a.rule_protocol}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Action:</span><span className={`font-mono font-bold ${a.rule_action === a.conflicting_action ? "text-foreground" : "text-destructive"}`}>{a.rule_action}</span></div>
                                </div>
                              </div>
                              <div className="bg-black/20 rounded-lg p-3">
                                <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-2">Conflicting: {a.conflicting_rule_name}</p>
                                <div className="space-y-1 text-xs">
                                  <div className="flex justify-between"><span className="text-muted-foreground">Source:</span><span className={`font-mono ${a.rule_source === a.conflicting_source ? "text-foreground" : "text-warning"}`}>{a.conflicting_source}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Dest:</span><span className={`font-mono ${a.rule_dest === a.conflicting_dest ? "text-foreground" : "text-warning"}`}>{a.conflicting_dest}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Port:</span><span className={`font-mono ${a.rule_port === a.conflicting_port ? "text-foreground" : "text-warning"}`}>{a.conflicting_port}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Protocol:</span><span className="font-mono">{a.conflicting_protocol}</span></div>
                                  <div className="flex justify-between"><span className="text-muted-foreground">Action:</span><span className={`font-mono font-bold ${a.rule_action === a.conflicting_action ? "text-foreground" : "text-destructive"}`}>{a.conflicting_action}</span></div>
                                </div>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                  {anomalies.filter(a => anomalyFilter.size === 0 || anomalyFilter.has(a.anomaly_type)).length === 0 && (
                    <div className="p-12 text-center text-xs text-muted-foreground">
                      {anomalies.length === 0 ? "No anomalies detected — your ruleset looks clean!" : "No anomalies match the selected filters."}
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      )}
      {/* Tab 6: Switch Analysis */}
      {activeTab === 5 && (
        <DeviceAnalysisPanel
          title="Switch Security Analysis"
          icon={<Layers className="h-4 w-4 text-info" />}
          loading={loadingSwitchAnalysis}
          devices={switchAnalysis?.devices || []}
          emptyMsg="No switches found. Upload a switch config (switch*.conf) to analyze."
        />
      )}

      {/* Tab 7: Router Analysis */}
      {activeTab === 6 && (
        <DeviceAnalysisPanel
          title="Router Security Analysis"
          icon={<Router className="h-4 w-4 text-warning" />}
          loading={loadingRouterAnalysis}
          devices={routerAnalysis?.devices || []}
          emptyMsg="No routers found. Upload a router config (router*.conf) to analyze."
        />
      )}
    </AppLayout>
  );
}

/* ── Shared Device Analysis Panel ──────────────────────────────────────────── */

function DeviceAnalysisPanel({ title, icon, loading, devices, emptyMsg }: {
  title: string;
  icon: React.ReactNode;
  loading: boolean;
  devices: DeviceAnalysisReport[];
  emptyMsg: string;
}) {
  const [expandedDevice, setExpandedDevice] = useState<string | null>(null);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  if (loading) {
    return <div className="flex items-center justify-center py-16 text-muted-foreground text-sm"><Loader2 className="h-4 w-4 animate-spin mr-2" />Analyzing devices...</div>;
  }

  if (!devices.length) {
    return <div className="bg-card rounded-xl p-12 text-center text-muted-foreground text-sm">{emptyMsg}</div>;
  }

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {devices.map(d => (
          <button key={d.device_name} onClick={() => setExpandedDevice(expandedDevice === d.device_name ? null : d.device_name)}
            className={`bg-card rounded-xl p-4 shadow-card text-left transition-all hover:ring-1 hover:ring-primary/30 ${expandedDevice === d.device_name ? "ring-1 ring-primary" : ""}`}>
            <div className="flex items-center gap-2 mb-2">
              {icon}
              <span className="text-sm font-semibold text-foreground truncate">{d.device_name}</span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-3xl font-bold tabular-nums ${d.grade === "A" ? "text-success" : d.grade === "B" ? "text-info" : d.grade === "C" ? "text-warning" : "text-destructive"}`}>{d.grade}</span>
              <span className="text-sm text-muted-foreground">{d.score}/100</span>
            </div>
            <div className="mt-2 flex gap-3 text-xs">
              <span className="text-success">{d.passed} pass</span>
              <span className="text-destructive">{d.failed} fail</span>
              <span className="text-warning">{d.warnings} warn</span>
            </div>
          </button>
        ))}
      </div>

      {/* Expanded device detail */}
      {expandedDevice && (() => {
        const device = devices.find(d => d.device_name === expandedDevice);
        if (!device) return null;

        const categories = [...new Set(device.findings.map(f => f.category))];

        return (
          <div className="bg-card rounded-xl p-5 shadow-card">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                {icon}
                <div>
                  <h3 className="text-base font-semibold text-foreground">{device.device_name}</h3>
                  <p className="text-xs text-muted-foreground capitalize">{device.device_type} — {device.total_checks} security checks</p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className={`text-4xl font-bold ${device.grade === "A" ? "text-success" : device.grade === "B" ? "text-info" : device.grade === "C" ? "text-warning" : "text-destructive"}`}>
                  {device.grade}
                </div>
                <div className="text-right">
                  <p className="text-xl font-bold text-foreground tabular-nums">{device.score}<span className="text-sm text-muted-foreground">/100</span></p>
                  <p className="text-xs text-muted-foreground">Security Score</p>
                </div>
              </div>
            </div>

            {/* Summary stats row */}
            {device.summary && (
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2 mb-4">
                {Object.entries(device.summary).map(([key, val]) => (
                  <div key={key} className="bg-secondary/50 rounded-lg px-3 py-2">
                    <p className="text-xs text-muted-foreground capitalize">{key.replace(/_/g, " ")}</p>
                    <p className="text-sm font-semibold text-foreground">{String(val)}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Findings by category */}
            {categories.map(cat => (
              <div key={cat} className="mb-4">
                <h4 className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-2 capitalize">{cat.replace(/_/g, " ")}</h4>
                <div className="space-y-2">
                  {device.findings.filter(f => f.category === cat).map((finding, i) => {
                    const fKey = `${device.device_name}-${cat}-${i}`;
                    const isExpanded = expandedFinding === fKey;
                    return (
                      <button key={fKey} onClick={() => setExpandedFinding(isExpanded ? null : fKey)}
                        className="w-full text-left bg-background rounded-lg p-3 hover:bg-secondary/30 transition-colors">
                        <div className="flex items-center gap-2">
                          {finding.status === "pass" ? <ShieldCheck className="h-4 w-4 text-success shrink-0" /> :
                           finding.status === "fail" ? <ShieldX className="h-4 w-4 text-destructive shrink-0" /> :
                           <ShieldAlert className="h-4 w-4 text-warning shrink-0" />}
                          <span className="text-sm font-medium text-foreground flex-1">{finding.check}</span>
                          <SeverityBadge level={finding.severity} />
                          {isExpanded ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
                        </div>
                        {isExpanded && (
                          <div className="mt-3 pl-6 space-y-2 text-xs">
                            <p className="text-muted-foreground">{finding.description}</p>
                            <div className="bg-primary/5 border border-primary/20 rounded-lg p-2.5">
                              <p className="text-primary font-medium">Recommendation</p>
                              <p className="text-foreground mt-1">{finding.recommendation}</p>
                            </div>
                            {finding.affected_ports && finding.affected_ports.length > 0 && (
                              <p className="text-muted-foreground">Affected ports: <span className="font-mono text-foreground">{finding.affected_ports.join(", ")}</span></p>
                            )}
                            {finding.affected_peers && finding.affected_peers.length > 0 && (
                              <p className="text-muted-foreground">Affected peers: <span className="font-mono text-foreground">{finding.affected_peers.join(", ")}</span></p>
                            )}
                            {finding.mappings && finding.mappings.length > 0 && (
                              <div>
                                <p className="text-muted-foreground mb-1">NAT Mappings:</p>
                                {finding.mappings.map((m, j) => <p key={j} className="font-mono text-foreground ml-2">{m}</p>)}
                              </div>
                            )}
                          </div>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        );
      })()}
    </div>
  );
}
