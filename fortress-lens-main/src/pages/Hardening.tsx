import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { Shield, ChevronDown, ChevronUp, CheckCircle, XCircle, AlertTriangle } from "lucide-react";
import { getHardeningSummary, getHardeningDetail, type HardeningResult } from "@/lib/api";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const gradeColor = (g: string) => g === "A" ? "text-success" : g === "B" ? "text-primary" : g === "C" ? "text-warning" : "text-destructive";
const gradeBg = (g: string) => g === "A" ? "bg-success/20" : g === "B" ? "bg-primary/20" : g === "C" ? "bg-warning/20" : "bg-destructive/20";
const scoreBarColor = (s: number) => s >= 90 ? "hsl(142,70%,45%)" : s >= 75 ? "hsl(217,91%,60%)" : s >= 60 ? "hsl(38,92%,50%)" : "hsl(0,70%,50%)";

export default function Hardening() {
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const summaryQ = useQuery({ queryKey: ["hardeningSummary"], queryFn: getHardeningSummary, staleTime: 30_000 });
  const detailQ = useQuery({ queryKey: ["hardeningDetail", selectedDevice], queryFn: () => getHardeningDetail(selectedDevice!), enabled: !!selectedDevice, staleTime: 30_000 });

  const devices = summaryQ.data?.devices ?? [];
  const detail = detailQ.data;

  return (
    <AppLayout title="Device Hardening" breadcrumb={["Device Hardening"]}>
      {/* Score Chart */}
      <div className="bg-card rounded-xl p-5 shadow-card mb-6">
        <h3 className="text-sm font-semibold text-foreground mb-4">Device Hardening Scores</h3>
        {devices.length > 0 ? (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={devices}>
              <XAxis dataKey="device_name" stroke="hsl(240,5%,40%)" fontSize={10} />
              <YAxis domain={[0, 100]} stroke="hsl(240,5%,40%)" fontSize={10} />
              <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 11 }} />
              <Bar dataKey="score" radius={[4, 4, 0, 0]} onClick={(d) => setSelectedDevice((d as { device_name: string }).device_name)}>
                {devices.map((d, i) => <Cell key={i} fill={scoreBarColor(d.score)} cursor="pointer" />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : <div className="h-48 flex items-center justify-center text-xs text-muted-foreground">{summaryQ.isLoading ? "Loading..." : "No device data. Upload a config first."}</div>}
      </div>

      {/* Device Grade Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {devices.map(d => (
          <button key={d.device_name} onClick={() => setSelectedDevice(d.device_name)}
            className={`bg-card rounded-xl p-4 shadow-card text-left border transition-all ${selectedDevice === d.device_name ? "border-primary/40" : "border-border hover:border-primary/20"}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-foreground truncate">{d.device_name}</span>
              <span className={`text-lg font-bold ${gradeColor(d.grade)} ${gradeBg(d.grade)} px-2 rounded`}>{d.grade}</span>
            </div>
            <p className={`text-2xl font-bold tabular-nums ${gradeColor(d.grade)}`}>{d.score.toFixed(0)}%</p>
          </button>
        ))}
      </div>

      {/* Detail Checks */}
      {detail && (
        <div className="bg-card rounded-xl shadow-card overflow-hidden">
          <div className="p-4 border-b border-border flex items-center gap-3">
            <Shield className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">{detail.device_name} — Hardening Checks</h3>
            <span className={`text-xs font-bold ${gradeColor(detail.grade)}`}>Grade: {detail.grade} ({detail.score.toFixed(0)}%)</span>
          </div>
          {detail.checks.map(c => (
            <div key={c.check_id} className="border-b border-border/50">
              <button onClick={() => setExpanded(expanded === c.check_id ? null : c.check_id)} className="w-full flex items-center gap-3 p-4 text-left hover:bg-primary/5 transition-smooth">
                {c.status === "pass" ? <CheckCircle className="h-3.5 w-3.5 text-success" /> : c.status === "fail" ? <XCircle className="h-3.5 w-3.5 text-destructive" /> : <AlertTriangle className="h-3.5 w-3.5 text-warning" />}
                <span className="text-xs font-medium text-foreground flex-1">{c.check_name}</span>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${c.status === "pass" ? "bg-success/20 text-success" : c.status === "fail" ? "bg-destructive/20 text-destructive" : "bg-warning/20 text-warning"}`}>{c.status}</span>
                {expanded === c.check_id ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
              </button>
              {expanded === c.check_id && (
                <div className="px-4 pb-4 ml-7 space-y-2">
                  <p className="text-xs text-muted-foreground">{c.description}</p>
                  {c.remediation && <p className="text-xs text-primary"><strong>Remediation:</strong> {c.remediation}</p>}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </AppLayout>
  );
}
