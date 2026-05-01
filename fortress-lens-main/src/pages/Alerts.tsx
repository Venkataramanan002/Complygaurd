import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { Bell, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getAlerts, acknowledgeAlert, getAuthMe, type AlertData } from "@/lib/api";

const sevColors: Record<string, string> = {
  critical: "bg-destructive/20 text-destructive",
  high: "bg-orange-900/40 text-orange-400",
  medium: "bg-warning/20 text-warning",
  low: "bg-success/20 text-success",
};

const typeColors: Record<string, string> = {
  drift: "bg-blue-900/40 text-blue-400",
  threat: "bg-red-900/40 text-red-400",
  compliance: "bg-purple-900/40 text-purple-400",
  health: "bg-cyan-900/40 text-cyan-400",
};

export default function AlertsPage() {
  const qc = useQueryClient();
  const [filter, setFilter] = useState<boolean | undefined>(undefined);
  const q = useQuery({ queryKey: ["alerts", filter], queryFn: () => getAlerts(filter), staleTime: 10_000, refetchInterval: 10_000 });
  const alerts = q.data?.alerts ?? [];

  const handleAck = async (id: string) => {
    const userRes = await getAuthMe().catch(() => ({ username: "Analyst" }));
    await acknowledgeAlert(id, userRes.username || "Analyst");
    qc.invalidateQueries({ queryKey: ["alerts"] });
    qc.invalidateQueries({ queryKey: ["unreadAlerts"] });
  };

  return (
    <AppLayout title="Alerts" breadcrumb={["Alerts"]}>
      <div className="bg-card rounded-xl p-4 shadow-card mb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bell className="h-5 w-5 text-primary" />
          <h2 className="text-sm font-semibold text-foreground">All Alerts</h2>
          <span className="text-xs text-muted-foreground">{alerts.length} total</span>
        </div>
        <div className="flex gap-1">
          {[
            { label: "All", val: undefined },
            { label: "Unread", val: false },
            { label: "Acknowledged", val: true },
          ].map(f => (
            <button key={f.label} onClick={() => setFilter(f.val)}
              className={`text-xs px-3 py-1 rounded-lg font-medium transition-smooth ${filter === f.val ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"}`}>
              {f.label}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-card rounded-xl shadow-card overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              {["Type", "Severity", "Title", "Device", "Time", "Status", ""].map(h => (
                <TableHead key={h} className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{h}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {alerts.length === 0 ? (
              <TableRow><TableCell colSpan={7} className="text-center py-12 text-xs text-muted-foreground">No alerts</TableCell></TableRow>
            ) : (
              alerts.map(a => (
                <TableRow key={a.id} className={`border-border/50 ${!a.acknowledged ? "bg-primary/5" : ""}`}>
                  <TableCell><span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${typeColors[a.alert_type] ?? "bg-secondary text-muted-foreground"}`}>{a.alert_type}</span></TableCell>
                  <TableCell><span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${sevColors[a.severity] ?? ""}`}>{a.severity}</span></TableCell>
                  <TableCell className="text-xs text-foreground max-w-[250px] truncate">{a.title}</TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground">{a.source_device || "—"}</TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground">{new Date(a.created_at).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}</TableCell>
                  <TableCell>{a.acknowledged ? <span className="text-xs text-muted-foreground">Acknowledged</span> : <span className="text-xs text-primary font-semibold">New</span>}</TableCell>
                  <TableCell>{!a.acknowledged && <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={() => handleAck(a.id)}><Check className="h-3 w-3 mr-0.5" />Ack</Button>}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </AppLayout>
  );
}
