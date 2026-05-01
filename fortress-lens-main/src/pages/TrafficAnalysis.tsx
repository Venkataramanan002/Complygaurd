import { useQuery } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { BarChart3 } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { getTopTalkers, getZoneFlowMatrix, getAppUsage, getEastWestNorthSouth } from "@/lib/api";

const fmt = (bytes: number) => {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
};

const COLORS = ["hsl(217,91%,60%)", "hsl(142,70%,45%)", "hsl(38,92%,50%)", "hsl(262,83%,58%)", "hsl(0,70%,50%)"];

export default function TrafficAnalysis() {
  const talkersQ = useQuery({ queryKey: ["topTalkers"], queryFn: () => getTopTalkers(), staleTime: 30_000 });
  const zoneQ = useQuery({ queryKey: ["zoneMatrix"], queryFn: getZoneFlowMatrix, staleTime: 30_000 });
  const appQ = useQuery({ queryKey: ["appUsage"], queryFn: () => getAppUsage(), staleTime: 30_000 });
  const ewnsQ = useQuery({ queryKey: ["ewns"], queryFn: getEastWestNorthSouth, staleTime: 30_000 });

  const senders = talkersQ.data?.senders ?? [];
  const receivers = talkersQ.data?.receivers ?? [];
  const apps = appQ.data?.applications ?? [];
  const ewns = ewnsQ.data;
  const zoneFlows = zoneQ.data?.flows ?? [];
  const zoneList = zoneQ.data?.zones ?? [];

  // Build matrix lookup
  const matrixLookup: Record<string, number> = {};
  let maxBytes = 1;
  for (const f of zoneFlows) {
    matrixLookup[`${f.zone_from}→${f.zone_to}`] = f.total_bytes;
    if (f.total_bytes > maxBytes) maxBytes = f.total_bytes;
  }

  return (
    <AppLayout title="Traffic Analysis" breadcrumb={["Traffic Analysis"]}>
      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Top Senders */}
        <div className="bg-card rounded-xl p-5 shadow-card">
          <h3 className="text-sm font-semibold text-foreground mb-4 flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-primary" /> Top Senders (by bytes)
          </h3>
          {senders.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={senders.slice(0, 10)} layout="vertical">
                <XAxis type="number" stroke="hsl(240,5%,40%)" fontSize={10} tickFormatter={fmt} />
                <YAxis type="category" dataKey="ip" stroke="hsl(240,5%,40%)" fontSize={9} width={100} />
                <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 11 }} formatter={(v: number) => fmt(v)} />
                <Bar dataKey="total_bytes" fill="hsl(217,91%,60%)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="h-64 flex items-center justify-center text-xs text-muted-foreground">No traffic data</div>}
        </div>

        {/* Top Receivers */}
        <div className="bg-card rounded-xl p-5 shadow-card">
          <h3 className="text-sm font-semibold text-foreground mb-4">Top Receivers (by bytes)</h3>
          {receivers.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={receivers.slice(0, 10)} layout="vertical">
                <XAxis type="number" stroke="hsl(240,5%,40%)" fontSize={10} tickFormatter={fmt} />
                <YAxis type="category" dataKey="ip" stroke="hsl(240,5%,40%)" fontSize={9} width={100} />
                <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 11 }} formatter={(v: number) => fmt(v)} />
                <Bar dataKey="total_bytes" fill="hsl(38,92%,50%)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="h-64 flex items-center justify-center text-xs text-muted-foreground">No traffic data</div>}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* E-W vs N-S */}
        <div className="bg-card rounded-xl p-5 shadow-card">
          <h3 className="text-sm font-semibold text-foreground mb-4">East-West vs North-South</h3>
          {ewns ? (
            <div className="flex items-center gap-6">
              <ResponsiveContainer width="50%" height={200}>
                <PieChart>
                  <Pie data={[
                    { name: "East-West", value: ewns.east_west_bytes },
                    { name: "North-South", value: ewns.north_south_bytes },
                  ]} cx="50%" cy="50%" innerRadius={50} outerRadius={75} dataKey="value" paddingAngle={2}>
                    <Cell fill="hsl(217,91%,60%)" />
                    <Cell fill="hsl(38,92%,50%)" />
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 11 }} formatter={(v: number) => fmt(v)} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground">East-West (Internal)</p>
                  <p className="text-xl font-bold text-primary tabular-nums">{ewns.east_west_pct}%</p>
                  <p className="text-xs text-muted-foreground">{fmt(ewns.east_west_bytes)}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">North-South (External)</p>
                  <p className="text-xl font-bold text-warning tabular-nums">{ewns.north_south_pct}%</p>
                  <p className="text-xs text-muted-foreground">{fmt(ewns.north_south_bytes)}</p>
                </div>
              </div>
            </div>
          ) : <div className="h-48 flex items-center justify-center text-xs text-muted-foreground">No zone data</div>}
        </div>

        {/* App Usage */}
        <div className="bg-card rounded-xl p-5 shadow-card">
          <h3 className="text-sm font-semibold text-foreground mb-4">Application Usage</h3>
          {apps.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={apps.slice(0, 8)} layout="vertical">
                <XAxis type="number" stroke="hsl(240,5%,40%)" fontSize={10} tickFormatter={fmt} />
                <YAxis type="category" dataKey="app_name" stroke="hsl(240,5%,40%)" fontSize={9} width={80} />
                <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 11 }} formatter={(v: number) => fmt(v)} />
                <Bar dataKey="total_bytes" radius={[0, 4, 4, 0]}>
                  {apps.slice(0, 8).map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <div className="h-48 flex items-center justify-center text-xs text-muted-foreground">No application data</div>}
        </div>
      </div>

      {/* Zone Flow Heatmap */}
      <div className="bg-card rounded-xl p-5 shadow-card">
        <h3 className="text-sm font-semibold text-foreground mb-4">Zone-to-Zone Traffic Flow Matrix</h3>
        {zoneList.length > 0 ? (
          <div className="overflow-auto">
            <table className="text-xs">
              <thead>
                <tr>
                  <th className="px-2 py-1 text-muted-foreground font-bold">From \ To</th>
                  {zoneList.map(z => <th key={z} className="px-2 py-1 text-muted-foreground font-bold text-center" style={{ writingMode: "vertical-rl" }}>{z}</th>)}
                </tr>
              </thead>
              <tbody>
                {zoneList.map(zf => (
                  <tr key={zf}>
                    <td className="px-2 py-1 text-muted-foreground font-medium whitespace-nowrap">{zf}</td>
                    {zoneList.map(zt => {
                      const val = matrixLookup[`${zf}→${zt}`] || 0;
                      const intensity = val > 0 ? Math.max(0.15, val / maxBytes) : 0;
                      return (
                        <td key={zt} className="px-2 py-1 text-center tabular-nums" style={{ backgroundColor: val > 0 ? `rgba(99,102,241,${intensity})` : "transparent" }}>
                          {val > 0 ? fmt(val) : "—"}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="h-32 flex items-center justify-center text-xs text-muted-foreground">No zone flow data — upload traffic logs to populate</div>}
      </div>
    </AppLayout>
  );
}
