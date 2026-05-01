import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { Radar, Search, RefreshCw, Globe, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { checkThreatIntel, getIOCSummary, enrichConnections, type ThreatIntelCheckResult } from "@/lib/api";

const scoreColor = (score: number) =>
  score >= 70 ? "text-destructive" : score >= 40 ? "text-warning" : "text-success";

const scoreBg = (score: number) =>
  score >= 70 ? "bg-destructive/20 text-destructive" : score >= 40 ? "bg-warning/20 text-warning" : "bg-success/20 text-success";

export default function ThreatIntel() {
  const qc = useQueryClient();
  const [searchIP, setSearchIP] = useState("");
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<ThreatIntelCheckResult | null>(null);
  const [enriching, setEnriching] = useState(false);

  const iocQ = useQuery({ queryKey: ["iocSummary"], queryFn: getIOCSummary, staleTime: 60_000 });
  const iocs = iocQ.data?.iocs ?? [];

  const handleCheck = async () => {
    if (!searchIP.trim()) return;
    setChecking(true);
    try {
      const res = await checkThreatIntel(searchIP.trim());
      setCheckResult(res);
    } catch { /* empty */ }
    setChecking(false);
  };

  const handleEnrich = async () => {
    setEnriching(true);
    try {
      await enrichConnections();
      qc.invalidateQueries({ queryKey: ["iocSummary"] });
    } catch { /* empty */ }
    setEnriching(false);
  };

  return (
    <AppLayout title="Threat Intelligence" breadcrumb={["Threat Intelligence"]}>
      {/* Search Bar */}
      <div className="bg-card rounded-xl p-5 shadow-card mb-6">
        <div className="flex items-center gap-3 mb-4">
          <Radar className="h-5 w-5 text-primary" />
          <h2 className="text-sm font-semibold text-foreground">IP Reputation Lookup</h2>
        </div>
        <div className="flex gap-2">
          <div className="relative flex-1 max-w-md">
            <Search className="h-3.5 w-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Enter IP address (e.g., 8.8.8.8)"
              className="pl-9"
              value={searchIP}
              onChange={e => setSearchIP(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleCheck()}
            />
          </div>
          <Button onClick={handleCheck} disabled={checking || !searchIP.trim()}>
            {checking ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : <Search className="h-4 w-4 mr-2" />}
            Check IP
          </Button>
          <Button variant="outline" onClick={handleEnrich} disabled={enriching}>
            {enriching ? <RefreshCw className="h-4 w-4 animate-spin mr-2" /> : <Globe className="h-4 w-4 mr-2" />}
            Enrich All Connections
          </Button>
        </div>
      </div>

      {/* Check Result Card */}
      {checkResult && (
        <div className={`bg-card rounded-xl p-5 shadow-card mb-6 border ${checkResult.is_malicious ? "border-red-800/30" : "border-border"}`}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <span className="text-base font-mono font-bold text-foreground">{checkResult.ip}</span>
              <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${scoreBg(checkResult.combined_score)}`}>
                Score: {checkResult.combined_score}
              </span>
              {checkResult.is_malicious && (
                <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-destructive/20 text-destructive flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" /> Malicious
                </span>
              )}
            </div>
            <span className="text-xs text-muted-foreground uppercase">{checkResult.status}</span>
          </div>

          {checkResult.sources.length > 0 && (
            <div className="grid grid-cols-3 gap-4">
              {checkResult.sources.map(s => (
                <div key={s.source} className="bg-black/20 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-foreground uppercase">{s.source}</span>
                    <span className={`text-sm font-bold tabular-nums ${scoreColor(s.risk_score)}`}>{s.risk_score}</span>
                  </div>
                  <div className="space-y-1 text-xs text-muted-foreground">
                    {s.country && <div>Country: <span className="text-foreground">{s.country}</span></div>}
                    {s.isp && <div>ISP: <span className="text-foreground">{s.isp}</span></div>}
                    <div>Reports: <span className="text-foreground">{s.reports_count}</span></div>
                    {s.categories.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {s.categories.slice(0, 3).map((c, i) => (
                          <span key={i} className="bg-secondary px-1.5 py-0.5 rounded text-xs">{c}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* IOC Summary Table */}
      <div className="bg-card rounded-xl shadow-card overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-warning" />
            <h3 className="text-sm font-semibold text-foreground">IOC Summary — Top Suspicious IPs</h3>
          </div>
          <span className="text-xs text-muted-foreground">{iocs.length} entries</span>
        </div>
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              {["IP Address", "Risk Score", "Status", "Country", "Sources"].map(h => (
                <TableHead key={h} className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{h}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {iocs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center py-12 text-xs text-muted-foreground">
                  No IOC data yet. Click "Enrich All Connections" to scan traffic IPs.
                </TableCell>
              </TableRow>
            ) : (
              iocs.map(ioc => (
                <TableRow key={ioc.ip} className="border-border/50">
                  <TableCell className="text-xs font-mono text-foreground">{ioc.ip}</TableCell>
                  <TableCell><span className={`text-xs font-bold tabular-nums ${scoreColor(ioc.max_score)}`}>{ioc.max_score}</span></TableCell>
                  <TableCell>
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${ioc.is_malicious ? "bg-destructive/20 text-destructive" : "bg-success/20 text-success"}`}>
                      {ioc.is_malicious ? "Malicious" : "Clean"}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{ioc.country || "—"}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {ioc.sources.map((s, i) => (
                        <span key={i} className="text-xs bg-secondary px-1.5 py-0.5 rounded uppercase">{s}</span>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </AppLayout>
  );
}
