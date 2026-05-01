import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { Plug, Zap, CheckCircle, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getIntegrations, testIntegration } from "@/lib/api";

export default function Integrations() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["integrations"], queryFn: getIntegrations, staleTime: 30_000 });
  const targets = q.data?.targets ?? [];

  const handleTest = async (name: string) => {
    try {
      await testIntegration(name);
      qc.invalidateQueries({ queryKey: ["integrations"] });
    } catch (e) { console.error(e); }
  };

  return (
    <AppLayout title="Integrations" breadcrumb={["Integrations"]}>
      <div className="bg-card rounded-xl p-4 shadow-card mb-6 flex items-center gap-3">
        <Plug className="h-5 w-5 text-primary" />
        <h2 className="text-sm font-semibold text-foreground">SIEM Integrations</h2>
        <span className="text-xs text-muted-foreground">{targets.length} target{targets.length !== 1 ? "s" : ""} configured</span>
      </div>

      {targets.length === 0 ? (
        <div className="bg-card rounded-xl p-12 shadow-card text-center">
          <Plug className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
          <p className="text-sm font-semibold text-foreground mb-2">No integrations configured</p>
          <p className="text-xs text-muted-foreground">Edit config/siem.yaml to add SIEM targets (Splunk HEC, Elastic, Webhook, Syslog).</p>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          {targets.map(t => (
            <div key={t.name} className="bg-card rounded-xl p-5 shadow-card">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Zap className="h-4 w-4 text-primary" />
                  <span className="text-sm font-semibold text-foreground">{t.name}</span>
                  <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-primary/20 text-primary uppercase">{t.type}</span>
                </div>
                {t.enabled ? <CheckCircle className="h-4 w-4 text-success" /> : <XCircle className="h-4 w-4 text-muted-foreground" />}
              </div>
              <div className="space-y-1 text-xs text-muted-foreground mb-3">
                <p>Endpoint: <span className="font-mono text-foreground">{t.endpoint.slice(0, 40)}...</span></p>
                <p>Events Sent: <span className="text-foreground tabular-nums">{t.events_sent}</span></p>
              </div>
              <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => handleTest(t.name)}>Test Connection</Button>
            </div>
          ))}
        </div>
      )}
    </AppLayout>
  );
}
