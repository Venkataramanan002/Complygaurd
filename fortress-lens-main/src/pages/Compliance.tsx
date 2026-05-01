import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { ShieldCheck, ChevronDown, ChevronUp, CheckCircle, XCircle, AlertTriangle, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getComplianceAll, downloadPDFReport, type ComplianceFrameworkResult, type ComplianceCheck } from "@/lib/api";

const statusIcon = (status: string) => {
  if (status === "pass") return <CheckCircle className="h-3.5 w-3.5 text-success" />;
  if (status === "fail") return <XCircle className="h-3.5 w-3.5 text-destructive" />;
  if (status === "warning") return <AlertTriangle className="h-3.5 w-3.5 text-warning" />;
  return <span className="text-xs text-muted-foreground">N/A</span>;
};

const statusBadge = (status: string) => {
  const cls = status === "pass" ? "bg-success/20 text-success" :
    status === "fail" ? "bg-destructive/20 text-destructive" :
    status === "warning" ? "bg-warning/20 text-warning" : "bg-secondary text-muted-foreground";
  return <span className={`text-xs font-semibold px-2 py-0.5 rounded-full uppercase ${cls}`}>{status}</span>;
};

const scoreColor = (score: number) =>
  score >= 80 ? "text-success" : score >= 60 ? "text-warning" : "text-destructive";

const overallBadge = (status: string) => {
  const cls = status === "Compliant" ? "bg-success/20 text-success" :
    status === "Partial" ? "bg-warning/20 text-warning" : "bg-destructive/20 text-destructive";
  return <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${cls}`}>{status}</span>;
};

export default function CompliancePage() {
  const [activeFramework, setActiveFramework] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const q = useQuery({ queryKey: ["complianceAll"], queryFn: getComplianceAll, staleTime: 60_000 });
  const frameworks = q.data?.frameworks ?? [];
  const active = frameworks[activeFramework] ?? null;

  return (
    <AppLayout title="Compliance" breadcrumb={["Compliance"]}>
      {/* Framework Cards */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {frameworks.map((fw, i) => (
          <button
            key={fw.framework}
            onClick={() => setActiveFramework(i)}
            className={`bg-card rounded-xl p-4 shadow-card text-left transition-all border ${
              activeFramework === i ? "border-primary/40 ring-1 ring-primary/20" : "border-border hover:border-primary/20"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold truncate">{fw.framework}</span>
              {overallBadge(fw.status)}
            </div>
            <p className={`text-2xl font-bold tabular-nums ${scoreColor(fw.overall_score)}`}>{fw.overall_score.toFixed(0)}%</p>
            <div className="flex gap-2 mt-2 text-xs">
              <span className="text-success">{fw.passed} pass</span>
              <span className="text-destructive">{fw.failed} fail</span>
              <span className="text-warning">{fw.warnings} warn</span>
            </div>
          </button>
        ))}
        {frameworks.length === 0 && (
          <div className="col-span-5 bg-card rounded-xl p-12 shadow-card text-center">
            <ShieldCheck className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-xs text-muted-foreground">{q.isLoading ? "Loading compliance data..." : "Upload a firewall config to run compliance checks."}</p>
          </div>
        )}
      </div>

      {/* Framework Details */}
      {active && (
        <>
          <div className="bg-card rounded-xl p-5 shadow-card mb-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <ShieldCheck className="h-5 w-5 text-primary" />
                <h2 className="text-sm font-semibold text-foreground">{active.framework}</h2>
                {overallBadge(active.status)}
              </div>
              <div className="flex items-center gap-4">
                <div className="flex gap-3 text-xs">
                  <span><span className="font-bold text-foreground">{active.total_checks}</span> <span className="text-muted-foreground">checks</span></span>
                  <span className="text-success"><span className="font-bold">{active.passed}</span> passed</span>
                  <span className="text-destructive"><span className="font-bold">{active.failed}</span> failed</span>
                  <span className="text-warning"><span className="font-bold">{active.warnings}</span> warnings</span>
                </div>
                <Button variant="outline" size="sm" className="h-7 text-xs" onClick={downloadPDFReport}>
                  <Download className="h-3 w-3 mr-1" />Export PDF
                </Button>
              </div>
            </div>
            {/* Score bar */}
            <div className="mt-3 h-2 bg-secondary rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-700 ${
                  active.overall_score >= 80 ? "bg-success" :
                  active.overall_score >= 60 ? "bg-warning" : "bg-destructive"
                }`}
                style={{ width: `${active.overall_score}%` }}
              />
            </div>
          </div>

          {/* Check List */}
          <div className="bg-card rounded-xl shadow-card overflow-hidden">
            {active.checks.map(check => (
              <div key={check.check_id} className="border-b border-border/50">
                <button
                  onClick={() => setExpanded(expanded === check.check_id ? null : check.check_id)}
                  className="w-full flex items-center gap-3 p-4 text-left hover:bg-primary/5 transition-smooth"
                >
                  {statusIcon(check.status)}
                  <span className="text-xs font-mono text-muted-foreground w-20">{check.check_id}</span>
                  <span className="text-xs font-medium text-foreground flex-1">{check.check_name}</span>
                  {statusBadge(check.status)}
                  {expanded === check.check_id ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
                </button>
                {expanded === check.check_id && (
                  <div className="px-4 pb-4 ml-9 space-y-2">
                    <p className="text-xs text-muted-foreground">{check.description}</p>
                    <div>
                      <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-1">Evidence</p>
                      {check.evidence.map((e, i) => (
                        <p key={i} className="text-xs text-foreground font-mono">{e}</p>
                      ))}
                    </div>
                    {check.remediation_suggestion && (
                      <div className="bg-primary/5 rounded-lg p-3 mt-2">
                        <p className="text-xs uppercase tracking-widest text-primary font-bold mb-1">Remediation</p>
                        <p className="text-xs text-foreground">{check.remediation_suggestion}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </AppLayout>
  );
}
