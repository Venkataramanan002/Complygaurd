import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { FileText, Download, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { generateReport, listReports, downloadReport } from "@/lib/api";

export default function Reports() {
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [template, setTemplate] = useState("executive_summary");
  const [format, setFormat] = useState("json");
  const [generating, setGenerating] = useState(false);

  const q = useQuery({ queryKey: ["reports"], queryFn: listReports, staleTime: 10_000 });
  const reports = q.data?.reports ?? [];

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      await generateReport(template, format);
      qc.invalidateQueries({ queryKey: ["reports"] });
      setDialogOpen(false);
    } catch (e) { console.error(e); }
    setGenerating(false);
  };

  return (
    <AppLayout title="Reports" breadcrumb={["Reports"]}>
      <div className="bg-card rounded-xl p-4 shadow-card mb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText className="h-5 w-5 text-primary" />
          <h2 className="text-sm font-semibold text-foreground">Generated Reports</h2>
          <span className="text-xs text-muted-foreground">{reports.length} reports</span>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="h-8 text-xs"><Plus className="h-3.5 w-3.5 mr-1.5" />Generate Report</Button>
          </DialogTrigger>
          <DialogContent className="bg-card border-border">
            <DialogHeader><DialogTitle className="text-sm">Generate Report</DialogTitle></DialogHeader>
            <div className="grid gap-3 py-2">
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Template</label>
                <Select value={template} onValueChange={setTemplate}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="executive_summary">Executive Summary</SelectItem>
                    <SelectItem value="compliance_audit">Compliance Audit</SelectItem>
                    <SelectItem value="risk_assessment">Risk Assessment</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">Format</label>
                <Select value={format} onValueChange={setFormat}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pdf">PDF</SelectItem>
                    <SelectItem value="json">JSON</SelectItem>
                    <SelectItem value="html">HTML</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button onClick={handleGenerate} disabled={generating} className="w-full mt-2">{generating ? "Generating..." : "Generate"}</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="bg-card rounded-xl shadow-card overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              {["Report ID", "Template", "Format", "Size", "Generated", "Actions"].map(h => (
                <TableHead key={h} className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{h}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {reports.length === 0 ? (
              <TableRow><TableCell colSpan={6} className="text-center py-12 text-xs text-muted-foreground">No reports generated yet.</TableCell></TableRow>
            ) : (
              reports.map(r => {
                const tpl = r.template ?? (r.filename ? r.filename.split("_").slice(0, -2).join("_") : "unknown");
                const ts = r.generated_at ?? r.created_at;
                const tsDate = ts ? (typeof ts === "number" ? new Date(ts * 1000) : new Date(ts)) : null;
                return (
                  <TableRow key={r.report_id} className="border-border/50">
                    <TableCell className="text-xs font-mono text-muted-foreground">{(r.report_id ?? "").slice(0, 12)}{(r.report_id?.length ?? 0) > 12 ? "..." : ""}</TableCell>
                    <TableCell className="text-xs text-foreground capitalize">{tpl.replace(/_/g, " ")}</TableCell>
                    <TableCell><span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-primary/20 text-primary uppercase">{r.format}</span></TableCell>
                    <TableCell className="text-xs text-muted-foreground tabular-nums">{((r.file_size ?? 0) / 1024).toFixed(1)} KB</TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground">{tsDate ? tsDate.toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "—"}</TableCell>
                    <TableCell><Button variant="ghost" size="sm" className="h-6 text-xs" onClick={() => downloadReport(r.report_id)}><Download className="h-3 w-3 mr-1" />Download</Button></TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </AppLayout>
  );
}
