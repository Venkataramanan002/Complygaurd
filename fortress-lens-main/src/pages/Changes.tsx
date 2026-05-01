import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { GitPullRequest, Plus, CheckCircle, XCircle, Rocket, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  getChangeDashboard, getChanges, createChange, approveChange, rejectChange, deployChange, rollbackChange,
  getAuthMe, type ChangeRequestData,
} from "@/lib/api";

const statusColors: Record<string, string> = {
  draft: "bg-secondary text-muted-foreground",
  pending_review: "bg-warning/20 text-warning",
  approved: "bg-blue-900/40 text-blue-400",
  rejected: "bg-destructive/20 text-destructive",
  implementing: "bg-primary/20 text-primary",
  deployed: "bg-success/20 text-success",
  rolled_back: "bg-secondary text-muted-foreground",
  failed: "bg-destructive/20 text-destructive",
};

const priorityColors: Record<string, string> = {
  critical: "bg-red-900/40 text-red-400",
  high: "bg-orange-900/40 text-orange-400",
  medium: "bg-yellow-900/40 text-yellow-400",
  low: "bg-green-900/40 text-green-400",
};

export default function Changes() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [form, setForm] = useState({ title: "", description: "", requester_name: "", priority: "medium", device_name: "", change_type: "add_rule", proposed_changes: [{ rule_name: "", source_ip: "", dest_ip: "", dest_port: "", protocol: "tcp", action: "allow" }] });

  const dashQ = useQuery({ queryKey: ["changeDash"], queryFn: getChangeDashboard, staleTime: 10_000 });
  const listQ = useQuery({ queryKey: ["changes", statusFilter], queryFn: () => getChanges(statusFilter || undefined), staleTime: 10_000 });

  const dash = dashQ.data;
  const changes = listQ.data?.changes ?? [];

  const handleCreate = async () => {
    if (!form.title || !form.requester_name) return;
    await createChange(form);
    qc.invalidateQueries({ queryKey: ["changes"] });
    qc.invalidateQueries({ queryKey: ["changeDash"] });
    setDialogOpen(false);
  };

  const handleAction = async (id: string, action: string) => {
    try {
      const userRes = await getAuthMe().catch(() => ({ username: "Analyst" }));
      const actor = userRes.username || "Analyst";
      if (action === "approve") await approveChange(id, actor, "Approved via UI");
      else if (action === "reject") await rejectChange(id, actor, "Rejected via UI");
      else if (action === "deploy") await deployChange(id);
      else if (action === "rollback") await rollbackChange(id);
      qc.invalidateQueries({ queryKey: ["changes"] });
      qc.invalidateQueries({ queryKey: ["changeDash"] });
    } catch (e) { console.error(e); }
  };

  return (
    <AppLayout title="Change Management" breadcrumb={["Change Management"]}>
      {/* KPI Bar */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: "Total Requests", value: dash?.total ?? 0, color: "text-primary" },
          { label: "Pending Review", value: dash?.pending_review ?? 0, color: "text-warning" },
          { label: "Deployed This Week", value: dash?.deployed_this_week ?? 0, color: "text-success" },
          { label: "Rollbacks", value: dash?.rollbacks ?? 0, color: "text-destructive" },
        ].map(k => (
          <div key={k.label} className="bg-card rounded-xl p-4 shadow-card">
            <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{k.label}</span>
            <p className={`text-2xl font-bold tabular-nums ${k.color} mt-1`}>{k.value}</p>
          </div>
        ))}
      </div>

      {/* Filter + Create */}
      <div className="bg-card rounded-xl p-4 shadow-card mb-6 flex items-center justify-between">
        <div className="flex items-center gap-2">
          {["", "pending_review", "approved", "deployed", "rejected"].map(s => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={`text-xs px-3 py-1.5 rounded-lg font-medium transition-smooth ${statusFilter === s ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"}`}>
              {s || "All"}
            </button>
          ))}
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="h-8 text-xs"><Plus className="h-3.5 w-3.5 mr-1.5" />New Request</Button>
          </DialogTrigger>
          <DialogContent className="bg-card border-border max-w-lg">
            <DialogHeader><DialogTitle className="text-sm">New Change Request</DialogTitle></DialogHeader>
            <div className="grid gap-3 py-2">
              <Input placeholder="Title" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} />
              <textarea className="w-full h-16 rounded-lg bg-secondary border border-border text-xs text-foreground p-2 resize-none" placeholder="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
              <div className="grid grid-cols-2 gap-3">
                <Input placeholder="Your name" value={form.requester_name} onChange={e => setForm({ ...form, requester_name: e.target.value })} />
                <Input placeholder="Device name" value={form.device_name} onChange={e => setForm({ ...form, device_name: e.target.value })} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Select value={form.priority} onValueChange={v => setForm({ ...form, priority: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={form.change_type} onValueChange={v => setForm({ ...form, change_type: v })}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="add_rule">Add Rule</SelectItem>
                    <SelectItem value="modify_rule">Modify Rule</SelectItem>
                    <SelectItem value="delete_rule">Delete Rule</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="text-xs text-muted-foreground">Proposed rules:</p>
              {form.proposed_changes.map((r, i) => (
                <div key={i} className="grid grid-cols-3 gap-2">
                  <Input placeholder="Source IP" value={r.source_ip} onChange={e => { const nr = [...form.proposed_changes]; nr[i] = { ...nr[i], source_ip: e.target.value }; setForm({ ...form, proposed_changes: nr }); }} className="text-xs" />
                  <Input placeholder="Dest IP" value={r.dest_ip} onChange={e => { const nr = [...form.proposed_changes]; nr[i] = { ...nr[i], dest_ip: e.target.value }; setForm({ ...form, proposed_changes: nr }); }} className="text-xs" />
                  <Input placeholder="Port" value={r.dest_port} onChange={e => { const nr = [...form.proposed_changes]; nr[i] = { ...nr[i], dest_port: e.target.value }; setForm({ ...form, proposed_changes: nr }); }} className="text-xs" />
                </div>
              ))}
              <Button onClick={handleCreate} className="w-full mt-2">Submit Request</Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Changes Table */}
      <div className="bg-card rounded-xl shadow-card overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              {["Title", "Requester", "Device", "Type", "Priority", "Risk", "Status", "Date", "Actions"].map(h => (
                <TableHead key={h} className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{h}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {changes.length === 0 ? (
              <TableRow><TableCell colSpan={9} className="text-center py-12 text-xs text-muted-foreground">No change requests yet.</TableCell></TableRow>
            ) : (
              changes.map(c => (
                <TableRow key={c.id} className="border-border/50">
                  <TableCell className="text-xs font-medium text-foreground max-w-[150px] truncate">{c.title}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{c.requester_name}</TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground">{c.device_name || "—"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{c.change_type.replace("_", " ")}</TableCell>
                  <TableCell><span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${priorityColors[c.priority] ?? ""}`}>{c.priority}</span></TableCell>
                  <TableCell><span className={`text-xs font-bold tabular-nums ${c.risk_score >= 6 ? "text-destructive" : c.risk_score >= 3 ? "text-warning" : "text-success"}`}>{c.risk_score.toFixed(1)}</span></TableCell>
                  <TableCell><span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${statusColors[c.status] ?? ""}`}>{c.status.replace("_", " ")}</span></TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground">{c.request_date ? new Date(c.request_date).toLocaleDateString("en-GB", { day: "2-digit", month: "short" }) : "—"}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {c.status === "pending_review" && (
                        <>
                          <Button variant="outline" size="sm" className="h-6 text-xs px-2" onClick={() => handleAction(c.id, "approve")}><CheckCircle className="h-3 w-3 mr-0.5" />Approve</Button>
                          <Button variant="ghost" size="sm" className="h-6 text-xs px-2 text-destructive" onClick={() => handleAction(c.id, "reject")}><XCircle className="h-3 w-3" /></Button>
                        </>
                      )}
                      {c.status === "approved" && (
                        <Button variant="outline" size="sm" className="h-6 text-xs px-2" onClick={() => handleAction(c.id, "deploy")}><Rocket className="h-3 w-3 mr-0.5" />Deploy</Button>
                      )}
                      {c.status === "deployed" && (
                        <Button variant="ghost" size="sm" className="h-6 text-xs px-2 text-warning" onClick={() => handleAction(c.id, "rollback")}><RotateCcw className="h-3 w-3 mr-0.5" />Rollback</Button>
                      )}
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
