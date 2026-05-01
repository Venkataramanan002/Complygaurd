import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { ClipboardCheck, Search, UserPlus, CheckCircle, XCircle, Clock, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  getLifecycleDashboard, getLifecycleRules, assignRuleOwner, certifyRule,
  type LifecycleRule,
} from "@/lib/api";

const statusColors: Record<string, string> = {
  active: "bg-success/20 text-success",
  pending_review: "bg-warning/20 text-warning",
  expired: "bg-destructive/20 text-destructive",
  decommissioned: "bg-secondary text-muted-foreground",
  unowned: "bg-secondary text-muted-foreground",
};

export default function RuleLifecycle() {
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [assignOpen, setAssignOpen] = useState(false);
  const [certifyOpen, setCertifyOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<LifecycleRule | null>(null);

  // Assign form
  const [ownerName, setOwnerName] = useState("");
  const [ownerEmail, setOwnerEmail] = useState("");
  const [department, setDepartment] = useState("");

  // Certify form
  const [reviewerName, setReviewerName] = useState("");
  const [decision, setDecision] = useState("certify");
  const [justification, setJustification] = useState("");
  const [nextReviewMonths, setNextReviewMonths] = useState(6);
  const [riskAccepted, setRiskAccepted] = useState(false);

  const dashQ = useQuery({ queryKey: ["lifecycleDash"], queryFn: getLifecycleDashboard, staleTime: 15_000 });
  const rulesQ = useQuery({
    queryKey: ["lifecycleRules", statusFilter, search],
    queryFn: () => getLifecycleRules(statusFilter, search),
    staleTime: 10_000,
  });

  const dash = dashQ.data;
  const rules = rulesQ.data?.rules ?? [];

  const handleAssign = async () => {
    if (!selectedRule || !ownerName || !ownerEmail) return;
    await assignRuleOwner(selectedRule.rule_id, { owner_name: ownerName, owner_email: ownerEmail, department });
    qc.invalidateQueries({ queryKey: ["lifecycleRules"] });
    qc.invalidateQueries({ queryKey: ["lifecycleDash"] });
    setAssignOpen(false);
    setOwnerName(""); setOwnerEmail(""); setDepartment("");
  };

  const handleCertify = async () => {
    if (!selectedRule || !reviewerName) return;
    await certifyRule(selectedRule.rule_id, {
      reviewer_name: reviewerName,
      decision,
      justification,
      next_review_months: nextReviewMonths,
      risk_accepted: riskAccepted,
    });
    qc.invalidateQueries({ queryKey: ["lifecycleRules"] });
    qc.invalidateQueries({ queryKey: ["lifecycleDash"] });
    setCertifyOpen(false);
    setReviewerName(""); setDecision("certify"); setJustification(""); setRiskAccepted(false);
  };

  return (
    <AppLayout title="Rule Lifecycle" breadcrumb={["Rule Lifecycle"]}>
      {/* KPI Bar */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {[
          { label: "Total Rules", value: dash?.total_rules ?? 0, icon: ClipboardCheck, color: "text-primary" },
          { label: "Certified", value: dash?.certified ?? 0, sub: `${dash?.certified_pct ?? 0}%`, icon: CheckCircle, color: "text-success" },
          { label: "Expired", value: dash?.expired ?? 0, sub: `${dash?.expired_pct ?? 0}%`, icon: XCircle, color: "text-destructive" },
          { label: "Due Soon", value: dash?.due_soon ?? 0, sub: `${dash?.due_soon_pct ?? 0}%`, icon: Clock, color: "text-warning" },
          { label: "Unowned", value: dash?.unowned ?? 0, sub: `${dash?.unowned_pct ?? 0}%`, icon: AlertTriangle, color: "text-muted-foreground" },
        ].map(k => (
          <div key={k.label} className="bg-card rounded-xl p-4 shadow-card">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{k.label}</span>
              <k.icon className={`h-4 w-4 ${k.color}`} />
            </div>
            <p className="text-2xl font-bold tabular-nums text-foreground">{k.value}</p>
            {k.sub && <p className="text-xs text-muted-foreground mt-0.5">{k.sub}</p>}
          </div>
        ))}
      </div>

      {/* Filter Bar */}
      <div className="bg-card rounded-xl p-4 shadow-card mb-6 flex items-center gap-3">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-44 h-8 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="pending_review">Pending Review</SelectItem>
            <SelectItem value="expired">Expired</SelectItem>
            <SelectItem value="decommissioned">Decommissioned</SelectItem>
            <SelectItem value="unowned">Unowned</SelectItem>
          </SelectContent>
        </Select>
        <div className="relative flex-1">
          <Search className="h-3.5 w-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by rule name or owner..."
            className="h-8 pl-9 text-xs"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-card rounded-xl shadow-card overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              {["Rule Name", "Device", "Owner", "Department", "Last Certified", "Due Date", "Status", "Actions"].map(h => (
                <TableHead key={h} className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{h}</TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="text-center py-12 text-xs text-muted-foreground">
                  {rulesQ.isLoading ? "Loading..." : "No rules found matching your filters."}
                </TableCell>
              </TableRow>
            ) : (
              rules.map(r => (
                <TableRow key={r.rule_id} className="border-border/50">
                  <TableCell className="text-xs font-medium text-foreground max-w-[160px] truncate">{r.rule_name}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{r.device_name}</TableCell>
                  <TableCell className="text-xs text-foreground">{r.owner_name || <span className="text-muted-foreground">—</span>}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{r.department || "—"}</TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground">
                    {r.last_certified_date ? new Date(r.last_certified_date).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "2-digit" }) : "—"}
                  </TableCell>
                  <TableCell className="text-xs font-mono text-muted-foreground">
                    {r.certification_due_date ? new Date(r.certification_due_date).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "2-digit" }) : "—"}
                  </TableCell>
                  <TableCell>
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${statusColors[r.status] ?? statusColors.unowned}`}>
                      {r.status.replace("_", " ")}
                    </span>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button variant="outline" size="sm" className="h-6 text-xs px-2" onClick={() => { setSelectedRule(r); setCertifyOpen(true); }}>
                        Certify
                      </Button>
                      <Button variant="ghost" size="sm" className="h-6 text-xs px-2" onClick={() => { setSelectedRule(r); setAssignOpen(true); }}>
                        <UserPlus className="h-3 w-3" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Assign Owner Dialog */}
      <Dialog open={assignOpen} onOpenChange={setAssignOpen}>
        <DialogContent className="bg-card border-border">
          <DialogHeader>
            <DialogTitle className="text-sm">Assign Owner — {selectedRule?.rule_name}</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Owner Name</label>
              <Input value={ownerName} onChange={e => setOwnerName(e.target.value)} placeholder="John Smith" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Email</label>
              <Input value={ownerEmail} onChange={e => setOwnerEmail(e.target.value)} placeholder="john@company.com" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Department</label>
              <Select value={department} onValueChange={setDepartment}>
                <SelectTrigger><SelectValue placeholder="Select..." /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="Network Operations">Network Operations</SelectItem>
                  <SelectItem value="Security">Security</SelectItem>
                  <SelectItem value="IT Infrastructure">IT Infrastructure</SelectItem>
                  <SelectItem value="DevOps">DevOps</SelectItem>
                  <SelectItem value="Compliance">Compliance</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button onClick={handleAssign} className="w-full mt-2">Assign Owner</Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Certify Dialog */}
      <Dialog open={certifyOpen} onOpenChange={setCertifyOpen}>
        <DialogContent className="bg-card border-border">
          <DialogHeader>
            <DialogTitle className="text-sm">Certify Rule — {selectedRule?.rule_name}</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3 py-2">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Reviewer Name</label>
              <Input value={reviewerName} onChange={e => setReviewerName(e.target.value)} placeholder="Your name" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Decision</label>
              <Select value={decision} onValueChange={setDecision}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="certify">Certify — Rule is valid</SelectItem>
                  <SelectItem value="modify">Modify — Rule needs changes</SelectItem>
                  <SelectItem value="decommission">Decommission — Remove rule</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Justification</label>
              <textarea
                className="w-full h-20 rounded-lg bg-secondary border border-border text-xs text-foreground p-2 resize-none"
                value={justification}
                onChange={e => setJustification(e.target.value)}
                placeholder="Reason for this decision..."
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Next Review</label>
              <Select value={String(nextReviewMonths)} onValueChange={v => setNextReviewMonths(parseInt(v))}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="3">3 months</SelectItem>
                  <SelectItem value="6">6 months</SelectItem>
                  <SelectItem value="12">12 months</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <label className="flex items-center gap-2 text-xs text-foreground">
              <input type="checkbox" checked={riskAccepted} onChange={e => setRiskAccepted(e.target.checked)} className="rounded" />
              Risk Accepted — I acknowledge the risk associated with this rule
            </label>
            <Button onClick={handleCertify} className="w-full mt-2">Submit Review</Button>
          </div>
        </DialogContent>
      </Dialog>
    </AppLayout>
  );
}
