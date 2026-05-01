import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { Server, Plus, RefreshCw, Play, Pause, Download, GitCompare, HardDrive } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  getCollectorStatus,
  pollDevice,
  toggleCollectorSchedule,
  addDevice,
  getBackupHistory,
  triggerBackup,
  getBackupDiff,
  downloadBackup,
  type DeviceStatus,
  type AddDevicePayload,
  type BackupEntry,
} from "@/lib/api";

const vendorBadge = (vendor: string) => {
  const colors: Record<string, string> = {
    paloalto: "bg-blue-900/40 text-blue-400",
    fortinet: "bg-red-900/40 text-red-400",
    cisco: "bg-cyan-900/40 text-cyan-400",
  };
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded-full uppercase ${colors[vendor] ?? "bg-secondary text-muted-foreground"}`}>
      {vendor}
    </span>
  );
};

const statusBadge = (device: DeviceStatus) => {
  if (device.last_poll === null)
    return <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-secondary text-muted-foreground">Never Polled</span>;
  if (device.last_poll_success)
    return <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-success/20 text-success">Success</span>;
  return <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-destructive/20 text-destructive">Error</span>;
};

export default function Devices() {
  const queryClient = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [polling, setPolling] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"devices" | "backups">("devices");
  const [selectedDevice, setSelectedDevice] = useState<string>("");
  const [backingUp, setBackingUp] = useState(false);
  const [diffOpen, setDiffOpen] = useState(false);
  const [diffData, setDiffData] = useState<{ diff: string; additions: number; deletions: number; a: string; b: string } | null>(null);
  const [compareA, setCompareA] = useState<string>("");
  const [compareB, setCompareB] = useState<string>("");

  // Queries
  const statusQ = useQuery({
    queryKey: ["collectorStatus"],
    queryFn: getCollectorStatus,
    staleTime: 10_000,
    refetchInterval: 10_000,
  });

  const data = statusQ.data;
  const devices = data?.devices ?? [];

  const backupQ = useQuery({
    queryKey: ["backupHistory", selectedDevice],
    queryFn: () => getBackupHistory(selectedDevice),
    enabled: !!selectedDevice && activeTab === "backups",
    staleTime: 10_000,
  });
  const backups = backupQ.data?.backups ?? [];

  // Form state for Add Device
  const [form, setForm] = useState<AddDevicePayload>({
    name: "",
    host: "",
    vendor: "paloalto",
    auth_type: "apikey",
    credentials_env_var: "",
    poll_interval_minutes: 15,
    enabled: true,
    verify_ssl: false,
  });

  const handlePoll = async (deviceName: string) => {
    setPolling(deviceName);
    try {
      await pollDevice(deviceName);
      queryClient.invalidateQueries({ queryKey: ["collectorStatus"] });
    } catch (e) {
      console.error("Poll failed:", e);
    } finally {
      setPolling(null);
    }
  };

  const handleToggleSchedule = async () => {
    await toggleCollectorSchedule();
    queryClient.invalidateQueries({ queryKey: ["collectorStatus"] });
  };

  const handleAddDevice = async () => {
    if (!form.name || !form.host || !form.credentials_env_var) return;
    try {
      await addDevice(form);
      queryClient.invalidateQueries({ queryKey: ["collectorStatus"] });
      setDialogOpen(false);
      setForm({ name: "", host: "", vendor: "paloalto", auth_type: "apikey", credentials_env_var: "", poll_interval_minutes: 15, enabled: true, verify_ssl: false });
    } catch (e) {
      console.error("Add device failed:", e);
    }
  };

  const handleBackupNow = async () => {
    if (!selectedDevice) return;
    setBackingUp(true);
    try {
      await triggerBackup(selectedDevice);
      queryClient.invalidateQueries({ queryKey: ["backupHistory", selectedDevice] });
    } catch (e) {
      console.error("Backup failed:", e);
    } finally {
      setBackingUp(false);
    }
  };

  const handleCompare = async () => {
    if (!compareA || !compareB || compareA === compareB) return;
    try {
      const result = await getBackupDiff(compareA, compareB);
      setDiffData({
        diff: result.diff,
        additions: result.additions,
        deletions: result.deletions,
        a: `v${result.backup_a.version}`,
        b: `v${result.backup_b.version}`,
      });
      setDiffOpen(true);
    } catch (e) {
      console.error("Diff failed:", e);
    }
  };

  return (
    <AppLayout title="Device Management" breadcrumb={["Device Management"]}>
      {/* Tabs */}
      <div className="flex items-center gap-1 mb-6">
        {[
          { key: "devices" as const, label: "Devices", icon: Server },
          { key: "backups" as const, label: "Config Backups", icon: HardDrive },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-smooth ${
              activeTab === tab.key
                ? "bg-primary/10 text-primary border border-primary/20"
                : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
            }`}
          >
            <tab.icon className="h-3.5 w-3.5" />
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === "devices" ? (
        <>
          {/* Header */}
          <div className="bg-card rounded-xl p-4 shadow-card mb-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Server className="h-5 w-5 text-primary" />
                <h2 className="text-sm font-semibold text-foreground">Configured Devices</h2>
                <span className="text-xs text-muted-foreground">{devices.length} device{devices.length !== 1 ? "s" : ""}</span>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant={data?.scheduling_active ? "destructive" : "outline"}
                  size="sm"
                  className="h-8 text-xs"
                  onClick={handleToggleSchedule}
                >
                  {data?.scheduling_active ? <><Pause className="h-3.5 w-3.5 mr-1.5" />Stop Scheduler</> : <><Play className="h-3.5 w-3.5 mr-1.5" />Start Scheduler</>}
                </Button>

                <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
                  <DialogTrigger asChild>
                    <Button size="sm" className="h-8 text-xs">
                      <Plus className="h-3.5 w-3.5 mr-1.5" />Add Device
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="bg-card border-border">
                    <DialogHeader>
                      <DialogTitle className="text-sm">Add New Device</DialogTitle>
                    </DialogHeader>
                    <div className="grid gap-4 py-2">
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-xs text-muted-foreground mb-1 block">Device Name</label>
                          <Input placeholder="pa-fw-01" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
                        </div>
                        <div>
                          <label className="text-xs text-muted-foreground mb-1 block">Host / IP</label>
                          <Input placeholder="192.168.1.1" value={form.host} onChange={e => setForm({ ...form, host: e.target.value })} />
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-xs text-muted-foreground mb-1 block">Vendor</label>
                          <Select value={form.vendor} onValueChange={v => setForm({ ...form, vendor: v })}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="paloalto">Palo Alto</SelectItem>
                              <SelectItem value="fortinet">Fortinet</SelectItem>
                              <SelectItem value="cisco">Cisco</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <label className="text-xs text-muted-foreground mb-1 block">Auth Type</label>
                          <Select value={form.auth_type} onValueChange={v => setForm({ ...form, auth_type: v })}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="apikey">API Key</SelectItem>
                              <SelectItem value="token">Bearer Token</SelectItem>
                              <SelectItem value="basic">Basic Auth</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="text-xs text-muted-foreground mb-1 block">Credentials Env Var</label>
                          <Input placeholder="PA_API_KEY" value={form.credentials_env_var} onChange={e => setForm({ ...form, credentials_env_var: e.target.value })} />
                        </div>
                        <div>
                          <label className="text-xs text-muted-foreground mb-1 block">Poll Interval (min)</label>
                          <Input type="number" min={1} value={form.poll_interval_minutes} onChange={e => setForm({ ...form, poll_interval_minutes: parseInt(e.target.value) || 15 })} />
                        </div>
                      </div>
                      <Button onClick={handleAddDevice} className="w-full mt-2">Add Device</Button>
                    </div>
                  </DialogContent>
                </Dialog>

                <button onClick={() => queryClient.invalidateQueries({ queryKey: ["collectorStatus"] })} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-smooth ml-1">
                  <RefreshCw className={`h-3 w-3 ${statusQ.isFetching ? "animate-spin" : ""}`} />
                </button>
              </div>
            </div>
          </div>

          {/* Device Table */}
          <div className="bg-card rounded-xl shadow-card overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  {["Name", "Vendor", "Host", "Interval", "Last Poll", "Status", "Rules", "Actions"].map(h => (
                    <TableHead key={h} className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{h}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center py-12 text-xs text-muted-foreground">
                      No devices configured. Click "Add Device" to get started.
                    </TableCell>
                  </TableRow>
                ) : (
                  devices.map(d => (
                    <TableRow key={d.name} className="border-border/50">
                      <TableCell className="text-xs font-medium text-foreground">{d.name}</TableCell>
                      <TableCell>{vendorBadge(d.vendor)}</TableCell>
                      <TableCell className="text-xs font-mono text-muted-foreground">{d.host}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{d.poll_interval_minutes}m</TableCell>
                      <TableCell className="text-xs font-mono text-muted-foreground">
                        {d.last_poll ? new Date(d.last_poll).toLocaleString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—"}
                      </TableCell>
                      <TableCell>{statusBadge(d)}</TableCell>
                      <TableCell className="text-xs tabular-nums text-foreground">{d.rules_collected}</TableCell>
                      <TableCell>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs"
                          disabled={polling === d.name}
                          onClick={() => handlePoll(d.name)}
                        >
                          {polling === d.name ? <RefreshCw className="h-3 w-3 animate-spin" /> : "Poll Now"}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {devices.some(d => d.last_error) && (
              <div className="px-4 py-3 border-t border-border">
                <p className="text-xs uppercase tracking-widest text-muted-foreground font-bold mb-2">Recent Errors</p>
                {devices.filter(d => d.last_error).map(d => (
                  <div key={d.name} className="text-xs text-destructive mb-1">
                    <span className="font-medium">{d.name}:</span> {d.last_error}
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      ) : (
        /* ── Config Backups Tab ── */
        <>
          <div className="bg-card rounded-xl p-4 shadow-card mb-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <HardDrive className="h-5 w-5 text-primary" />
                <h2 className="text-sm font-semibold text-foreground">Config Backups</h2>
              </div>
              <div className="flex items-center gap-2">
                <Select value={selectedDevice} onValueChange={setSelectedDevice}>
                  <SelectTrigger className="w-48 h-8 text-xs">
                    <SelectValue placeholder="Select device..." />
                  </SelectTrigger>
                  <SelectContent>
                    {devices.map(d => (
                      <SelectItem key={d.name} value={d.name}>{d.name} ({d.vendor})</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  size="sm"
                  className="h-8 text-xs"
                  disabled={!selectedDevice || backingUp}
                  onClick={handleBackupNow}
                >
                  {backingUp ? <RefreshCw className="h-3.5 w-3.5 animate-spin mr-1.5" /> : <HardDrive className="h-3.5 w-3.5 mr-1.5" />}
                  Backup Now
                </Button>
              </div>
            </div>
          </div>

          {!selectedDevice ? (
            <div className="bg-card rounded-xl p-16 shadow-card text-center">
              <HardDrive className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <p className="text-sm font-semibold text-foreground mb-2">Select a device</p>
              <p className="text-xs text-muted-foreground">Choose a device from the dropdown to view its backup history.</p>
            </div>
          ) : (
            <>
              {/* Compare controls */}
              {backups.length >= 2 && (
                <div className="bg-card rounded-xl p-4 shadow-card mb-6">
                  <div className="flex items-center gap-3">
                    <GitCompare className="h-4 w-4 text-primary" />
                    <span className="text-xs font-medium text-foreground">Compare Versions</span>
                    <Select value={compareA} onValueChange={setCompareA}>
                      <SelectTrigger className="w-40 h-7 text-xs">
                        <SelectValue placeholder="Version A..." />
                      </SelectTrigger>
                      <SelectContent>
                        {backups.map(b => (
                          <SelectItem key={b.id} value={b.id}>v{b.version_number} — {b.file_hash.slice(0, 8)}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <span className="text-xs text-muted-foreground">vs</span>
                    <Select value={compareB} onValueChange={setCompareB}>
                      <SelectTrigger className="w-40 h-7 text-xs">
                        <SelectValue placeholder="Version B..." />
                      </SelectTrigger>
                      <SelectContent>
                        {backups.map(b => (
                          <SelectItem key={b.id} value={b.id}>v{b.version_number} — {b.file_hash.slice(0, 8)}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button size="sm" className="h-7 text-xs" onClick={handleCompare} disabled={!compareA || !compareB || compareA === compareB}>
                      <GitCompare className="h-3 w-3 mr-1" />Compare
                    </Button>
                  </div>
                </div>
              )}

              {/* Backup History Table */}
              <div className="bg-card rounded-xl shadow-card overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border hover:bg-transparent">
                      {["Version", "Date", "Hash", "Size", "Change", "Summary", "Actions"].map(h => (
                        <TableHead key={h} className="text-xs uppercase tracking-widest text-muted-foreground font-bold">{h}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {backups.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={7} className="text-center py-12 text-xs text-muted-foreground">
                          No backups yet. Click "Backup Now" to create the first backup.
                        </TableCell>
                      </TableRow>
                    ) : (
                      backups.map(b => (
                        <TableRow key={b.id} className="border-border/50">
                          <TableCell className="text-xs font-bold text-primary tabular-nums">v{b.version_number}</TableCell>
                          <TableCell className="text-xs font-mono text-muted-foreground">
                            {new Date(b.timestamp).toLocaleString("en-GB", { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                          </TableCell>
                          <TableCell className="text-xs font-mono text-muted-foreground">{b.file_hash.slice(0, 12)}...</TableCell>
                          <TableCell className="text-xs text-muted-foreground tabular-nums">{(b.file_size / 1024).toFixed(1)} KB</TableCell>
                          <TableCell>
                            {b.change_detected ? (
                              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-warning/20 text-warning">Changed</span>
                            ) : (
                              <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-secondary text-muted-foreground">No Change</span>
                            )}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground max-w-[200px] truncate">{b.change_summary || "—"}</TableCell>
                          <TableCell>
                            <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={() => downloadBackup(b.id)}>
                              <Download className="h-3 w-3 mr-1" />Download
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </>
          )}

          {/* Diff Modal */}
          <Dialog open={diffOpen} onOpenChange={setDiffOpen}>
            <DialogContent className="bg-card border-border max-w-4xl max-h-[80vh] overflow-hidden">
              <DialogHeader>
                <DialogTitle className="text-sm flex items-center gap-3">
                  Config Diff: {diffData?.a} vs {diffData?.b}
                  <span className="text-xs font-normal bg-green-900/30 text-green-400 px-2 py-0.5 rounded">+{diffData?.additions ?? 0}</span>
                  <span className="text-xs font-normal bg-red-900/30 text-red-400 px-2 py-0.5 rounded">-{diffData?.deletions ?? 0}</span>
                </DialogTitle>
              </DialogHeader>
              <div className="overflow-auto max-h-[60vh] rounded-lg border border-border">
                <pre className="text-xs font-mono leading-relaxed p-4">
                  {diffData?.diff ? (
                    diffData.diff.split("\n").map((line, i) => (
                      <div
                        key={i}
                        className={
                          line.startsWith("+") && !line.startsWith("+++")
                            ? "bg-green-900/30 text-green-300"
                            : line.startsWith("-") && !line.startsWith("---")
                            ? "bg-red-900/30 text-red-300"
                            : line.startsWith("@@")
                            ? "text-primary"
                            : "text-muted-foreground"
                        }
                      >
                        {line}
                      </div>
                    ))
                  ) : (
                    <span className="text-muted-foreground">No differences found</span>
                  )}
                </pre>
              </div>
            </DialogContent>
          </Dialog>
        </>
      )}
    </AppLayout>
  );
}
