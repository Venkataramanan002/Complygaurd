import { NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  LayoutDashboard, Activity, ShieldAlert, BarChart3, Route, Wrench, Shield, User, LogOut, Network, Server, ClipboardCheck, ShieldCheck, Radar, GitPullRequest, Bell, Lock, FileText, Plug
} from "lucide-react";

const navItems = [
  { title: "Dashboard", path: "/", icon: LayoutDashboard },
  { title: "Live Traffic", path: "/live-traffic", icon: Activity },
  { title: "Traffic Analysis", path: "/traffic-analysis", icon: BarChart3 },
  { title: "Threats", path: "/threats", icon: ShieldAlert },
  { title: "Analysis", path: "/analysis", icon: BarChart3 },
  { title: "Attack Paths", path: "/attack-paths", icon: Route },
  { title: "Remediation", path: "/remediation", icon: Wrench },
  { title: "Rule Lifecycle", path: "/rule-lifecycle", icon: ClipboardCheck },
  { title: "Compliance", path: "/compliance", icon: ShieldCheck },
  { title: "Threat Intel", path: "/threat-intel", icon: Radar },
  { title: "Changes", path: "/changes", icon: GitPullRequest },
  { title: "Alerts", path: "/alerts", icon: Bell },
  { title: "Hardening", path: "/hardening", icon: Lock },
  { title: "Reports", path: "/reports", icon: FileText },
  { title: "Integrations", path: "/integrations", icon: Plug },
  { title: "FW Topology", path: "/firewall-topology", icon: Network },
  { title: "Devices", path: "/devices", icon: Server },
];

interface UserProfile {
  username: string;
  email: string;
  role: string;
}

async function fetchCurrentUser(): Promise<UserProfile> {
  const res = await fetch("/api/auth/me");
  if (!res.ok) return { username: "Analyst", email: "", role: "viewer" };
  return res.json();
}

export function AppSidebar() {
  const location = useLocation();
  const { data: user } = useQuery({
    queryKey: ["currentUser"],
    queryFn: fetchCurrentUser,
    staleTime: 5 * 60_000,
  });

  const displayName = user?.username && user.username !== "anonymous"
    ? user.username
    : "Analyst";
  const displayEmail = user?.email || "";
  const displayRole = user?.role || "viewer";

  return (
    <aside className="w-60 min-h-screen bg-card shadow-sidebar flex flex-col fixed left-0 top-0 z-40">
      {/* Logo */}
      <div className="h-14 flex items-center gap-2.5 px-5 border-b border-border">
        <Shield className="h-5 w-5 text-primary" />
        <span className="text-sm font-semibold tracking-tight text-foreground">
          Fortress Lens
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium tracking-tight transition-smooth ${
                isActive
                  ? "sidebar-active"
                  : "text-muted-foreground hover:text-foreground hover:bg-secondary/50 hover:translate-x-0.5"
              }`}
            >
              <item.icon className="h-4 w-4" />
              <span>{item.title}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom section */}
      <div className="p-3 border-t border-border space-y-1">
        <div className="flex items-center gap-3 px-3 py-2 rounded-lg">
          <div className="h-7 w-7 rounded-full bg-primary/20 flex items-center justify-center">
            <User className="h-3.5 w-3.5 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-foreground truncate capitalize">{displayName}</p>
            {displayEmail ? (
              <p className="text-xs text-muted-foreground truncate">{displayEmail}</p>
            ) : (
              <p className="text-xs text-muted-foreground truncate capitalize">{displayRole}</p>
            )}
          </div>
          <LogOut className="h-3.5 w-3.5 text-muted-foreground cursor-pointer hover:text-foreground transition-smooth" />
        </div>
      </div>
    </aside>
  );
}
