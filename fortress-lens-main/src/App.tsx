import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Index from "./pages/Index.tsx";
import LiveTraffic from "./pages/LiveTraffic.tsx";
import Threats from "./pages/Threats.tsx";
import Analysis from "./pages/Analysis.tsx";
import AttackPaths from "./pages/AttackPaths.tsx";
import Remediation from "./pages/Remediation.tsx";
import FirewallTopology from "./pages/FirewallTopology.tsx";
import Devices from "./pages/Devices.tsx";
import RuleLifecycle from "./pages/RuleLifecycle.tsx";
import CompliancePage from "./pages/Compliance.tsx";
import ThreatIntel from "./pages/ThreatIntel.tsx";
import Changes from "./pages/Changes.tsx";
import AlertsPage from "./pages/Alerts.tsx";
import TrafficAnalysis from "./pages/TrafficAnalysis.tsx";
import Hardening from "./pages/Hardening.tsx";
import Reports from "./pages/Reports.tsx";
import Integrations from "./pages/Integrations.tsx";
import NotFound from "./pages/NotFound.tsx";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});

class AppErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (this.state.error) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background text-foreground p-8">
          <div className="max-w-lg space-y-3">
            <p className="text-destructive font-semibold text-sm">Something went wrong rendering this page.</p>
            <pre className="text-xs text-muted-foreground whitespace-pre-wrap bg-card rounded-xl p-4 border border-border">
              {(this.state.error as Error).message}
            </pre>
            <button
              onClick={() => this.setState({ error: null })}
              className="text-xs text-primary underline"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const App = () => (
  <AppErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={300}>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/live-traffic" element={<LiveTraffic />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/analysis" element={<Analysis />} />
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/remediation" element={<Remediation />} />
            <Route path="/firewall-topology" element={<FirewallTopology />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/rule-lifecycle" element={<RuleLifecycle />} />
            <Route path="/compliance" element={<CompliancePage />} />
            <Route path="/threat-intel" element={<ThreatIntel />} />
            <Route path="/changes" element={<Changes />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/traffic-analysis" element={<TrafficAnalysis />} />
            <Route path="/hardening" element={<Hardening />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/integrations" element={<Integrations />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </AppErrorBoundary>
);

export default App;
