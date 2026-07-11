/**
 * FirewallTopology.tsx — Interactive D3 force-directed network topology map.
 * Supports firewalls, switches, routers, and servers with device-specific detail panels.
 */

import { useState, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { Network, Search, Maximize2, Shield, Server as ServerIcon, Router, Layers, Cable } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getFullTopology, getFirewallTopology, type TopoNode, type TopoEdge } from "@/lib/api";
import * as d3Force from "d3-force";
import * as d3Zoom from "d3-zoom";
import * as d3Selection from "d3-selection";
import * as d3Drag from "d3-drag";

function zoneColor(zone: string): string {
  if (!zone) return "hsl(240,5%,40%)";
  let hash = 0;
  for (let i = 0; i < zone.length; i++) hash = zone.charCodeAt(i) + ((hash << 5) - hash);
  const h = Math.abs(hash % 360);
  return `hsl(${h},65%,55%)`;
}

// Device type → shape path (SVG d attribute)
const SHAPE_PATHS: Record<string, string> = {
  firewall: "M-14,-14 L14,-14 L14,14 L-14,14 Z",                        // square (shield)
  router:   "M0,-16 L16,0 L0,16 L-16,0 Z",                              // diamond
  switch:   "M-14,-8 L14,-8 L14,8 L-14,8 Z",                            // wide rect (horizontal)
  server:   "M-8,-14 L8,-14 L8,14 L-8,14 Z",                            // tall rect
  endpoint: "M0,-10 A10,10 0 1,1 0,10 A10,10 0 1,1 0,-10 Z",            // circle
};

// Device type label inside the shape
const SHAPE_LABELS: Record<string, string> = {
  firewall: "FW",
  router:   "RT",
  switch:   "SW",
  server:   "SV",
  endpoint: "EP",
};

interface SimNode extends TopoNode, d3Force.SimulationNodeDatum {}

interface SimEdge extends d3Force.SimulationLinkDatum<SimNode> {
  source: string | SimNode;
  target: string | SimNode;
  same_zone: boolean;
  trust_level: string;
  link_type?: string;
}

// After the force simulation initialises, edge endpoints are node objects
const endpoint = (v: string | SimNode) => v as SimNode;

export default function FirewallTopology() {
  const svgRef = useRef<SVGSVGElement>(null);
  const [zoneFilter, setZoneFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [search, setSearch] = useState("");
  const [selectedNode, setSelectedNode] = useState<SimNode | null>(null);

  const topoQ = useQuery({
    queryKey: ["fullTopology"],
    queryFn: () => getFullTopology(),
    staleTime: 60_000,
  });

  const legacyQ = useQuery({
    queryKey: ["fwTopology"],
    queryFn: getFirewallTopology,
    staleTime: 60_000,
  });

  const rawNodes = topoQ.data?.nodes ?? [];
  const rawEdges = topoQ.data?.edges ?? [];
  const zones = topoQ.data?.zones ?? [];
  const deviceTypes = topoQ.data?.device_types ?? [];
  const legacy = legacyQ.data;

  // Device type counts
  const typeCounts: Record<string, number> = {};
  const uniqueDevices = new Set<string>();
  rawNodes.forEach(n => {
    if (!uniqueDevices.has(n.device_name)) {
      uniqueDevices.add(n.device_name);
      typeCounts[n.device_type] = (typeCounts[n.device_type] || 0) + 1;
    }
  });

  // Filter nodes
  const filteredNodes = rawNodes.filter(n => {
    if (zoneFilter && n.zone !== zoneFilter) return false;
    if (typeFilter && n.device_type !== typeFilter) return false;
    if (search && !n.device_name.toLowerCase().includes(search.toLowerCase()) && !n.ip_address.includes(search)) return false;
    return true;
  });
  const nodeNames = new Set(filteredNodes.map(n => n.device_name));
  const filteredEdges = rawEdges.filter(e => nodeNames.has(e.source) && nodeNames.has(e.target));

  // D3 simulation
  useEffect(() => {
    if (!svgRef.current || filteredNodes.length === 0) return;

    const svg = d3Selection.select(svgRef.current);
    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight || 550;

    svg.selectAll("*").remove();

    const g = svg.append("g");

    // Zoom
    const zoomBehavior = d3Zoom.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoomBehavior);

    // Clone data for simulation
    const simNodes: SimNode[] = filteredNodes.map(n => ({ ...n }));
    const simEdges: SimEdge[] = filteredEdges.map(e => ({ ...e }));

    const simulation = d3Force.forceSimulation<SimNode>(simNodes)
      .force("link", d3Force.forceLink<SimNode, SimEdge>(simEdges).id(d => d.device_name).distance(120))
      .force("charge", d3Force.forceManyBody().strength(-250))
      .force("center", d3Force.forceCenter(width / 2, height / 2))
      .force("collision", d3Force.forceCollide(35))
      .alphaDecay(0.02);

    // Edge color by link type
    const edgeColor = (d: SimEdge) => {
      if (d.trust_level === "low") return "hsl(0,70%,50%)";
      if (d.trust_level === "high") return "hsl(142,70%,45%)";
      return "hsl(38,92%,50%)";
    };

    // Edges
    const links = g.append("g").selectAll("line")
      .data(simEdges)
      .enter().append("line")
      .attr("stroke", edgeColor)
      .attr("stroke-width", (d: SimEdge) => d.link_type === "trunk" ? 2.5 : 1.5)
      .attr("stroke-dasharray", (d: SimEdge) => d.same_zone ? "none" : "6,4")
      .attr("opacity", 0.5);

    // Edge labels for link type
    const edgeLabels = g.append("g").selectAll("text")
      .data(simEdges.filter(e => e.link_type && e.link_type !== "routed"))
      .enter().append("text")
      .text((d: SimEdge) => d.link_type || "")
      .attr("text-anchor", "middle")
      .attr("fill", "hsl(240,5%,50%)")
      .attr("font-size", "7px")
      .attr("font-family", "monospace")
      .attr("opacity", 0.7);

    // Nodes
    const nodeGroups = g.append("g").selectAll("g")
      .data(simNodes)
      .enter().append("g")
      .attr("cursor", "pointer")
      .on("click", (_event, d) => setSelectedNode(d));

    // Node shape with glow on hover
    nodeGroups.append("path")
      .attr("d", (d: SimNode) => SHAPE_PATHS[d.device_type] || SHAPE_PATHS.server)
      .attr("fill", (d: SimNode) => zoneColor(d.zone))
      .attr("stroke", (d: SimNode) => d.is_entry_point ? "hsl(0,70%,60%)" : "hsl(240,5%,25%)")
      .attr("stroke-width", (d: SimNode) => d.is_entry_point ? 2.5 : 1)
      .attr("opacity", 0.9)
      .on("mouseenter", function () { d3Selection.select(this).attr("opacity", 1).attr("stroke-width", 2.5); })
      .on("mouseleave", function (_event, d) { d3Selection.select(this).attr("opacity", 0.9).attr("stroke-width", d.is_entry_point ? 2.5 : 1); });

    // Device type abbreviation inside shape
    nodeGroups.append("text")
      .text((d: SimNode) => SHAPE_LABELS[d.device_type] || "?")
      .attr("text-anchor", "middle")
      .attr("dy", "0.35em")
      .attr("fill", "white")
      .attr("font-size", "8px")
      .attr("font-weight", "bold")
      .attr("font-family", "monospace")
      .attr("pointer-events", "none");

    // Node label
    nodeGroups.append("text")
      .text((d: SimNode) => d.device_name.length > 18 ? d.device_name.slice(0, 17) + "\u2026" : d.device_name)
      .attr("text-anchor", "middle")
      .attr("dy", 26)
      .attr("fill", "hsl(240,5%,70%)")
      .attr("font-size", "9px")
      .attr("font-family", "monospace");

    // Zone label (smaller, below device name)
    nodeGroups.append("text")
      .text((d: SimNode) => d.zone || "")
      .attr("text-anchor", "middle")
      .attr("dy", 36)
      .attr("fill", (d: SimNode) => zoneColor(d.zone))
      .attr("font-size", "7px")
      .attr("font-family", "monospace")
      .attr("opacity", 0.7);

    // Tooltip
    nodeGroups.append("title")
      .text((d: SimNode) => `${d.device_name}\n${d.device_type} | ${d.zone}\nIP: ${d.ip_address}\nRules: ${d.rules_count}`);

    // Drag
    nodeGroups.call(
      d3Drag.drag<SVGGElement, SimNode>()
        .on("start", (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on("end", (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
    );

    simulation.on("tick", () => {
      links
        .attr("x1", d => endpoint(d.source).x ?? 0)
        .attr("y1", d => endpoint(d.source).y ?? 0)
        .attr("x2", d => endpoint(d.target).x ?? 0)
        .attr("y2", d => endpoint(d.target).y ?? 0);
      edgeLabels
        .attr("x", d => ((endpoint(d.source).x || 0) + (endpoint(d.target).x || 0)) / 2)
        .attr("y", d => ((endpoint(d.source).y || 0) + (endpoint(d.target).y || 0)) / 2 - 4);
      nodeGroups.attr("transform", d => `translate(${d.x ?? 0},${d.y ?? 0})`);
    });

    return () => { simulation.stop(); };
  }, [filteredNodes, filteredEdges]);

  const handleFit = () => {
    if (!svgRef.current) return;
    const svg = d3Selection.select(svgRef.current);
    svg.transition().duration(500).call(
      d3Zoom.zoom<SVGSVGElement, unknown>().transform,
      d3Zoom.zoomIdentity
    );
  };

  return (
    <AppLayout title="Network Topology" breadcrumb={["Network Topology"]}>
      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
        <div className="bg-card rounded-xl p-3 shadow-card">
          <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Total Devices</span>
          <p className="text-2xl font-bold tabular-nums text-foreground mt-1">{uniqueDevices.size}</p>
        </div>
        <div className="bg-card rounded-xl p-3 shadow-card">
          <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold flex items-center gap-1"><Shield className="h-3 w-3" /> Firewalls</span>
          <p className="text-2xl font-bold tabular-nums text-primary mt-1">{typeCounts.firewall || 0}</p>
        </div>
        <div className="bg-card rounded-xl p-3 shadow-card">
          <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold flex items-center gap-1"><Router className="h-3 w-3" /> Routers</span>
          <p className="text-2xl font-bold tabular-nums text-warning mt-1">{typeCounts.router || 0}</p>
        </div>
        <div className="bg-card rounded-xl p-3 shadow-card">
          <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold flex items-center gap-1"><Layers className="h-3 w-3" /> Switches</span>
          <p className="text-2xl font-bold tabular-nums text-info mt-1">{typeCounts.switch || 0}</p>
        </div>
        <div className="bg-card rounded-xl p-3 shadow-card">
          <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Zones</span>
          <p className="text-2xl font-bold tabular-nums text-success mt-1">{zones.length}</p>
        </div>
        <div className="bg-card rounded-xl p-3 shadow-card">
          <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold flex items-center gap-1"><Cable className="h-3 w-3" /> Links</span>
          <p className="text-2xl font-bold tabular-nums text-warning mt-1">{rawEdges.length}</p>
        </div>
        <div className="bg-card rounded-xl p-3 shadow-card">
          <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Multi-Device</span>
          <p className="text-lg font-bold mt-1">{legacy?.chain_detected ? <span className="text-warning">Yes</span> : <span className="text-muted-foreground">No</span>}</p>
        </div>
      </div>

      {/* Chain details banner */}
      {legacy?.chain_details && (
        <div className="bg-card/60 border border-border rounded-xl px-4 py-2 mb-4 text-xs text-muted-foreground">
          <Network className="h-3.5 w-3.5 inline mr-2 text-primary" />{legacy.chain_details}
        </div>
      )}

      {/* Controls */}
      <div className="bg-card rounded-xl p-4 shadow-card mb-6 flex items-center gap-3 flex-wrap">
        <Network className="h-4 w-4 text-primary" />
        <Select value={zoneFilter || "__all__"} onValueChange={v => setZoneFilter(v === "__all__" ? "" : v)}>
          <SelectTrigger className="w-40 h-8 text-xs"><SelectValue placeholder="All Zones" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">All Zones</SelectItem>
            {zones.map(z => <SelectItem key={z} value={z}>{z}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={typeFilter || "__all__"} onValueChange={v => setTypeFilter(v === "__all__" ? "" : v)}>
          <SelectTrigger className="w-36 h-8 text-xs"><SelectValue placeholder="All Types" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="__all__">All Types</SelectItem>
            {deviceTypes.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
          </SelectContent>
        </Select>
        <div className="relative flex-1 max-w-xs">
          <Search className="h-3.5 w-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search devices..." className="h-8 pl-9 text-xs" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <Button variant="outline" size="sm" className="h-8 text-xs" onClick={handleFit}>
          <Maximize2 className="h-3.5 w-3.5 mr-1" />Fit
        </Button>
        {/* Legend */}
        <div className="flex items-center gap-3 ml-auto text-xs text-muted-foreground flex-wrap">
          <span className="flex items-center gap-1"><span className="w-3 h-3 border border-muted-foreground inline-block" /> FW</span>
          <span className="flex items-center gap-1"><span className="w-3 h-3 border border-muted-foreground inline-block rotate-45 scale-75" /> RT</span>
          <span className="flex items-center gap-1"><span className="w-4 h-2 border border-muted-foreground inline-block" /> SW</span>
          <span className="mx-1 text-border">|</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-success inline-block" /> High</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-warning inline-block" /> Medium</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-destructive inline-block" /> Low</span>
          <span className="flex items-center gap-1"><span className="w-4 border-t border-dashed border-muted-foreground inline-block" /> Cross-zone</span>
        </div>
      </div>

      {/* Map + Detail Panel */}
      <div className="flex gap-4">
        <div className="flex-1 bg-card rounded-xl shadow-card overflow-hidden" style={{ minHeight: 550 }}>
          {filteredNodes.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs text-muted-foreground">
              {topoQ.isLoading ? "Loading topology..." : "No devices found. Upload a config to populate the topology."}
            </div>
          ) : (
            <svg ref={svgRef} width="100%" height="550" className="bg-background" />
          )}
        </div>

        {/* Detail Sidebar */}
        {selectedNode && (
          <div className="w-80 bg-card rounded-xl p-4 shadow-card overflow-y-auto" style={{ maxHeight: 550 }}>
            <div className="flex items-center gap-2 mb-3">
              {selectedNode.device_type === "firewall" && <Shield className="h-4 w-4 text-primary" />}
              {selectedNode.device_type === "router" && <Router className="h-4 w-4 text-warning" />}
              {selectedNode.device_type === "switch" && <Layers className="h-4 w-4 text-info" />}
              {selectedNode.device_type === "server" && <ServerIcon className="h-4 w-4 text-success" />}
              <h3 className="text-sm font-semibold text-foreground truncate">{selectedNode.device_name}</h3>
            </div>

            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between"><span className="text-muted-foreground">Type</span><span className="text-foreground capitalize">{selectedNode.device_type}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Zone</span><span className="font-medium" style={{ color: zoneColor(selectedNode.zone) }}>{selectedNode.zone || "\u2014"}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">IP</span><span className="font-mono text-foreground">{selectedNode.ip_address || "\u2014"}</span></div>
              {selectedNode.subnet && <div className="flex justify-between"><span className="text-muted-foreground">Subnet</span><span className="font-mono text-foreground">{selectedNode.subnet}</span></div>}
              <div className="flex justify-between"><span className="text-muted-foreground">Rules / ACLs</span><span className="text-foreground">{selectedNode.rules_count}</span></div>
              <div className="flex justify-between"><span className="text-muted-foreground">Entry Point</span><span className={selectedNode.is_entry_point ? "text-warning" : "text-muted-foreground"}>{selectedNode.is_entry_point ? "Yes" : "No"}</span></div>
              {selectedNode.link_type && <div className="flex justify-between"><span className="text-muted-foreground">Link Type</span><span className="text-foreground capitalize">{selectedNode.link_type}</span></div>}

              {/* Switch-specific section */}
              {selectedNode.device_type === "switch" && (
                <>
                  {selectedNode.stp_mode && (
                    <div className="border-t border-border pt-2 mt-2">
                      <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Spanning Tree</span>
                      <div className="flex justify-between mt-1"><span className="text-muted-foreground">Mode</span><span className="text-foreground uppercase">{selectedNode.stp_mode}</span></div>
                      {selectedNode.stp_root_for?.length > 0 && <div className="flex justify-between"><span className="text-muted-foreground">Root Bridge</span><span className="text-success">VLANs {selectedNode.stp_root_for.join(", ")}</span></div>}
                    </div>
                  )}
                  {selectedNode.vlans?.length > 0 && (
                    <div className="border-t border-border pt-2 mt-2">
                      <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">VLANs ({selectedNode.vlans.length})</span>
                      <div className="mt-1 space-y-0.5 max-h-24 overflow-y-auto">
                        {selectedNode.vlans.map(v => (
                          <div key={v.id} className="flex justify-between"><span className="text-muted-foreground">VLAN {v.id}</span><span className="text-foreground">{v.name}</span></div>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedNode.trunk_ports?.length > 0 && (
                    <div className="border-t border-border pt-2 mt-2">
                      <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Trunk Ports ({selectedNode.trunk_ports.length})</span>
                      <div className="mt-1 space-y-0.5">
                        {selectedNode.trunk_ports.map((p, i) => (
                          <div key={i} className="text-foreground font-mono">{p.port}{p.neighbor ? ` \u2192 ${p.neighbor}` : ""}</div>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedNode.port_security?.length > 0 && (
                    <div className="border-t border-border pt-2 mt-2">
                      <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Port Security ({selectedNode.port_security.length})</span>
                      <div className="mt-1 space-y-0.5">
                        {selectedNode.port_security.map((ps, i) => (
                          <div key={i} className="flex justify-between"><span className="text-muted-foreground font-mono">{ps.port}</span><span className="text-foreground">{ps.violation_mode} (max {ps.max_mac})</span></div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* Router-specific section */}
              {selectedNode.device_type === "router" && (
                <>
                  {selectedNode.routing_protocol && (
                    <div className="border-t border-border pt-2 mt-2">
                      <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Routing</span>
                      <div className="flex justify-between mt-1"><span className="text-muted-foreground">Protocol</span><span className="text-foreground uppercase">{selectedNode.routing_protocol}</span></div>
                      {selectedNode.ospf_area && <div className="flex justify-between"><span className="text-muted-foreground">OSPF Area</span><span className="text-foreground">{selectedNode.ospf_area}</span></div>}
                      {selectedNode.bgp_asn && <div className="flex justify-between"><span className="text-muted-foreground">BGP ASN</span><span className="text-foreground">{selectedNode.bgp_asn}</span></div>}
                    </div>
                  )}
                  {selectedNode.bgp_neighbors?.length > 0 && (
                    <div className="border-t border-border pt-2 mt-2">
                      <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">BGP Neighbors ({selectedNode.bgp_neighbors.length})</span>
                      <div className="mt-1 space-y-0.5">
                        {selectedNode.bgp_neighbors.map((n, i) => (
                          <div key={i} className="flex justify-between"><span className="text-muted-foreground font-mono">{n.neighbor_ip}</span><span className="text-foreground">AS {n.remote_asn}</span></div>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedNode.nat_rules?.length > 0 && (
                    <div className="border-t border-border pt-2 mt-2">
                      <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">NAT Rules ({selectedNode.nat_rules.length})</span>
                      <div className="mt-1 space-y-0.5">
                        {selectedNode.nat_rules.map((nr, i) => (
                          <div key={i} className="text-foreground text-xs">{nr.type}: {nr.inside_ip || nr.acl} \u2192 {nr.outside_ip || nr.interface || nr.pool}</div>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedNode.interfaces?.length > 0 && (
                    <div className="border-t border-border pt-2 mt-2">
                      <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Interfaces ({selectedNode.interfaces.length})</span>
                      <div className="mt-1 space-y-0.5 max-h-32 overflow-y-auto">
                        {selectedNode.interfaces.map((intf, i) => (
                          <div key={i} className="flex justify-between gap-2">
                            <span className="text-muted-foreground font-mono truncate">{intf.name}</span>
                            <span className="text-foreground font-mono">{intf.ip || "\u2014"}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* Health metrics */}
              {selectedNode.health && (
                <>
                  <div className="border-t border-border pt-2 mt-2">
                    <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Health</span>
                  </div>
                  <div className="flex justify-between"><span className="text-muted-foreground">CPU</span><span className="text-foreground">{selectedNode.health.cpu}%</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Memory</span><span className="text-foreground">{selectedNode.health.memory}%</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Sessions</span><span className="text-foreground">{selectedNode.health.sessions}</span></div>
                </>
              )}

              {/* Connected to */}
              {selectedNode.connected_to?.length > 0 && (
                <>
                  <div className="border-t border-border pt-2 mt-2">
                    <span className="text-xs uppercase tracking-widest text-muted-foreground font-bold">Connected To</span>
                  </div>
                  {selectedNode.connected_to.map((c: string) => (
                    <p key={c} className="text-foreground font-mono text-xs">{c}</p>
                  ))}
                </>
              )}
            </div>
            <Button variant="ghost" size="sm" className="w-full mt-3 h-7 text-xs" onClick={() => setSelectedNode(null)}>Close</Button>
          </div>
        )}
      </div>
    </AppLayout>
  );
}
