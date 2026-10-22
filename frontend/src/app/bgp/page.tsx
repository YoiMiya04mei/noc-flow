"use client";

import React, { useEffect, useState } from "react";
import {
  Network,
  ArrowUpRight,
  Search,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Activity,
  Play,
  RefreshCw,
  Plus,
  Send,
  Zap,
  Clock,
  Shield,
  Layers,
  Server,
  Crosshair,
  RotateCcw,
  XCircle,
  CheckCircle,
  Info,
  ShieldCheck,
  ShieldAlert,
  Cpu,
  Terminal,
  ArrowRight,
  FileText,
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { api } from "@/lib/api";

export default function BGPVisibilityPage() {
  const [activeTab, setActiveTab] = useState<"visibility" | "probing" | "lab">("visibility");
  const [peers, setPeers] = useState<any[]>([]);
  const [routes, setRoutes] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [bmpStatus, setBmpStatus] = useState<any>(null);
  const [probeTargets, setProbeTargets] = useState<any[]>([]);
  const [probeWorkerStatus, setProbeWorkerStatus] = useState<any>(null);
  const [egressCaps, setEgressCaps] = useState<any>(null);
  const [probeResults, setProbeResults] = useState<any[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);

  // Isolated BGP Lab State (Phase 6)
  const [labStatus, setLabStatus] = useState<any>(null);
  const [labHistory, setLabHistory] = useState<any[]>([]);
  const [selectedLabRun, setSelectedLabRun] = useState<any>(null);
  const [isLabRunning, setIsLabRunning] = useState(false);
  const [labPrefix, setLabPrefix] = useState("10.100.1.0/24");
  const [labSpeaker, setLabSpeaker] = useState("bgp-speaker-1");
  const [labChangeRequestId, setLabChangeRequestId] = useState<string>("");
  const [labActionMessage, setLabActionMessage] = useState<{ type: "success" | "error" | "info"; text: string } | null>(null);
  const [showRunDetailModal, setShowRunDetailModal] = useState(false);
  const [showManualReviewModal, setShowManualReviewModal] = useState(false);
  const [manualReviewNotes, setManualReviewNotes] = useState("");

  const [filterPrefix, setFilterPrefix] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isSimulatingBmp, setIsSimulatingBmp] = useState(false);
  const [isExecutingProbe, setIsExecutingProbe] = useState(false);
  const [showAddTargetModal, setShowAddTargetModal] = useState(false);
  const [newTarget, setNewTarget] = useState({
    target_ip: "1.1.1.1",
    target_name: "Cloudflare Anycast DNS",
    probe_type: "icmp",
    port: 80,
    egress_interface: "",
    source_ip: "",
    interval_seconds: 15,
    timeout_ms: 2000,
  });

  useEffect(() => {
    if (typeof window !== "undefined") {
      const urlParams = new URLSearchParams(window.location.search);
      const tabParam = urlParams.get("tab");
      const prefixParam = urlParams.get("prefix");
      const crParam = urlParams.get("cr");
      if (tabParam === "lab") {
        setActiveTab("lab");
      }
      if (prefixParam) {
        setLabPrefix(prefixParam);
      }
      if (crParam) {
        setLabChangeRequestId(crParam);
      }
    }
  }, []);

  const loadAllData = async () => {
    try {
      const [
        peersRes,
        routesRes,
        eventsRes,
        bmpRes,
        targetsRes,
        workerRes,
        egressRes,
        labStatusRes,
        labHistoryRes,
      ] = await Promise.allSettled([
        api.getBGPPeers(),
        api.getBGPRoutes(),
        api.getBGPRouteEvents(30),
        api.getBMPStatus(),
        api.getProbeTargets(),
        api.getProbeWorkerStatus(),
        api.getEgressCapabilities(),
        api.getLabStatus(),
        api.getLabHistory(),
      ]);

      if (peersRes.status === "fulfilled") setPeers(peersRes.value);
      if (routesRes.status === "fulfilled") setRoutes(routesRes.value);
      if (eventsRes.status === "fulfilled") setEvents(eventsRes.value);
      if (bmpRes.status === "fulfilled") setBmpStatus(bmpRes.value);
      if (targetsRes.status === "fulfilled") {
        setProbeTargets(targetsRes.value);
        if (targetsRes.value.length > 0 && selectedTargetId === null) {
          setSelectedTargetId(targetsRes.value[0].id);
        }
      }
      if (workerRes.status === "fulfilled") setProbeWorkerStatus(workerRes.value);
      if (egressRes.status === "fulfilled") setEgressCaps(egressRes.value);
      if (labStatusRes.status === "fulfilled") setLabStatus(labStatusRes.value);
      if (labHistoryRes.status === "fulfilled") setLabHistory(labHistoryRes.value);
    } catch (err) {
      console.error("Failed to load BGP telemetry", err);
    } finally {
      setIsLoading(false);
    }
  };

  const loadLabData = async () => {
    try {
      const [statusRes, historyRes] = await Promise.allSettled([
        api.getLabStatus(),
        api.getLabHistory(),
      ]);
      if (statusRes.status === "fulfilled") setLabStatus(statusRes.value);
      if (historyRes.status === "fulfilled") setLabHistory(historyRes.value);
    } catch (err) {
      console.error("Failed to load lab telemetry", err);
    }
  };

  // Load results for selected target
  useEffect(() => {
    if (selectedTargetId !== null) {
      api
        .getProbeResults(selectedTargetId, 30)
        .then((res) => {
          const chartData = res.map((r: any) => ({
            time: new Date(r.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            }),
            latency_ms: r.latency_ms,
            loss_percent: r.loss_percent,
            jitter_ms: r.jitter_ms,
          }));
          setProbeResults(chartData.reverse());
        })
        .catch((e) => console.error("Failed to load probe results", e));
    }
  }, [selectedTargetId]);

  // Initial load and 15s refresh cycle
  useEffect(() => {
    loadAllData();
    const timer = setInterval(loadAllData, 15000);
    return () => clearInterval(timer);
  }, []);

  const handleSimulateBmp = async (msgType: string) => {
    setIsSimulatingBmp(true);
    try {
      await api.simulateBMPPacket({
        message_type: msgType,
        peer_ip: "198.51.100.1",
        peer_asn: 7713,
        prefix: "103.150.88.0/24",
        next_hop: "198.51.100.1",
        as_path: "7713 136052",
        communities: "7713:100",
        is_withdraw: msgType === "withdraw",
      });
      await loadAllData();
    } catch (err) {
      console.error("BMP simulation error", err);
    } finally {
      setIsSimulatingBmp(false);
    }
  };

  const handleExecuteProbeNow = async (targetId?: number) => {
    setIsExecutingProbe(true);
    try {
      await api.executeProbeNow(targetId);
      await loadAllData();
      if (selectedTargetId) {
        const res = await api.getProbeResults(selectedTargetId, 30);
        setProbeResults(
          res
            .map((r: any) => ({
              time: new Date(r.timestamp).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              }),
              latency_ms: r.latency_ms,
              loss_percent: r.loss_percent,
              jitter_ms: r.jitter_ms,
            }))
            .reverse()
        );
      }
    } catch (err) {
      console.error("Execute probe error", err);
    } finally {
      setIsExecutingProbe(false);
    }
  };

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createProbeTarget({
        ...newTarget,
        port: Number(newTarget.port),
        interval_seconds: Number(newTarget.interval_seconds),
        timeout_ms: Number(newTarget.timeout_ms),
      });
      setShowAddTargetModal(false);
      await loadAllData();
    } catch (err) {
      console.error("Failed to create target", err);
    }
  };

  // Lab Actions
  const handleTriggerLabAnnounce = async () => {
    setIsLabRunning(true);
    setLabActionMessage({ type: "info", text: `Running 11-point Pre-Check and Announcing ${labPrefix}...` });
    try {
      const crId = labChangeRequestId ? parseInt(labChangeRequestId, 10) : undefined;
      const res = await api.triggerAnnounceTest({
        prefix: labPrefix,
        target_speaker: labSpeaker,
        change_request_id: isNaN(crId as number) ? undefined : crId,
      });
      setSelectedLabRun(res);
      setShowRunDetailModal(true);
      if (res.execution_status === "SUCCESS") {
        let convTime = "";
        try {
          convTime = JSON.parse(res.post_check_details).convergence_time_seconds + "s";
        } catch (_) {}
        setLabActionMessage({
          type: "success",
          text: `Announce SUCCESS: Verified on receiver in ${convTime || "1s"}.`,
        });
      } else if (res.execution_status === "ROLLED_BACK") {
        setLabActionMessage({
          type: "error",
          text: `Announce Failed post-check. Automated rollback: ${res.rollback_status}`,
        });
      } else {
        setLabActionMessage({ type: "error", text: `Pre-check FAILED: ${res.error_message}` });
      }
      loadLabData();
    } catch (err: any) {
      setLabActionMessage({ type: "error", text: `Lab error: ${err.message || String(err)}` });
    } finally {
      setIsLabRunning(false);
    }
  };

  const handleTriggerLabWithdraw = async () => {
    setIsLabRunning(true);
    setLabActionMessage({ type: "info", text: `Running Pre-Check and Withdrawing ${labPrefix}...` });
    try {
      const crId = labChangeRequestId ? parseInt(labChangeRequestId, 10) : undefined;
      const res = await api.triggerWithdrawTest({
        prefix: labPrefix,
        target_speaker: labSpeaker,
        change_request_id: isNaN(crId as number) ? undefined : crId,
      });
      setSelectedLabRun(res);
      setShowRunDetailModal(true);
      if (res.execution_status === "SUCCESS") {
        setLabActionMessage({ type: "success", text: `Withdraw SUCCESS: Prefix purged from receiver.` });
      } else if (res.execution_status === "ROLLED_BACK") {
        setLabActionMessage({
          type: "error",
          text: `Withdraw Failed post-check. Automated rollback: ${res.rollback_status}`,
        });
      } else {
        setLabActionMessage({ type: "error", text: `Pre-check FAILED: ${res.error_message}` });
      }
      loadLabData();
    } catch (err: any) {
      setLabActionMessage({ type: "error", text: `Lab error: ${err.message || String(err)}` });
    } finally {
      setIsLabRunning(false);
    }
  };

  const handleTriggerLabRoundtrip = async () => {
    setIsLabRunning(true);
    setLabActionMessage({ type: "info", text: `Executing full roundtrip test (Announce -> Verify -> Withdraw -> Verify)...` });
    try {
      const crId = labChangeRequestId ? parseInt(labChangeRequestId, 10) : undefined;
      const res = await api.triggerRoundtripTest({
        prefix: labPrefix,
        target_speaker: labSpeaker,
        change_request_id: isNaN(crId as number) ? undefined : crId,
      });
      setSelectedLabRun(res);
      setShowRunDetailModal(true);
      if (res.execution_status === "SUCCESS") {
        setLabActionMessage({
          type: "success",
          text: `Full Roundtrip SUCCESS: Route announced, verified, and cleanly purged.`,
        });
      } else {
        setLabActionMessage({ type: "error", text: `Roundtrip failed: ${res.error_message}` });
      }
      loadLabData();
    } catch (err: any) {
      setLabActionMessage({ type: "error", text: `Lab error: ${err.message || String(err)}` });
    } finally {
      setIsLabRunning(false);
    }
  };

  const handleSubmitManualReview = async () => {
    if (!selectedLabRun) return;
    try {
      const res = await api.submitManualReview(selectedLabRun.id, manualReviewNotes);
      setSelectedLabRun(res);
      setShowManualReviewModal(false);
      setManualReviewNotes("");
      setLabActionMessage({ type: "success", text: `Manual review completed for Test #${res.id}` });
      loadLabData();
    } catch (err: any) {
      alert(`Manual review failed: ${err.message || String(err)}`);
    }
  };

  const filteredRoutes = filterPrefix
    ? routes.filter((r) => r.prefix.toLowerCase().includes(filterPrefix.toLowerCase()))
    : routes;

  const selectedTarget = probeTargets.find((t) => t.id === selectedTargetId);

  return (
    <div className="space-y-6">
      {/* Top Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            BGP Visibility, Active Probing & Lab Testbed
            <span className="noc-badge-demo text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
              PHASE 6 READY
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            RFC 7854 BMP live telemetry, egress SLA probes, and isolated GoBGP container testbed with automated rollback.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => loadAllData()}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1F2937] hover:bg-[#374151] text-xs font-mono text-gray-200 rounded-lg transition-colors border border-gray-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-[#1F2937] gap-4">
        <button
          onClick={() => setActiveTab("visibility")}
          className={`pb-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === "visibility"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <Network className="w-4 h-4" />
          <span>BGP Visibility & BMP Telemetry</span>
        </button>
        <button
          onClick={() => setActiveTab("probing")}
          className={`pb-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === "probing"
              ? "border-emerald-500 text-emerald-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <Crosshair className="w-4 h-4" />
          <span>Active Path Probing</span>
        </button>
        <button
          onClick={() => setActiveTab("lab")}
          className={`pb-3 text-xs font-mono font-medium flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === "lab"
              ? "border-purple-500 text-purple-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <Server className="w-4 h-4" />
          <span>Isolated BGP Lab & Rollback Testbed</span>
          <span className="px-1.5 py-0.2 rounded text-[9px] bg-purple-500/20 text-purple-300 border border-purple-500/40">
            PHASE 6
          </span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: BGP VISIBILITY & BMP TELEMETRY */}
      {/* ========================================================================= */}
      {activeTab === "visibility" && (
        <div className="space-y-6">
          {/* BMP Adapter Telemetry Banner */}
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div
                  className={`p-2.5 rounded-lg border ${
                    bmpStatus?.is_running
                      ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-400"
                      : "bg-rose-950/40 border-rose-500/40 text-rose-400"
                  }`}
                >
                  <Radio className="w-5 h-5 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-white">BMP Adapter (RFC 7854)</h3>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full font-mono font-bold uppercase ${
                        bmpStatus?.is_running
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                          : "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                      }`}
                    >
                      {bmpStatus?.is_running ? "LISTENING" : "INACTIVE"}
                    </span>
                    {bmpStatus?.lab_mode && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
                        LAB MODE
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-gray-400 font-mono mt-0.5">
                    TCP Listener: <span className="text-blue-400">{bmpStatus?.host || "0.0.0.0"}:{bmpStatus?.port || 11019}</span> | Active Routers:{" "}
                    <span className="text-white font-bold">{bmpStatus?.active_connections || 0}</span>
                  </p>
                </div>
              </div>

              {/* Quick Metrics & Simulation Controls */}
              <div className="flex flex-wrap items-center gap-3">
                <div className="bg-[#0D1322] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs font-mono">
                  <span className="text-gray-400">Messages:</span>{" "}
                  <span className="text-emerald-400 font-bold">{bmpStatus?.total_messages_received || 0}</span>
                </div>
                <div className="bg-[#0D1322] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs font-mono">
                  <span className="text-gray-400">Route Events:</span>{" "}
                  <span className="text-blue-400 font-bold">{bmpStatus?.total_route_events || 0}</span>
                </div>
                <div className="bg-[#0D1322] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs font-mono">
                  <span className="text-gray-400">Parse Errors:</span>{" "}
                  <span className={bmpStatus?.total_parse_errors > 0 ? "text-rose-400 font-bold" : "text-gray-400"}>
                    {bmpStatus?.total_parse_errors || 0}
                  </span>
                </div>

                <button
                  onClick={() => handleSimulateBmp("route_monitoring")}
                  disabled={isSimulatingBmp}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/30 hover:bg-blue-600 text-blue-300 hover:text-white rounded-lg text-xs font-mono font-semibold transition-colors border border-blue-500/40 disabled:opacity-50"
                >
                  <Send className="w-3.5 h-3.5" />
                  {isSimulatingBmp ? "Simulating..." : "Inject Test BMP Update"}
                </button>
              </div>
            </div>
          </div>

          {/* BGP Peers & Live Route Events Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
              <div className="p-4 border-b border-[#1F2937] flex items-center justify-between">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                  Monitored BGP Peers ({peers.length})
                </h4>
                <span className="text-[10px] text-gray-400 font-mono">Protocol: BGP-4 / BMP v3</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
                    <tr>
                      <th className="py-2.5 px-3">Peer IP</th>
                      <th className="py-2.5 px-3">Remote AS</th>
                      <th className="py-2.5 px-3">Peer Name</th>
                      <th className="py-2.5 px-3">State</th>
                      <th className="py-2.5 px-3">Uptime</th>
                      <th className="py-2.5 px-3">Source</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2937] text-gray-300">
                    {peers.map((peer) => (
                      <tr key={peer.id} className="hover:bg-[#1A2234] transition-colors">
                        <td className="py-2.5 px-3 font-semibold text-white">{peer.peer_ip}</td>
                        <td className="py-2.5 px-3 text-blue-400">AS{peer.remote_as}</td>
                        <td className="py-2.5 px-3 text-gray-400">{peer.peer_name || "-"}</td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              peer.state === "Established"
                                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                                : "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                            }`}
                          >
                            {peer.state}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-gray-400 font-mono">
                          {Math.floor(peer.uptime_seconds / 3600)}h {Math.floor((peer.uptime_seconds % 3600) / 60)}m
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40 uppercase">
                            {peer.data_source || "SIMULATED"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden flex flex-col">
              <div className="p-4 border-b border-[#1F2937] flex items-center justify-between">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                  Live Route Events Feed
                </h4>
                <span className="text-[10px] text-gray-400 font-mono">Latest 30</span>
              </div>
              <div className="p-3 divide-y divide-[#1F2937] overflow-y-auto max-h-[300px] text-xs font-mono space-y-2">
                {events.length === 0 ? (
                  <p className="text-center text-gray-500 py-4">No route events received yet.</p>
                ) : (
                  events.map((ev) => (
                    <div key={ev.id} className="pt-2 flex items-start justify-between">
                      <div>
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                              ev.event_type === "ANNOUNCE"
                                ? "bg-emerald-500/20 text-emerald-400"
                                : ev.event_type === "WITHDRAW"
                                ? "bg-rose-500/20 text-rose-400"
                                : "bg-amber-500/20 text-amber-400"
                            }`}
                          >
                            {ev.event_type}
                          </span>
                          <span className="text-white font-bold">{ev.prefix}</span>
                        </div>
                        <p className="text-[11px] text-gray-400 mt-0.5">
                          Peer: {ev.peer_ip} | NextHop: {ev.next_hop || "-"}
                        </p>
                      </div>
                      <span className="text-[10px] text-gray-500">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* BGP Route Explorer */}
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[#1F2937] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                  BGP Routing Table & Prefix Explorer
                </h4>
                <p className="text-[11px] text-gray-400 font-mono mt-0.5">
                  Filter by prefix or autonomous system path.
                </p>
              </div>
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-gray-500" />
                <input
                  type="text"
                  placeholder="Filter prefix (e.g. 103.145)..."
                  value={filterPrefix}
                  onChange={(e) => setFilterPrefix(e.target.value)}
                  className="bg-[#0D1322] border border-[#1F2937] text-xs font-mono text-white rounded-lg pl-8 pr-3 py-1.5 w-64 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
                  <tr>
                    <th className="py-2.5 px-3">Prefix</th>
                    <th className="py-2.5 px-3">Next Hop</th>
                    <th className="py-2.5 px-3">Peer ASN</th>
                    <th className="py-2.5 px-3">AS Path</th>
                    <th className="py-2.5 px-3">Origin</th>
                    <th className="py-2.5 px-3">Best Path</th>
                    <th className="py-2.5 px-3">Data Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2937] text-gray-300">
                  {filteredRoutes.map((route) => (
                    <tr key={route.id} className="hover:bg-[#1A2234] transition-colors">
                      <td className="py-2.5 px-3 font-bold text-white">{route.prefix}</td>
                      <td className="py-2.5 px-3 text-emerald-400">{route.next_hop || "-"}</td>
                      <td className="py-2.5 px-3 text-blue-400">AS{route.peer_asn}</td>
                      <td className="py-2.5 px-3 text-gray-400">{route.as_path || "-"}</td>
                      <td className="py-2.5 px-3 text-gray-300">{route.origin}</td>
                      <td className="py-2.5 px-3">
                        {route.best_path ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 font-bold">
                            YES
                          </span>
                        ) : (
                          <span className="text-gray-500">NO</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40 uppercase">
                          {route.data_source || "SIMULATED"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: ACTIVE PATH PROBING */}
      {/* ========================================================================= */}
      {activeTab === "probing" && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2.5 bg-blue-950/40 border border-blue-500/40 rounded-lg text-blue-400">
                  <Crosshair className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                      Egress Binding Mode:
                    </h4>
                    <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                      {egressCaps?.recommended_mode?.toUpperCase() || "SOURCE_IP_BIND"}
                    </span>
                    <span className="text-[10px] text-gray-400 font-mono">
                      Host OS: {egressCaps?.platform || "Unknown"}
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-400 mt-0.5">
                    {egressCaps?.environment_caveat ||
                      "Source address binding (sock.bind((ip, 0))) active. Note: Policy routing (PBR) required for strict multi-interface egress."}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleExecuteProbeNow()}
                  disabled={isExecutingProbe}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-mono font-semibold transition-colors disabled:opacity-50"
                >
                  <Zap className="w-3.5 h-3.5" />
                  {isExecutingProbe ? "Probing..." : "Probe All Targets Now"}
                </button>
                <button
                  onClick={() => setShowAddTargetModal(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1F2937] hover:bg-[#374151] text-gray-200 rounded-lg text-xs font-mono font-semibold transition-colors border border-gray-700"
                >
                  <Plus className="w-3.5 h-3.5" />
                  New Target
                </button>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
              <div className="p-4 border-b border-[#1F2937] flex items-center justify-between">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                  Configured Probe Targets ({probeTargets.length})
                </h4>
                <span className="text-[10px] text-gray-400 font-mono">
                  Worker Sweep: every {probeWorkerStatus?.interval_seconds || 15}s
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
                    <tr>
                      <th className="py-2.5 px-3">Target Name</th>
                      <th className="py-2.5 px-3">Target IP & Port</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Latency (ms)</th>
                      <th className="py-2.5 px-3">Loss (%)</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2937] text-gray-300">
                    {probeTargets.map((t) => {
                      const isSelected = t.id === selectedTargetId;
                      const isOk = t.last_status === "ok";
                      const isTimeout = t.last_status === "timeout";
                      const isStale = t.last_status === "stale";
                      return (
                        <tr
                          key={t.id}
                          onClick={() => setSelectedTargetId(t.id)}
                          className={`cursor-pointer transition-colors ${
                            isSelected ? "bg-[#1E293B]" : "hover:bg-[#1A2234]"
                          }`}
                        >
                          <td className="py-2.5 px-3 font-semibold text-white flex items-center gap-1.5">
                            {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />}
                            {t.target_name}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-gray-300">
                            {t.target_ip}
                            {t.port ? `:${t.port}` : ""}
                          </td>
                          <td className="py-2.5 px-3 uppercase text-blue-400">{t.probe_type}</td>
                          <td className="py-2.5 px-3 font-bold text-emerald-400">
                            {t.last_latency_ms !== null ? `${t.last_latency_ms.toFixed(1)} ms` : "-"}
                          </td>
                          <td className="py-2.5 px-3 font-bold text-amber-400">
                            {t.last_loss_percent !== null ? `${t.last_loss_percent.toFixed(1)}%` : "-"}
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                isOk
                                  ? "bg-emerald-500/20 text-emerald-400"
                                  : isTimeout
                                  ? "bg-rose-500/20 text-rose-400"
                                  : isStale
                                  ? "bg-amber-500/20 text-amber-400"
                                  : "bg-gray-700 text-gray-400"
                              }`}
                            >
                              {t.last_status || "PENDING"}
                            </span>
                          </td>
                          <td className="py-2.5 px-3">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleExecuteProbeNow(t.id);
                              }}
                              className="px-2 py-0.5 bg-[#1F2937] hover:bg-[#374151] text-gray-200 rounded text-[10px] font-mono border border-gray-700"
                            >
                              Probe
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Target Telemetry Chart */}
            <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
                  <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                    Target SLA: {selectedTarget?.target_name || "Select Target"}
                  </h4>
                  <span className="text-[10px] text-gray-400 font-mono">History (30 sweeps)</span>
                </div>

                <div className="h-56 mt-4">
                  {probeResults.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-xs text-gray-500 font-mono">
                      No sweep telemetry recorded yet.
                    </div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={probeResults}>
                        <defs>
                          <linearGradient id="latencyGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                            <stop offset="95%" stopColor="#10B981" stopOpacity={0.0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                        <XAxis dataKey="time" stroke="#6B7280" fontSize={10} tickLine={false} />
                        <YAxis stroke="#6B7280" fontSize={10} tickLine={false} unit="ms" />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#0D1322",
                            borderColor: "#374151",
                            fontSize: "11px",
                            fontFamily: "monospace",
                          }}
                        />
                        <Area
                          type="monotone"
                          dataKey="latency_ms"
                          name="RTT (ms)"
                          stroke="#10B981"
                          strokeWidth={2}
                          fillOpacity={1}
                          fill="url(#latencyGrad)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: ISOLATED BGP LAB & AUTOMATED ROLLBACK (PHASE 6) */}
      {/* ========================================================================= */}
      {activeTab === "lab" && (
        <div className="space-y-6">
          {/* Top Isolation & Safety Guardrail Banner */}
          <div className="bg-[#0D1322] border border-purple-500/40 rounded-xl p-5 shadow-2xl space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-purple-950/60 border border-purple-500/50 rounded-xl text-purple-400">
                  <Server className="w-6 h-6 animate-pulse" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                      ISOLATED BGP LAB & VALIDATION TESTBED
                    </h3>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold uppercase ${
                      labStatus?.lab_enabled
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
                        : "bg-rose-500/20 text-rose-400 border border-rose-500/40"
                    }`}>
                      BGP_LAB_ENABLED: {labStatus?.lab_enabled ? "TRUE" : "FALSE"}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 uppercase">
                      ROUTING_EXECUTION_ENABLED: FALSE (LOCKED)
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 font-mono mt-1">
                    Dual GoBGP container routers on non-routed internal bridge <span className="text-purple-300">bgp_lab_net</span>.
                    Zero host port 179 exposure, zero internet transit access, strict prefix allowlist.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => loadLabData()}
                  className="px-3 py-1.5 bg-[#1F2937] hover:bg-[#374151] text-xs font-mono text-gray-200 rounded-lg transition-colors border border-gray-700 flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Refresh Lab Status
                </button>
              </div>
            </div>

            {/* Action Flash Message */}
            {labActionMessage && (
              <div className={`p-3 rounded-lg text-xs font-mono flex items-center justify-between ${
                labActionMessage.type === "success"
                  ? "bg-emerald-950/50 border border-emerald-500/40 text-emerald-300"
                  : labActionMessage.type === "error"
                  ? "bg-rose-950/50 border border-rose-500/40 text-rose-300"
                  : "bg-blue-950/50 border border-blue-500/40 text-blue-300"
              }`}>
                <span>{labActionMessage.text}</span>
                <button
                  onClick={() => setLabActionMessage(null)}
                  className="text-gray-400 hover:text-white ml-2 text-xs"
                >
                  ✕
                </button>
              </div>
            )}
          </div>

          {/* Dual Speaker Status Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {labStatus?.speakers?.map((sp: any) => (
              <div key={sp.speaker_id} className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 space-y-3 font-mono">
                <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
                  <div className="flex items-center gap-2">
                    <Cpu className="w-4 h-4 text-purple-400" />
                    <span className="text-sm font-bold text-white uppercase">{sp.name}</span>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                    sp.is_healthy
                      ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                      : "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                  }`}>
                    {sp.is_healthy ? "ONLINE" : "OFFLINE"}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="bg-[#0D1322] p-2.5 rounded border border-[#1F2937]">
                    <span className="text-[10px] text-gray-500 block">AUTONOMOUS SYSTEM</span>
                    <span className="text-sm font-bold text-purple-300">AS{sp.asn}</span>
                  </div>
                  <div className="bg-[#0D1322] p-2.5 rounded border border-[#1F2937]">
                    <span className="text-[10px] text-gray-500 block">CONTAINER IP</span>
                    <span className="text-sm font-bold text-gray-200">{sp.ip_address}</span>
                  </div>
                </div>

                {/* Peering Sessions */}
                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] text-gray-400 uppercase font-bold block">Peering Sessions:</span>
                  {sp.peers?.map((p: any) => (
                    <div key={p.peer_ip} className="bg-[#0D1322] p-2 rounded border border-[#1F2937] flex items-center justify-between text-xs">
                      <div>
                        <span className="text-white font-bold">{p.peer_ip}</span>{" "}
                        <span className="text-purple-400">(AS{p.peer_as})</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        p.state === "Established"
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                          : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                      }`}>
                        {p.state}
                      </span>
                    </div>
                  ))}
                </div>

                <div className="text-[11px] text-gray-400 pt-1 flex justify-between">
                  <span>Active Routes in Global RIB:</span>
                  <span className="font-bold text-emerald-400">{sp.active_routes_count} prefixes</span>
                </div>
              </div>
            ))}
          </div>

          {/* Test Trigger Control Panel */}
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 space-y-4 font-mono">
            <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
              <h4 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-4 h-4 text-purple-400" />
                Lab Route Operation Runner (With 11-Point Safety Pre-Check)
              </h4>
              <span className="text-[10px] text-gray-400">Strict Allowlist Protected</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div>
                <label className="text-gray-400 block mb-1">Target Test Prefix</label>
                <select
                  value={labPrefix}
                  onChange={(e) => setLabPrefix(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white font-mono focus:border-purple-500"
                >
                  {labStatus?.allowed_prefixes?.map((pref: string) => (
                    <option key={pref} value={pref}>{pref}</option>
                  ))}
                  <option value="0.0.0.0/0">0.0.0.0/0 (Negative Test: Should Reject)</option>
                  <option value="192.0.2.0/24">192.0.2.0/24 (Negative Test: Unallowlisted)</option>
                </select>
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Originating Speaker</label>
                <select
                  value={labSpeaker}
                  onChange={(e) => setLabSpeaker(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white font-mono focus:border-purple-500"
                >
                  <option value="bgp-speaker-1">bgp-speaker-1 (AS 65001)</option>
                  <option value="bgp-speaker-2">bgp-speaker-2 (AS 65002)</option>
                </select>
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Linked Change Request ID (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. 1"
                  value={labChangeRequestId}
                  onChange={(e) => setLabChangeRequestId(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white font-mono focus:border-purple-500"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={handleTriggerLabAnnounce}
                disabled={isLabRunning}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded text-xs flex items-center gap-2 disabled:opacity-50 transition-colors"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Test Route Announcement</span>
              </button>

              <button
                onClick={handleTriggerLabWithdraw}
                disabled={isLabRunning}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded text-xs flex items-center gap-2 disabled:opacity-50 transition-colors"
              >
                <XCircle className="w-3.5 h-3.5" />
                <span>Test Route Withdrawal</span>
              </button>

              <button
                onClick={handleTriggerLabRoundtrip}
                disabled={isLabRunning}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white font-bold rounded text-xs flex items-center gap-2 disabled:opacity-50 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Full Roundtrip Verification</span>
              </button>
            </div>
          </div>

          {/* Test Runs History Table */}
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden font-mono">
            <div className="p-4 border-b border-[#1F2937] flex items-center justify-between">
              <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                Lab Test Runs & Rollback History ({labHistory.length})
              </h4>
              <span className="text-[10px] text-gray-400">Auditable Verification Records</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
                  <tr>
                    <th className="py-2.5 px-3">Run ID</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Prefix</th>
                    <th className="py-2.5 px-3">Speaker</th>
                    <th className="py-2.5 px-3">Pre-Check</th>
                    <th className="py-2.5 px-3">Post-Check</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Rollback</th>
                    <th className="py-2.5 px-3">CR Link</th>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2937] text-gray-300">
                  {labHistory.length === 0 ? (
                    <tr>
                      <td colSpan={11} className="py-8 text-center text-gray-500">
                        No lab test runs executed yet. Select a prefix above and click Test Route Announcement.
                      </td>
                    </tr>
                  ) : (
                    labHistory.map((run) => (
                      <tr key={run.id} className="hover:bg-[#1A2234] transition-colors">
                        <td className="py-2.5 px-3 font-bold text-white">#{run.id}</td>
                        <td className="py-2.5 px-3 uppercase text-purple-300">{run.test_type}</td>
                        <td className="py-2.5 px-3 font-bold text-white">{run.prefix}</td>
                        <td className="py-2.5 px-3 text-gray-400">{run.target_speaker}</td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            run.pre_check_status === "PASS"
                              ? "bg-emerald-500/20 text-emerald-400"
                              : "bg-rose-500/20 text-rose-400"
                          }`}>
                            {run.pre_check_status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            run.post_check_status === "PASS"
                              ? "bg-emerald-500/20 text-emerald-400"
                              : run.post_check_status === "FAIL"
                              ? "bg-rose-500/20 text-rose-400"
                              : "bg-gray-700 text-gray-400"
                          }`}>
                            {run.post_check_status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            run.execution_status === "SUCCESS"
                              ? "bg-emerald-500/20 text-emerald-400"
                              : run.execution_status === "ROLLED_BACK"
                              ? "bg-amber-500/20 text-amber-400"
                              : "bg-rose-500/20 text-rose-400"
                          }`}>
                            {run.execution_status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            run.rollback_status === "ROLLBACK_SUCCEEDED"
                              ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                              : run.rollback_status === "NEEDS_MANUAL_REVIEW"
                              ? "bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse"
                              : "text-gray-500"
                          }`}>
                            {run.rollback_status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-blue-400">
                          {run.change_request_id ? `#${run.change_request_id}` : "-"}
                        </td>
                        <td className="py-2.5 px-3 text-gray-400">
                          {new Date(run.created_at).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 text-right space-x-1.5">
                          <button
                            onClick={() => {
                              setSelectedLabRun(run);
                              setShowRunDetailModal(true);
                            }}
                            className="px-2 py-1 bg-[#1F2937] hover:bg-[#374151] text-gray-200 rounded text-[10px] font-mono border border-gray-700"
                          >
                            Inspect
                          </button>
                          {run.rollback_status === "NEEDS_MANUAL_REVIEW" && (
                            <button
                              onClick={() => {
                                setSelectedLabRun(run);
                                setShowManualReviewModal(true);
                              }}
                              className="px-2 py-1 bg-amber-600 hover:bg-amber-500 text-white rounded text-[10px] font-mono font-bold"
                            >
                              Review
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* RUN DETAIL & 11-POINT PRE-CHECK INSPECTOR MODAL */}
      {/* ========================================================================= */}
      {showRunDetailModal && selectedLabRun && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 font-mono">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-3xl w-full p-6 space-y-4 max-h-[90vh] overflow-y-auto shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-purple-400" />
                  Lab Test Run #{selectedLabRun.id} Detailed Report
                </h3>
                <p className="text-xs text-gray-400 mt-0.5">
                  Type: <span className="text-purple-300 font-bold">{selectedLabRun.test_type}</span> | Prefix:{" "}
                  <span className="text-white font-bold">{selectedLabRun.prefix}</span> | Speaker: {selectedLabRun.target_speaker}
                </p>
              </div>
              <button
                onClick={() => setShowRunDetailModal(false)}
                className="text-gray-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            {/* Status Summary Banner */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
              <div className="bg-[#0D1322] p-3 rounded border border-[#1F2937]">
                <span className="text-[10px] text-gray-500 block">EXECUTION STATUS</span>
                <span className={`text-sm font-bold uppercase ${
                  selectedLabRun.execution_status === "SUCCESS"
                    ? "text-emerald-400"
                    : selectedLabRun.execution_status === "ROLLED_BACK"
                    ? "text-amber-400"
                    : "text-rose-400"
                }`}>
                  {selectedLabRun.execution_status}
                </span>
              </div>
              <div className="bg-[#0D1322] p-3 rounded border border-[#1F2937]">
                <span className="text-[10px] text-gray-500 block">POST-CHECK CONVERGENCE</span>
                <span className={`text-sm font-bold uppercase ${
                  selectedLabRun.post_check_status === "PASS" ? "text-emerald-400" : "text-rose-400"
                }`}>
                  {selectedLabRun.post_check_status}
                </span>
              </div>
              <div className="bg-[#0D1322] p-3 rounded border border-[#1F2937]">
                <span className="text-[10px] text-gray-500 block">AUTOMATED ROLLBACK</span>
                <span className={`text-sm font-bold uppercase ${
                  selectedLabRun.rollback_status === "ROLLBACK_SUCCEEDED"
                    ? "text-emerald-400"
                    : selectedLabRun.rollback_status === "NEEDS_MANUAL_REVIEW"
                    ? "text-rose-400"
                    : "text-gray-400"
                }`}>
                  {selectedLabRun.rollback_status}
                </span>
              </div>
            </div>

            {/* Error Message if present */}
            {selectedLabRun.error_message && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded text-xs text-rose-300">
                <span className="font-bold">Error/Notice:</span> {selectedLabRun.error_message}
              </div>
            )}

            {/* 11-Point Pre-Check Breakdown */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                11-Point Safety Pre-Check Inspection Results
              </h4>
              <div className="bg-[#0D1322] border border-[#1F2937] rounded-lg divide-y divide-[#1F2937] text-xs">
                {(() => {
                  try {
                    const items = JSON.parse(selectedLabRun.pre_check_details || "[]");
                    return items.map((chk: any, idx: number) => (
                      <div key={idx} className="p-2.5 flex items-start justify-between gap-3">
                        <div className="flex items-start gap-2">
                          {chk.status === "PASS" ? (
                            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                          ) : (
                            <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                          )}
                          <div>
                            <span className="font-bold text-white block">{chk.check_name}</span>
                            <span className="text-[11px] text-gray-400">{chk.details}</span>
                          </div>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                          chk.status === "PASS"
                            ? "bg-emerald-500/20 text-emerald-400"
                            : "bg-rose-500/20 text-rose-400"
                        }`}>
                          {chk.status}
                        </span>
                      </div>
                    ));
                  } catch (_) {
                    return <p className="p-4 text-gray-500">No pre-check details available.</p>;
                  }
                })()}
              </div>
            </div>

            {/* Post-Check Details */}
            {selectedLabRun.post_check_details && (
              <div className="space-y-1.5">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Post-Check Convergence Telemetry
                </h4>
                <div className="bg-[#0D1322] border border-[#1F2937] rounded-lg p-3 text-xs text-gray-300">
                  <pre className="text-[11px] text-emerald-300 whitespace-pre-wrap">
                    {JSON.stringify(JSON.parse(selectedLabRun.post_check_details), null, 2)}
                  </pre>
                </div>
              </div>
            )}

            {/* Rollback Details if executed */}
            {selectedLabRun.rollback_details && (
              <div className="space-y-1.5">
                <h4 className="text-xs font-bold text-amber-300 uppercase tracking-wider flex items-center gap-1.5">
                  <RotateCcw className="w-4 h-4 text-amber-400" />
                  Automated Rollback Audit Steps
                </h4>
                <div className="bg-[#0D1322] border border-[#1F2937] rounded-lg p-3 text-xs text-gray-300">
                  <pre className="text-[11px] text-amber-300 whitespace-pre-wrap">
                    {JSON.stringify(JSON.parse(selectedLabRun.rollback_details), null, 2)}
                  </pre>
                </div>
              </div>
            )}

            <div className="flex justify-end pt-3 border-t border-[#1F2937]">
              <button
                onClick={() => setShowRunDetailModal(false)}
                className="px-4 py-2 bg-[#1F2937] hover:bg-[#374151] text-white rounded text-xs font-mono"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MANUAL REVIEW MODAL */}
      {showManualReviewModal && selectedLabRun && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 font-mono">
          <div className="bg-[#111827] border border-amber-500/50 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
              <h3 className="text-sm font-bold text-amber-300 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                Complete Manual Operator Review
              </h3>
              <button
                onClick={() => setShowManualReviewModal(false)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <p className="text-xs text-gray-300">
              Lab test run #{selectedLabRun.id} for prefix {selectedLabRun.prefix} was flagged with NEEDS_MANUAL_REVIEW.
              Enter your operational review justification to clear the review flag.
            </p>
            <textarea
              rows={3}
              placeholder="e.g. Verified BGP state on bgp-speaker-2 CLI. State is clean, zero lingering routes."
              value={manualReviewNotes}
              onChange={(e) => setManualReviewNotes(e.target.value)}
              className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2.5 text-xs text-white font-mono focus:border-amber-500"
            />
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowManualReviewModal(false)}
                className="px-3 py-1.5 bg-[#1F2937] text-gray-300 rounded text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmitManualReview}
                disabled={manualReviewNotes.trim().length < 3}
                className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white font-bold rounded text-xs disabled:opacity-50"
              >
                Confirm Resolution
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ADD TARGET MODAL (Existing) */}
      {showAddTargetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 font-mono">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl text-xs">
            <div className="flex items-center justify-between pb-2 border-b border-[#1F2937]">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Plus className="w-4 h-4 text-emerald-400" />
                Add Active SLA Probe Target
              </h3>
              <button
                onClick={() => setShowAddTargetModal(false)}
                className="text-gray-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateTarget} className="space-y-3">
              <div>
                <label className="text-gray-400 block mb-1">Target Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Google Primary DNS"
                  value={newTarget.target_name}
                  onChange={(e) => setNewTarget({ ...newTarget, target_name: e.target.value })}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-gray-400 block mb-1">Target IP</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 8.8.8.8"
                    value={newTarget.target_ip}
                    onChange={(e) => setNewTarget({ ...newTarget, target_ip: e.target.value })}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-gray-400 block mb-1">Probe Type</label>
                  <select
                    value={newTarget.probe_type}
                    onChange={(e) => setNewTarget({ ...newTarget, probe_type: e.target.value })}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  >
                    <option value="icmp">ICMP Ping</option>
                    <option value="tcp">TCP Connect RTT</option>
                  </select>
                </div>
              </div>

              {newTarget.probe_type === "tcp" && (
                <div>
                  <label className="text-gray-400 block mb-1">Target TCP Port</label>
                  <input
                    type="number"
                    value={newTarget.port}
                    onChange={(e) => setNewTarget({ ...newTarget, port: Number(e.target.value) })}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  />
                </div>
              )}

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-gray-400 block mb-1">Source IP (Egress Bind)</label>
                  <input
                    type="text"
                    placeholder="e.g. 198.51.100.254"
                    value={newTarget.source_ip}
                    onChange={(e) => setNewTarget({ ...newTarget, source_ip: e.target.value })}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-gray-400 block mb-1">Egress Interface</label>
                  <input
                    type="text"
                    placeholder="e.g. ge-0/0/0"
                    value={newTarget.egress_interface}
                    onChange={(e) => setNewTarget({ ...newTarget, egress_interface: e.target.value })}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddTargetModal(false)}
                  className="px-3 py-1.5 bg-[#1F2937] text-gray-300 rounded hover:bg-[#374151]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-blue-600 text-white font-bold rounded hover:bg-blue-500"
                >
                  Create Target
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
