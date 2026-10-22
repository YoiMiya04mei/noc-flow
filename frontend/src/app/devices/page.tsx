"use client";

import React, { useEffect, useState } from "react";
import {
  Server,
  Activity,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Clock,
  RefreshCw,
  Key,
  TrendingUp,
  X,
  Plus,
  Radio,
  Sliders,
  ExternalLink,
} from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Area,
  AreaChart,
} from "recharts";
import { api } from "@/lib/api";

function formatBps(bps?: number): string {
  if (!bps || bps <= 0) return "0 bps";
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
  return `${bps} bps`;
}

function formatPps(pps?: number): string {
  if (!pps || pps <= 0) return "0 pps";
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(2)} Mpps`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(1)} Kpps`;
  return `${pps} pps`;
}

function formatUptime(ticks?: number): string {
  if (!ticks || ticks <= 0) return "Unknown";
  const seconds = Math.floor(ticks / 100);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m ${seconds % 60}s`;
}

function timeAgo(dateStr?: string): string {
  if (!dateStr) return "Never";
  const elapsed = Math.floor((new Date().getTime() - new Date(dateStr).getTime()) / 1000);
  if (elapsed < 5) return "Just now";
  if (elapsed < 60) return `${elapsed}s ago`;
  if (elapsed < 3600) return `${Math.floor(elapsed / 60)}m ago`;
  return `${Math.floor(elapsed / 3600)}h ago`;
}

export default function DevicesPage() {
  const [devices, setDevices] = useState<any[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [pollingId, setPollingId] = useState<number | null>(null);
  const [pollFeedback, setPollFeedback] = useState<{ id: number; msg: string; success: boolean } | null>(null);

  // SNMP Worker Status
  const [workerStatus, setWorkerStatus] = useState<any>(null);
  const [triggeringWorker, setTriggeringWorker] = useState(false);

  // Interface History Modal
  const [historyInterface, setHistoryInterface] = useState<any | null>(null);
  const [historyData, setHistoryData] = useState<any[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // SNMP Profiles Management Modal
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [newProfile, setNewProfile] = useState({
    name: "",
    version: "v3",
    port: 161,
    timeout_sec: 3.0,
    retries: 2,
    security_name: "",
    auth_protocol: "SHA",
    auth_pass: "",
    priv_protocol: "AES",
    priv_pass: "",
    community: "",
  });

  const loadData = async () => {
    try {
      setLoading(true);
      const data = await api.getDevices();
      setDevices(data);
      if (data.length > 0) {
        setSelectedDevice((prev: any) => data.find((d: any) => d.id === prev?.id) || data[0]);
      }
      const profs = await api.getSNMPProfiles();
      setProfiles(profs);
      try {
        const ws = await api.getSNMPWorkerStatus();
        setWorkerStatus(ws);
      } catch {
        // worker status fallback
      }
    } catch (err) {
      console.error("Failed to load inventory:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      loadData();
    }, 15000); // Polling status auto-refresh every 15s
    return () => clearInterval(interval);
  }, []);

  const handleTriggerWorkerSweep = async () => {
    try {
      setTriggeringWorker(true);
      const updated = await api.triggerSNMPWorkerCycle();
      setWorkerStatus(updated);
      const refreshed = await api.getDevices();
      setDevices(refreshed);
      setSelectedDevice((prev: any) => refreshed.find((d: any) => d.id === prev?.id) || refreshed[0]);
    } catch (err: any) {
      alert(`Worker sweep error: ${err.message}`);
    } finally {
      setTriggeringWorker(false);
    }
  };

  const handlePoll = async (devId: number) => {
    try {
      setPollingId(devId);
      setPollFeedback(null);
      const res = await api.pollDevice(devId, true);
      setPollFeedback({
        id: devId,
        msg: res.success
          ? `Polled ${res.interfaces_polled} interfaces in ${res.duration_ms.toFixed(1)}ms`
          : `Poll failed: ${res.error_message || res.snmp_status}`,
        success: res.success,
      });
      // Re-fetch devices to update UI
      const refreshed = await api.getDevices();
      setDevices(refreshed);
      setSelectedDevice((prev: any) => refreshed.find((d: any) => d.id === prev?.id) || refreshed[0]);
    } catch (err: any) {
      setPollFeedback({
        id: devId,
        msg: `Error: ${err.message}`,
        success: false,
      });
    } finally {
      setPollingId(null);
    }
  };

  const openInterfaceHistory = async (iface: any) => {
    if (!selectedDevice) return;
    setHistoryInterface(iface);
    setHistoryLoading(true);
    try {
      const history = await api.getInterfaceHistory(selectedDevice.id, iface.id, 30);
      const formatted = history.map((item: any) => ({
        time: new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        in_mbps: +(item.in_bps / 1_000_000).toFixed(2),
        out_mbps: +(item.out_bps / 1_000_000).toFixed(2),
        utilization_pct: item.utilization_pct,
        in_kpps: +(item.in_pps / 1_000).toFixed(1),
        out_kpps: +(item.out_pps / 1_000).toFixed(1),
      }));
      setHistoryData(formatted);
    } catch (err) {
      console.error("Failed to load history:", err);
      setHistoryData([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleCreateProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createSNMPProfile(newProfile);
      setShowProfileModal(false);
      setNewProfile({
        name: "",
        version: "v3",
        port: 161,
        timeout_sec: 3.0,
        retries: 2,
        security_name: "",
        auth_protocol: "SHA",
        auth_pass: "",
        priv_protocol: "AES",
        priv_pass: "",
        community: "",
      });
      const profs = await api.getSNMPProfiles();
      setProfiles(profs);
    } catch (err: any) {
      alert(`Failed to create SNMP profile: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            Network Devices & SNMP Engine
            <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
              PHASE 3 ACTIVE
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Real-time interface health, 64-bit HC counter math, reboot & wrap detection, and SNMPv3 authPriv.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowProfileModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1F2937] hover:bg-[#374151] border border-gray-700 rounded-lg text-xs font-mono text-gray-200 transition-colors"
          >
            <Key className="w-3.5 h-3.5 text-blue-400" />
            <span>SNMP Profiles ({profiles.length})</span>
          </button>
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono transition-colors shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Background Polling Worker Banner */}
      <div className="bg-[#0F172A] border border-blue-900/40 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-gray-800/80 pb-3 mb-3">
          <div className="flex items-center gap-2.5">
            <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white font-mono uppercase tracking-wide">
                  Background SNMP Worker Engine
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  {workerStatus?.is_running ? "RUNNING (SCHEDULED)" : "ACTIVE / ON-DEMAND"}
                </span>
              </div>
              <p className="text-[11px] text-gray-400 font-mono mt-0.5">
                Periodic inventory sweeps with concurrency throttle ({workerStatus?.concurrency_limit || 10} concurrent), timeout backoff, and double-poll lock.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleTriggerWorkerSweep}
              disabled={triggeringWorker}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 rounded-lg text-xs font-mono transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${triggeringWorker ? "animate-spin" : ""}`} />
              <span>{triggeringWorker ? "Running Sweep..." : "Run Sweep Now"}</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs font-mono">
          <div className="bg-[#131C31] p-2.5 rounded-lg border border-gray-800">
            <span className="text-gray-400 text-[10px] block">Polling Interval</span>
            <span className="text-white font-semibold">{workerStatus?.polling_interval_seconds || 30}s Cycle</span>
          </div>
          <div className="bg-[#131C31] p-2.5 rounded-lg border border-gray-800">
            <span className="text-gray-400 text-[10px] block">Completed Cycles</span>
            <span className="text-blue-400 font-semibold">{workerStatus?.total_cycles || 0} Sweeps</span>
          </div>
          <div className="bg-[#131C31] p-2.5 rounded-lg border border-gray-800">
            <span className="text-gray-400 text-[10px] block">Success / Failed</span>
            <span className="text-emerald-400 font-semibold">
              {workerStatus?.total_polls_succeeded || 0} <span className="text-gray-500">/</span>{" "}
              <span className="text-rose-400">{workerStatus?.total_polls_failed || 0}</span>
            </span>
          </div>
          <div className="bg-[#131C31] p-2.5 rounded-lg border border-gray-800">
            <span className="text-gray-400 text-[10px] block">Last Sweep Time</span>
            <span className="text-gray-200 font-semibold">{workerStatus?.last_cycle_at ? timeAgo(workerStatus.last_cycle_at) : "Pending"}</span>
          </div>
          <div className="bg-[#131C31] p-2.5 rounded-lg border border-gray-800">
            <span className="text-gray-400 text-[10px] block">Sweep Duration</span>
            <span className="text-emerald-400 font-semibold">{workerStatus?.last_cycle_duration_ms ? `${workerStatus.last_cycle_duration_ms.toFixed(1)}ms` : "0.0ms"}</span>
          </div>
        </div>
      </div>

      {/* Managed Nodes Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {devices.map((dev) => {
          const isSelected = selectedDevice?.id === dev.id;
          const isPollingThis = pollingId === dev.id;
          const isStale = dev.snmp_status === "stale" || (dev.last_polled_at && (new Date().getTime() - new Date(dev.last_polled_at).getTime()) > 180_000);
          const isDemo = dev.mgmt_ip?.startsWith("192.0.2.") || dev.mgmt_ip?.startsWith("127.") || dev.mgmt_ip?.startsWith("198.51.100.");

          return (
            <div
              key={dev.id}
              onClick={() => setSelectedDevice(dev)}
              className={`cursor-pointer bg-[#111827] border rounded-xl p-4 transition-all relative ${
                isSelected
                  ? "border-blue-500 shadow-lg shadow-blue-500/10 bg-[#131D33]"
                  : "border-[#1F2937] hover:border-gray-700"
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-blue-400" />
                  <span className="text-xs font-semibold text-white font-mono">{dev.hostname}</span>
                </div>
                {/* Visual Status Badges */}
                {dev.snmp_status === "ok" && !isStale ? (
                  <span className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    SNMP OK
                  </span>
                ) : isStale ? (
                  <span className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 font-bold">
                    <Clock className="w-3 h-3 text-yellow-400" />
                    STALE
                  </span>
                ) : dev.snmp_status === "timeout" ? (
                  <span className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold">
                    <AlertCircle className="w-3 h-3 text-amber-400" />
                    TIMEOUT
                  </span>
                ) : dev.snmp_status === "auth_error" ? (
                  <span className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-bold">
                    <AlertCircle className="w-3 h-3 text-rose-400" />
                    AUTH FAIL
                  </span>
                ) : (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700 font-bold">
                    STANDBY
                  </span>
                )}
              </div>

              {/* Specs & Hardware */}
              <div className="mt-3 text-xs text-gray-400 space-y-1 font-mono">
                <div className="flex justify-between">
                  <span>Target IP:</span>
                  <span className="text-gray-200">{dev.mgmt_ip}</span>
                </div>
                <div className="flex justify-between">
                  <span>Hardware:</span>
                  <span className="text-gray-200">{dev.vendor} {dev.model || "Router"}</span>
                </div>
                <div className="flex justify-between">
                  <span>UpTime:</span>
                  <span className="text-emerald-400 font-semibold">{formatUptime(dev.sys_uptime)}</span>
                </div>
                <div className="flex justify-between items-center pt-1 border-t border-gray-800/80">
                  <span className="text-[10px] text-gray-500">
                    Last Polled: {timeAgo(dev.last_polled_at)}
                  </span>
                  <span className="text-[10px] text-blue-400">
                    {dev.interfaces?.length || 0} Interfaces
                  </span>
                </div>
              </div>

              {/* Live Poll Action Button */}
              <div className="mt-3 pt-2 flex items-center justify-between">
                {isDemo ? (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-400 border border-violet-500/20 font-semibold">
                    DEMO TELEMETRY
                  </span>
                ) : (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                    LIVE SNMP
                  </span>
                )}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handlePoll(dev.id);
                  }}
                  disabled={isPollingThis}
                  className="flex items-center gap-1 px-2.5 py-1 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 rounded text-[11px] font-mono transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={`w-3 h-3 ${isPollingThis ? "animate-spin" : ""}`} />
                  <span>{isPollingThis ? "Polling..." : "Poll Now"}</span>
                </button>
              </div>

              {/* Feedback toast on card */}
              {pollFeedback && pollFeedback.id === dev.id && (
                <div
                  className={`mt-2 p-1.5 rounded text-[10px] font-mono text-center ${
                    pollFeedback.success
                      ? "bg-emerald-950/60 border border-emerald-500/30 text-emerald-300"
                      : "bg-rose-950/60 border border-rose-500/30 text-rose-300"
                  }`}
                >
                  {pollFeedback.msg}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Selected Device Interfaces Section */}
      {selectedDevice && (
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden shadow-sm">
          <div className="p-4 border-b border-[#1F2937] flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#0E1524]">
            <div>
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                  {selectedDevice.hostname} ({selectedDevice.mgmt_ip}) — Interfaces & Health
                </h3>
              </div>
              <p className="text-[11px] text-gray-400 font-mono mt-0.5">
                SysDescr: {selectedDevice.sys_descr || "Standard MIB-II Router Gateway"}
              </p>
            </div>

            <div className="flex items-center gap-3">
              <span className="text-[10px] font-mono text-gray-400">
                Poll Latency:{" "}
                <span className="text-emerald-400 font-semibold">
                  {selectedDevice.last_poll_duration_ms ? `${selectedDevice.last_poll_duration_ms.toFixed(1)}ms` : "N/A"}
                </span>
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#090D16] text-gray-400 border-b border-[#1F2937]">
                <tr>
                  <th className="py-2.5 px-3">Idx</th>
                  <th className="py-2.5 px-3">Interface</th>
                  <th className="py-2.5 px-3">Alias / Circuit</th>
                  <th className="py-2.5 px-3">Capacity</th>
                  <th className="py-2.5 px-3">Inbound (bps / pps)</th>
                  <th className="py-2.5 px-3">Outbound (bps / pps)</th>
                  <th className="py-2.5 px-3 w-44">Utilization %</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-center">History</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2937] text-gray-300">
                {(selectedDevice.interfaces || []).map((iface: any) => {
                  const util = iface.utilization_pct || 0;
                  const isUp = iface.oper_status === "up";

                  return (
                    <tr key={iface.id} className="hover:bg-[#151E32] transition-colors">
                      <td className="py-2.5 px-3 text-gray-500">#{iface.if_index}</td>
                      <td className="py-2.5 px-3 font-semibold text-blue-400">
                        {iface.if_name}
                      </td>
                      <td className="py-2.5 px-3 text-gray-200">
                        {iface.alias || "-"}
                      </td>
                      <td className="py-2.5 px-3 text-gray-400 font-semibold">
                        {formatBps(iface.speed_bps)}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="text-emerald-400 font-semibold">{formatBps(iface.in_bps)}</div>
                        <div className="text-[10px] text-gray-500">{formatPps(iface.in_pps)}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="text-blue-400 font-semibold">{formatBps(iface.out_bps)}</div>
                        <div className="text-[10px] text-gray-500">{formatPps(iface.out_pps)}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                            <div
                              className={`h-2 rounded-full transition-all duration-500 ${
                                util > 85 ? "bg-rose-500" : util > 70 ? "bg-amber-500" : "bg-blue-500"
                              }`}
                              style={{ width: `${Math.min(util, 100)}%` }}
                            />
                          </div>
                          <span className="text-[11px] w-10 text-right font-semibold">{util}%</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold inline-flex items-center gap-1 ${
                            isUp
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${isUp ? "bg-emerald-400" : "bg-rose-400"}`} />
                          {iface.oper_status.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <button
                          onClick={() => openInterfaceHistory(iface)}
                          className="p-1 hover:bg-gray-700/60 rounded text-gray-400 hover:text-blue-400 transition-colors"
                          title="View Historical Bandwidth Chart"
                        >
                          <TrendingUp className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Interface History Modal / Chart Drawer */}
      {historyInterface && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-4xl w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setHistoryInterface(null)}
              className="absolute top-4 right-4 p-1 hover:bg-gray-800 rounded text-gray-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="w-5 h-5 text-blue-400" />
              <div>
                <h3 className="text-base font-bold text-white font-mono">
                  {historyInterface.if_name} — Historical Bandwidth & Utilization
                </h3>
                <p className="text-xs text-gray-400 font-mono">
                  Circuit: {historyInterface.alias || "Direct Uplink"} | Speed: {formatBps(historyInterface.speed_bps)}
                </p>
              </div>
            </div>

            {historyLoading ? (
              <div className="h-64 flex items-center justify-center text-xs font-mono text-gray-400">
                <RefreshCw className="w-5 h-5 animate-spin mr-2 text-blue-400" />
                Querying database telemetry...
              </div>
            ) : historyData.length === 0 ? (
              <div className="h-64 flex flex-col items-center justify-center text-xs font-mono text-gray-400">
                <Clock className="w-8 h-8 text-gray-600 mb-2" />
                No historical samples recorded yet for this interface. Trigger consecutive polls to accumulate metrics.
              </div>
            ) : (
              <div className="space-y-4">
                {/* Bandwidth Chart */}
                <div className="bg-[#0D1322] border border-gray-800 rounded-lg p-3">
                  <div className="text-[11px] font-mono text-gray-400 mb-2 flex justify-between">
                    <span>Traffic Rate (Mbps)</span>
                    <div className="flex gap-4">
                      <span className="text-emerald-400">■ Inbound Traffic</span>
                      <span className="text-blue-400">■ Outbound Traffic</span>
                    </div>
                  </div>
                  <div className="h-56">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={historyData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
                        <XAxis dataKey="time" stroke="#6B7280" tick={{ fontSize: 10, fill: "#9CA3AF" }} />
                        <YAxis stroke="#6B7280" tick={{ fontSize: 10, fill: "#9CA3AF" }} unit=" Mbps" />
                        <Tooltip
                          contentStyle={{ backgroundColor: "#111827", borderColor: "#374151", fontSize: "11px", color: "#fff" }}
                        />
                        <Line type="monotone" dataKey="in_mbps" stroke="#10B981" strokeWidth={2} dot={false} name="Inbound (Mbps)" />
                        <Line type="monotone" dataKey="out_mbps" stroke="#3B82F6" strokeWidth={2} dot={false} name="Outbound (Mbps)" />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Utilization Chart */}
                <div className="bg-[#0D1322] border border-gray-800 rounded-lg p-3">
                  <div className="text-[11px] font-mono text-gray-400 mb-2">
                    <span>Capacity Utilization (%)</span>
                  </div>
                  <div className="h-28">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={historyData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" />
                        <XAxis dataKey="time" stroke="#6B7280" tick={{ fontSize: 10, fill: "#9CA3AF" }} />
                        <YAxis stroke="#6B7280" tick={{ fontSize: 10, fill: "#9CA3AF" }} domain={[0, 100]} unit="%" />
                        <Tooltip
                          contentStyle={{ backgroundColor: "#111827", borderColor: "#374151", fontSize: "11px", color: "#fff" }}
                        />
                        <Area type="monotone" dataKey="utilization_pct" stroke="#F59E0B" fill="#F59E0B20" name="Utilization %" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* SNMP Profiles Modal */}
      {showProfileModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-2xl w-full p-6 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setShowProfileModal(false)}
              className="absolute top-4 right-4 p-1 hover:bg-gray-800 rounded text-gray-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <Key className="w-5 h-5 text-blue-400" />
              <div>
                <h3 className="text-base font-bold text-white font-mono">SNMP Credentials & Profiles</h3>
                <p className="text-xs text-gray-400 font-mono">
                  AES-128 encrypted secrets at rest. Never exposed in API responses or logs.
                </p>
              </div>
            </div>

            {/* List existing profiles */}
            <div className="mb-6 space-y-2">
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider font-mono">Active Profiles</h4>
              {profiles.length === 0 ? (
                <div className="text-xs font-mono text-gray-500 p-3 bg-gray-900/50 rounded border border-gray-800">
                  No custom SNMP profiles configured yet. Defaulting to standard router discovery.
                </div>
              ) : (
                <div className="divide-y divide-gray-800 border border-gray-800 rounded-lg overflow-hidden bg-gray-900/40">
                  {profiles.map((p) => (
                    <div key={p.id} className="p-3 text-xs font-mono flex items-center justify-between">
                      <div>
                        <div className="font-semibold text-white">{p.name} ({p.version.toUpperCase()})</div>
                        <div className="text-[10px] text-gray-400 mt-0.5">
                          SecName: {p.security_name || "N/A"} | Port: {p.port} | Auth: {p.auth_protocol} | Priv: {p.priv_protocol}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-bold border border-emerald-500/20">
                          {p.has_auth_pass && p.has_priv_pass ? "authPriv Encrypted" : "Active"}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Form to add new profile */}
            <form onSubmit={handleCreateProfile} className="space-y-4 pt-4 border-t border-gray-800">
              <h4 className="text-xs font-semibold text-gray-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
                <Plus className="w-3.5 h-3.5 text-blue-400" />
                Add SNMP Profile
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                <div>
                  <label className="text-gray-400 block mb-1">Profile Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Juniper-MX-SNMPv3"
                    value={newProfile.name}
                    onChange={(e) => setNewProfile({ ...newProfile, name: e.target.value })}
                    className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="text-gray-400 block mb-1">SNMP Version</label>
                  <select
                    value={newProfile.version}
                    onChange={(e) => setNewProfile({ ...newProfile, version: e.target.value })}
                    className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="v3">SNMPv3 (authPriv Recommended)</option>
                    <option value="v2c">SNMPv2c (Community)</option>
                  </select>
                </div>
              </div>

              {newProfile.version === "v2c" ? (
                <div className="space-y-2 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg">
                  <p className="text-[11px] font-mono text-amber-300">
                    ⚠️ Warning: SNMPv2c transmits community strings in plaintext across the network. Consider SNMPv3 authPriv for production routers.
                  </p>
                  <div>
                    <label className="text-gray-400 block mb-1 text-xs font-mono">Community String</label>
                    <input
                      type="password"
                      placeholder="e.g. public"
                      value={newProfile.community}
                      onChange={(e) => setNewProfile({ ...newProfile, community: e.target.value })}
                      className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white text-xs font-mono focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-3 p-3 bg-gray-900/60 border border-gray-800 rounded-lg">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                    <div>
                      <label className="text-gray-400 block mb-1">Security User (USM)</label>
                      <input
                        type="text"
                        placeholder="e.g. noc_monitor"
                        value={newProfile.security_name}
                        onChange={(e) => setNewProfile({ ...newProfile, security_name: e.target.value })}
                        className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="text-gray-400 block mb-1">Auth Protocol</label>
                      <select
                        value={newProfile.auth_protocol}
                        onChange={(e) => setNewProfile({ ...newProfile, auth_protocol: e.target.value })}
                        className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                      >
                        <option value="SHA">SHA-1 (HMAC-SHA-96)</option>
                        <option value="SHA-256">SHA-256 (HMAC-SHA-256)</option>
                        <option value="MD5">MD5</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-gray-400 block mb-1">Auth Password</label>
                      <input
                        type="password"
                        placeholder="Authentication Secret"
                        value={newProfile.auth_pass}
                        onChange={(e) => setNewProfile({ ...newProfile, auth_pass: e.target.value })}
                        className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div>
                      <label className="text-gray-400 block mb-1">Privacy Protocol (Encryption)</label>
                      <select
                        value={newProfile.priv_protocol}
                        onChange={(e) => setNewProfile({ ...newProfile, priv_protocol: e.target.value })}
                        className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                      >
                        <option value="AES">AES-128 (CFB-128)</option>
                        <option value="AES-256">AES-256</option>
                        <option value="DES">DES (CBC-DES)</option>
                      </select>
                    </div>
                    <div>
                      <label className="text-gray-400 block mb-1">Privacy Password</label>
                      <input
                        type="password"
                        placeholder="Privacy Encryption Secret"
                        value={newProfile.priv_pass}
                        onChange={(e) => setNewProfile({ ...newProfile, priv_pass: e.target.value })}
                        className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-3 gap-3 text-xs font-mono">
                <div>
                  <label className="text-gray-400 block mb-1">Port</label>
                  <input
                    type="number"
                    value={newProfile.port}
                    onChange={(e) => setNewProfile({ ...newProfile, port: parseInt(e.target.value) || 161 })}
                    className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="text-gray-400 block mb-1">Timeout (sec)</label>
                  <input
                    type="number"
                    step="0.5"
                    value={newProfile.timeout_sec}
                    onChange={(e) => setNewProfile({ ...newProfile, timeout_sec: parseFloat(e.target.value) || 3.0 })}
                    className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="text-gray-400 block mb-1">Retries</label>
                  <input
                    type="number"
                    value={newProfile.retries}
                    onChange={(e) => setNewProfile({ ...newProfile, retries: parseInt(e.target.value) || 2 })}
                    className="w-full bg-[#0D1322] border border-gray-700 rounded px-2.5 py-1.5 text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setShowProfileModal(false)}
                  className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs font-mono"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-mono font-semibold"
                >
                  Save Profile
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
