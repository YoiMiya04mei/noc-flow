"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowDownRight,
  ArrowUpRight,
  Activity,
  Server,
  Network,
  Zap,
  AlertTriangle,
  RefreshCw,
  Info,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { api } from "@/lib/api";

function formatBps(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(2)} Kbps`;
  return `${bps} bps`;
}

function formatPps(pps: number): string {
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(2)} Mpps`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(1)} Kpps`;
  return `${pps} pps`;
}

export default function OverviewPage() {
  const [summary, setSummary] = useState<any>({
    inbound_bps: 4850000000,
    outbound_bps: 2120000000,
    total_pps: 680000,
    active_exporters_count: 3,
    total_devices: 3,
    online_devices: 3,
    bgp_peers_established: 2,
    bgp_peers_total: 2,
    active_incidents_count: 1,
    routing_recommendations_count: 1,
    routing_execution_enabled: false,
    data_freshness_seconds: 5,
    is_demo_data: true,
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadData() {
      try {
        const data = await api.getDashboardSummary();
        setSummary(data);
      } catch (err) {
        // Keeps deterministic fallback
      }
    }
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  // Mock time-series chart data
  const chartData = [
    { time: "09:00", inbound: 4.2, outbound: 1.8 },
    { time: "09:05", inbound: 4.5, outbound: 2.0 },
    { time: "09:10", inbound: 4.8, outbound: 2.1 },
    { time: "09:15", inbound: 5.1, outbound: 2.3 },
    { time: "09:20", inbound: 4.9, outbound: 2.1 },
    { time: "09:25", inbound: 4.85, outbound: 2.12 },
  ];

  return (
    <div className="space-y-6">
      {/* Top Header & Freshness Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            NOC Operations Overview
            {summary.is_demo_data ? (
              <span className="noc-badge-demo text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
                DEMO / SIMULATED DATA
              </span>
            ) : (
              <span className="noc-badge-live text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
                LIVE TELEMETRY
              </span>
            )}
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Real-time multi-homing transit traffic, BGP status, and flow metrics.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-xs font-mono text-gray-400 flex items-center gap-1.5 bg-[#111827] px-3 py-1.5 rounded-lg border border-[#1F2937]">
            <RefreshCw className="w-3.5 h-3.5 text-blue-400" />
            <span>Freshness: {summary.data_freshness_seconds}s ago</span>
          </div>
        </div>
      </div>

      {/* KPI Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Inbound Bandwidth */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Inbound Aggregate</span>
            <ArrowDownRight className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">
            {formatBps(summary.inbound_bps)}
          </div>
          <div className="mt-1 text-[11px] text-gray-400 font-mono">
            Packets: {formatPps(summary.total_pps)}
          </div>
        </div>

        {/* Outbound Bandwidth */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Outbound Aggregate</span>
            <ArrowUpRight className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">
            {formatBps(summary.outbound_bps)}
          </div>
          <div className="mt-1 text-[11px] text-gray-400 font-mono">
            Active Exporters: {summary.active_exporters_count}
          </div>
        </div>

        {/* BGP Peers */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>BGP Transit Peers</span>
            <Network className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">
            {summary.bgp_peers_established} / {summary.bgp_peers_total}
          </div>
          <div className="mt-1 text-[11px] text-emerald-400 font-mono flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            100% Established
          </div>
        </div>

        {/* Route Optimization Candidates */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Route Optimization</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-white">
            {summary.routing_recommendations_count} Pending
          </div>
          <div className="mt-1 text-[11px] text-amber-400 font-mono">
            {summary.active_incidents_count} Alert / Incident
          </div>
        </div>
      </div>

      {/* Aggregate Traffic Area Chart */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-white">Aggregated Bandwidth Trend (Gbps)</h3>
            <p className="text-xs text-gray-400 font-mono">POP-CGK-1 Transit Interfaces</p>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded bg-emerald-500" />
              <span className="text-gray-300">Inbound</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded bg-blue-500" />
              <span className="text-gray-300">Outbound</span>
            </div>
          </div>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="inboundGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10B981" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="outboundGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#4B5563" fontSize={11} />
              <YAxis stroke="#4B5563" fontSize={11} tickFormatter={(val) => `${val}G`} />
              <Tooltip
                contentStyle={{ backgroundColor: "#0D1322", borderColor: "#1F2937", borderRadius: 8, fontSize: 12 }}
              />
              <Area type="monotone" dataKey="inbound" stroke="#10B981" fill="url(#inboundGrad)" strokeWidth={2} />
              <Area type="monotone" dataKey="outbound" stroke="#3B82F6" fill="url(#outboundGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Quick Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          href="/traffic"
          className="bg-[#111827] border border-[#1F2937] hover:border-blue-500/50 rounded-xl p-4 transition-all group"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white group-hover:text-blue-400">
            <Activity className="w-4 h-4 text-blue-400" />
            <span>Flow Analyzer & Data Explorer</span>
          </div>
          <p className="text-xs text-gray-400 mt-2">
            Inspect raw NetFlow/IPFIX/sFlow feeds, drill-down top talkers, ASNs, and protocols.
          </p>
        </Link>

        <Link
          href="/optimization"
          className="bg-[#111827] border border-[#1F2937] hover:border-amber-500/50 rounded-xl p-4 transition-all group"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white group-hover:text-amber-400">
            <Zap className="w-4 h-4 text-amber-400" />
            <span>Route Optimization & Simulator</span>
          </div>
          <p className="text-xs text-gray-400 mt-2">
            Evaluate multi-metric routing recommendations and execute dry-run simulations.
          </p>
        </Link>

        <Link
          href="/audit"
          className="bg-[#111827] border border-[#1F2937] hover:border-purple-500/50 rounded-xl p-4 transition-all group"
        >
          <div className="flex items-center gap-2 text-sm font-semibold text-white group-hover:text-purple-400">
            <Server className="w-4 h-4 text-purple-400" />
            <span>Security & Audit Trail</span>
          </div>
          <p className="text-xs text-gray-400 mt-2">
            Review immutable append-only operational events, approvals, and system changes.
          </p>
        </Link>
      </div>
    </div>
  );
}
