"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  Filter,
  Download,
  Search,
  Radio,
  ArrowRight,
  TrendingUp,
} from "lucide-react";
import { api } from "@/lib/api";

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000_000_000) return `${(bytes / 1_000_000_000_000).toFixed(2)} TB`;
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(2)} KB`;
  return `${bytes} B`;
}

function getProtocolName(p: number): string {
  switch (p) {
    case 6:
      return "TCP";
    case 17:
      return "UDP";
    case 1:
      return "ICMP";
    default:
      return `Proto-${p}`;
  }
}

export default function TrafficExplorerPage() {
  const [flows, setFlows] = useState<any[]>([]);
  const [topTalkers, setTopTalkers] = useState<any[]>([]);
  const [trafficMatrix, setTrafficMatrix] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  // Filters
  const [srcIpFilter, setSrcIpFilter] = useState("");
  const [dstIpFilter, setDstIpFilter] = useState("");
  const [protocolFilter, setProtocolFilter] = useState<string>("");

  useEffect(() => {
    fetchData();
  }, []);

  async function fetchData() {
    setLoading(true);
    try {
      const params: any = {};
      if (srcIpFilter) params.src_ip = srcIpFilter;
      if (dstIpFilter) params.dst_ip = dstIpFilter;
      if (protocolFilter) params.protocol = parseInt(protocolFilter);

      const [flowsData, talkersData, matrixData] = await Promise.all([
        api.getFlows(params),
        api.getTopTalkers("src_ip", 6),
        api.getTrafficMatrix(5),
      ]);

      setFlows(flowsData);
      setTopTalkers(talkersData);
      setTrafficMatrix(matrixData);
    } catch (err) {
      console.error("Failed to load traffic data:", err);
    } finally {
      setLoading(false);
    }
  }

  function handleFilterSubmit(e: React.FormEvent) {
    e.preventDefault();
    fetchData();
  }

  return (
    <div className="space-y-6">
      {/* Title & Filter Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            Traffic Intelligence & Data Explorer
            <span className="noc-badge-demo text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
              FLOW ANALYZER v1
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Normalized NetFlow v5/v9, IPFIX, and sFlow telemetry with multi-field drilldown.
          </p>
        </div>

        <button
          onClick={() => {
            alert("Export CSV: Generating filtered flow records export.");
          }}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#111827] border border-[#1F2937] hover:border-gray-600 text-xs text-gray-300 font-mono transition-colors"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export CSV</span>
        </button>
      </div>

      {/* Top Talkers & Traffic Matrix Side-by-Side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Talkers */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
              <TrendingUp className="w-3.5 h-3.5 text-blue-400" />
              <span>Top Talkers (Source IPs)</span>
            </h3>
            <span className="text-[10px] text-gray-400 font-mono">Last 1 Hour</span>
          </div>

          <div className="space-y-2.5">
            {topTalkers.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2">
                  <span className="w-4 text-gray-500">{idx + 1}.</span>
                  <span className="text-gray-200">{item.key}</span>
                </div>
                <div className="flex items-center gap-4">
                  <div className="w-24 bg-gray-800 rounded-full h-1.5 overflow-hidden">
                    <div className="bg-blue-500 h-1.5 rounded-full" style={{ width: `${item.percentage}%` }} />
                  </div>
                  <span className="text-gray-400 w-12 text-right">{item.percentage}%</span>
                  <span className="text-white font-semibold w-20 text-right">{formatBytes(item.bytes)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Traffic Matrix */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-purple-400" />
              <span>Transit Traffic Matrix (Origin -&gt; Destination ASN)</span>
            </h3>
            <span className="text-[10px] text-gray-400 font-mono">Aggregated</span>
          </div>

          <div className="space-y-2.5">
            {trafficMatrix.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between text-xs font-mono bg-[#0D1322] p-2 rounded border border-[#1F2937]">
                <div className="flex items-center gap-2">
                  <span className="text-blue-300">{item.source}</span>
                  <ArrowRight className="w-3 h-3 text-gray-500" />
                  <span className="text-purple-300">{item.destination}</span>
                </div>
                <div className="text-white font-semibold">
                  {formatBytes(item.bytes)}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <form onSubmit={handleFilterSubmit} className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 flex-1 min-w-[200px]">
          <Search className="w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Filter Source IP (e.g. 103.145.2.14)..."
            value={srcIpFilter}
            onChange={(e) => setSrcIpFilter(e.target.value)}
            className="w-full bg-[#0D1322] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>

        <div className="min-w-[180px]">
          <input
            type="text"
            placeholder="Filter Destination IP..."
            value={dstIpFilter}
            onChange={(e) => setDstIpFilter(e.target.value)}
            className="w-full bg-[#0D1322] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>

        <div className="min-w-[120px]">
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="w-full bg-[#0D1322] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500 font-mono"
          >
            <option value="">All Protocols</option>
            <option value="6">TCP (6)</option>
            <option value="17">UDP (17)</option>
            <option value="1">ICMP (1)</option>
          </select>
        </div>

        <button
          type="submit"
          className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium transition-colors"
        >
          <Filter className="w-3.5 h-3.5" />
          <span>Apply Filters</span>
        </button>
      </form>

      {/* Raw / Normalized Flows Table */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
        <div className="p-4 border-b border-[#1F2937] flex items-center justify-between">
          <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
            Normalized Flow Records ({flows.length} events)
          </h3>
          <span className="text-[10px] text-gray-400 font-mono">ClickHouse Ingestion Table</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">POP</th>
                <th className="py-2.5 px-3">Source IP : Port</th>
                <th className="py-2.5 px-3">Destination IP : Port</th>
                <th className="py-2.5 px-3">Proto</th>
                <th className="py-2.5 px-3">Volume</th>
                <th className="py-2.5 px-3">Format</th>
                <th className="py-2.5 px-3">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937] text-gray-300">
              {flows.map((f, i) => (
                <tr key={i} className="hover:bg-[#151E32] transition-colors">
                  <td className="py-2.5 px-3 text-gray-400 whitespace-nowrap">
                    {new Date(f.timestamp).toISOString().replace("T", " ").substring(0, 19)}
                  </td>
                  <td className="py-2.5 px-3 text-blue-400">{f.site_id}</td>
                  <td className="py-2.5 px-3 text-white font-medium">
                    {f.src_ip}:{f.src_port}
                  </td>
                  <td className="py-2.5 px-3 text-white">
                    {f.dst_ip}:{f.dst_port}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                      f.protocol === 6 ? "bg-blue-500/10 text-blue-400" : "bg-purple-500/10 text-purple-400"
                    }`}>
                      {getProtocolName(f.protocol)}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <div>{formatBytes(f.bytes)}</div>
                    <div className="text-[10px] text-gray-500">{f.packets} pkts</div>
                  </td>
                  <td className="py-2.5 px-3 text-gray-400 uppercase text-[10px]">{f.flow_format}</td>
                  <td className="py-2.5 px-3">
                    {f.is_demo ? (
                      <span className="noc-badge-demo text-[10px] px-1.5 py-0.5 rounded font-mono">
                        DEMO
                      </span>
                    ) : (
                      <span className="noc-badge-live text-[10px] px-1.5 py-0.5 rounded font-mono">
                        LIVE
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
