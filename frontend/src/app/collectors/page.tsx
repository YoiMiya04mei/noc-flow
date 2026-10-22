"use client";

import React, { useEffect, useState } from "react";
import { Radio, Activity, CheckCircle, AlertTriangle } from "lucide-react";
import { api } from "@/lib/api";

export default function CollectorsPage() {
  const [collectors, setCollectors] = useState<any[]>([]);

  useEffect(() => {
    async function load() {
      try {
        const data = await api.getCollectors();
        setCollectors(data);
      } catch (err) {
        setCollectors([
          {
            id: 1,
            name: "Collector-CGK-Primary",
            host: "10.250.0.50",
            port: 2055,
            collector_type: "netflow",
            status: "active",
            packets_received: 142500000,
            flows_parsed: 980000000,
            parse_errors: 12,
          },
          {
            id: 2,
            name: "Collector-SUB-Secondary",
            host: "10.250.1.50",
            port: 6343,
            collector_type: "sflow",
            status: "active",
            packets_received: 45000000,
            flows_parsed: 310000000,
            parse_errors: 4,
          },
        ]);
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
          High-Rate Flow Collectors
          <span className="noc-badge-live text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
            GO ENGINE: ACTIVE
          </span>
        </h2>
        <p className="text-xs text-gray-400 mt-0.5">
          Standalone Go UDP ingestion workers, buffer queues, packet parsing stats, and ClickHouse flush latency.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {collectors.map((c) => (
          <div key={c.id} className="bg-[#111827] border border-[#1F2937] rounded-xl p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Radio className="w-5 h-5 text-blue-400" />
                <div>
                  <h3 className="text-sm font-semibold text-white">{c.name}</h3>
                  <p className="text-xs text-gray-400 font-mono">
                    {c.host}:{c.port} ({c.collector_type.toUpperCase()})
                  </p>
                </div>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                {c.status.toUpperCase()}
              </span>
            </div>

            <div className="grid grid-cols-3 gap-3 mt-4 pt-4 border-t border-[#1F2937] text-center font-mono">
              <div className="bg-[#0D1322] p-2.5 rounded border border-[#1F2937]">
                <div className="text-[10px] text-gray-400">Packets</div>
                <div className="text-sm font-bold text-white mt-0.5">
                  {(c.packets_received / 1_000_000).toFixed(1)}M
                </div>
              </div>
              <div className="bg-[#0D1322] p-2.5 rounded border border-[#1F2937]">
                <div className="text-[10px] text-gray-400">Flows Parsed</div>
                <div className="text-sm font-bold text-blue-400 mt-0.5">
                  {(c.flows_parsed / 1_000_000).toFixed(1)}M
                </div>
              </div>
              <div className="bg-[#0D1322] p-2.5 rounded border border-[#1F2937]">
                <div className="text-[10px] text-gray-400">Parse Errors</div>
                <div className="text-sm font-bold text-emerald-400 mt-0.5">{c.parse_errors}</div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
