"use client";

import React, { useEffect, useState } from "react";
import { ShieldAlert, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import { api } from "@/lib/api";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    async function load() {
      try {
        const data = await api.getAlerts();
        setAlerts(data);
      } catch {
        setAlerts([
          {
            id: 1,
            severity: "warning",
            title: "High Bandwidth Utilization on Uplink Indosat 20G",
            description: "Interface xe-0/0/1 on cr01.cgk.jdp.net exceeded 70% utilization threshold (currently 74%).",
            target_entity: "cr01.cgk.jdp.net:xe-0/0/1",
            status: "active",
            started_at: new Date(Date.now() - 3600000).toISOString(),
          },
        ]);
      }
    }
    load();
  }, []);

  async function handleAcknowledge(id: number) {
    try {
      await api.acknowledgeAlert(id, "Investigating interface utilization with shift lead.");
      setAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, status: "acknowledged", acknowledged_by: "admin" } : a))
      );
    } catch (err: any) {
      alert(`Ack failed: ${err.message}`);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
          Alerts & Incident Management
          <span className="noc-badge-live text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
            STATUS ENGINE
          </span>
        </h2>
        <p className="text-xs text-gray-400 mt-0.5">
          Real-time interface threshold breaches, BGP peer flaps, packet loss anomalies, and collector drops.
        </p>
      </div>

      <div className="space-y-4">
        {alerts.map((alt) => (
          <div key={alt.id} className="bg-[#111827] border border-[#1F2937] rounded-xl p-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white font-mono">{alt.title}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 font-bold uppercase">
                      {alt.severity}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      alt.status === "active" ? "bg-rose-500/10 text-rose-400" : "bg-blue-500/10 text-blue-400"
                    }`}>
                      {alt.status}
                    </span>
                  </div>
                  <p className="text-xs text-gray-300 font-mono mt-1.5">{alt.description}</p>
                  <div className="flex items-center gap-4 mt-2 text-[10px] text-gray-400 font-mono">
                    <div>Entity: <span className="text-blue-400">{alt.target_entity}</span></div>
                    <div>Started: {new Date(alt.started_at).toISOString().replace("T", " ").substring(0, 19)} UTC</div>
                    {alt.acknowledged_by && <div>Ack By: <span className="text-emerald-400">{alt.acknowledged_by}</span></div>}
                  </div>
                </div>
              </div>

              {alt.status === "active" && (
                <button
                  onClick={() => handleAcknowledge(alt.id)}
                  className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-mono font-medium transition-colors whitespace-nowrap"
                >
                  Acknowledge Alert
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
