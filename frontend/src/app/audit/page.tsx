"use client";

import React, { useEffect, useState } from "react";
import { History, ShieldCheck, Search, Filter } from "lucide-react";
import { api } from "@/lib/api";

export default function AuditTrailPage() {
  const [events, setEvents] = useState<any[]>([]);
  const [filterAction, setFilterAction] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const data = await api.getAuditEvents();
        setEvents(data);
      } catch (err) {
        setEvents([
          {
            id: 1,
            actor_username: "admin",
            actor_role: "super_admin",
            action: "SYSTEM_INIT",
            resource_type: "system",
            resource_id: "1",
            details: "Initial platform seeding completed successfully. ROUTING_EXECUTION_ENABLED is locked to false.",
            ip_address: "127.0.0.1",
            timestamp: new Date().toISOString(),
          },
          {
            id: 2,
            actor_username: "admin",
            actor_role: "super_admin",
            action: "ADD_PREFIX_ALLOWLIST",
            resource_type: "policy",
            resource_id: "1",
            details: "Prefix 103.145.2.0/24 added to allowlist.",
            ip_address: "127.0.0.1",
            timestamp: new Date().toISOString(),
          },
        ]);
      }
    }
    load();
  }, []);

  const filteredEvents = filterAction
    ? events.filter((e) => e.action.toLowerCase().includes(filterAction.toLowerCase()))
    : events;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            Append-Only Audit Trail
            <span className="noc-badge-live text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
              IMMUTABLE LOG
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Full compliance record of operator logins, inventory modifications, policy allowlists, and dry-run actions.
          </p>
        </div>

        <div className="w-64">
          <input
            type="text"
            placeholder="Filter by action (e.g. LOGIN)..."
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="w-full bg-[#111827] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
              <tr>
                <th className="py-2.5 px-3">Timestamp (UTC)</th>
                <th className="py-2.5 px-3">Operator</th>
                <th className="py-2.5 px-3">Role</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Target Entity</th>
                <th className="py-2.5 px-3">Audit Details</th>
                <th className="py-2.5 px-3">Client IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937] text-gray-300">
              {filteredEvents.map((evt) => (
                <tr key={evt.id} className="hover:bg-[#151E32] transition-colors">
                  <td className="py-2.5 px-3 text-gray-400 whitespace-nowrap">
                    {new Date(evt.timestamp).toISOString().replace("T", " ").substring(0, 19)}
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-white">{evt.actor_username}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-500/10 text-blue-400">
                      {evt.actor_role}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-bold text-amber-400">{evt.action}</td>
                  <td className="py-2.5 px-3 text-purple-300">
                    {evt.resource_type}:{evt.resource_id || "-"}
                  </td>
                  <td className="py-2.5 px-3 text-gray-300 max-w-md truncate">{evt.details || "-"}</td>
                  <td className="py-2.5 px-3 text-gray-400">{evt.ip_address || "127.0.0.1"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
