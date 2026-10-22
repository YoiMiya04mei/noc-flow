"use client";

import React, { useEffect, useState } from "react";
import { Settings, ShieldCheck, Plus, AlertCircle, CheckCircle2 } from "lucide-react";
import { api } from "@/lib/api";

export default function AdminPage() {
  const [prefixes, setPrefixes] = useState<any[]>([]);
  const [newPrefix, setNewPrefix] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  const [users, setUsers] = useState<any[]>([
    { id: 1, username: "admin", email: "admin@jdp-noc.net", role: "super_admin", status: "active" },
    { id: 2, username: "engineer1", email: "engineer@jdp-noc.net", role: "network_engineer", status: "active" },
    { id: 3, username: "lead_approver", email: "approver@jdp-noc.net", role: "approver", status: "active" },
    { id: 4, username: "operator1", email: "operator@jdp-noc.net", role: "noc_operator", status: "active" },
    { id: 5, username: "auditor1", email: "auditor@jdp-noc.net", role: "auditor", status: "active" },
  ]);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    try {
      const data = await api.getPrefixAllowlists();
      setPrefixes(data);
    } catch {
      setPrefixes([
        { id: 1, prefix: "103.145.2.0/24", description: "Customer Core Block A - Subnet JDP", is_active: true },
        { id: 2, prefix: "103.145.3.0/24", description: "Customer Core Block B - Subnet JDP", is_active: true },
      ]);
    }
  }

  async function handleAddPrefix(e: React.FormEvent) {
    e.preventDefault();
    setErrorMsg("");
    setSuccessMsg("");

    // Client-side quick guardrail validation
    if (newPrefix.trim() === "0.0.0.0/0" || newPrefix.trim() === "::/0") {
      setErrorMsg("SAFETY GUARDRAIL VIOLATION: Default route (0.0.0.0/0 or ::/0) can NEVER be allowlisted!");
      return;
    }

    try {
      await api.addPrefixAllowlist({ prefix: newPrefix.trim(), description: newDesc.trim() });
      setSuccessMsg(`Prefix ${newPrefix} successfully added to allowlist.`);
      setNewPrefix("");
      setNewDesc("");
      loadData();
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to add prefix allowlist");
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
          Administration & Routing Policy Guardrails
          <span className="noc-badge-live text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
            DENY-BY-DEFAULT
          </span>
        </h2>
        <p className="text-xs text-gray-400 mt-0.5">
          Manage BGP prefix allowlists, transit peer restrictions, and role-based access control (RBAC).
        </p>
      </div>

      {/* Prefix Allowlist Section */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5">
        <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
          <div>
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Prefix Allowlists (Deny-by-Default BGP Routing Protection)</span>
            </h3>
            <p className="text-[10px] text-gray-400 font-mono mt-0.5">
              Only prefixes registered here can be simulated or targeted for routing changes. Default route (0.0.0.0/0) and bogons are permanently forbidden.
            </p>
          </div>
        </div>

        {errorMsg && (
          <div className="mt-3 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-300 text-xs font-mono flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div className="mt-3 p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-300 text-xs font-mono flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Add Prefix Form */}
        <form onSubmit={handleAddPrefix} className="mt-4 flex flex-wrap items-center gap-3">
          <div className="min-w-[200px] flex-1">
            <input
              type="text"
              placeholder="Prefix CIDR (e.g. 203.0.113.0/24)..."
              value={newPrefix}
              onChange={(e) => setNewPrefix(e.target.value)}
              required
              className="w-full bg-[#0D1322] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="min-w-[260px] flex-1">
            <input
              type="text"
              placeholder="Description (e.g. Transit block customer)..."
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              className="w-full bg-[#0D1322] border border-[#1F2937] rounded-lg px-3 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <button
            type="submit"
            className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-mono font-medium transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Allowlist</span>
          </button>
        </form>

        {/* Prefix Table */}
        <div className="mt-4 overflow-x-auto border border-[#1F2937] rounded-lg">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
              <tr>
                <th className="py-2.5 px-3">Allowed Prefix (CIDR)</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3">Policy Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937] text-gray-300">
              {prefixes.map((p) => (
                <tr key={p.id} className="hover:bg-[#151E32]">
                  <td className="py-2.5 px-3 font-bold text-emerald-400">{p.prefix}</td>
                  <td className="py-2.5 px-3 text-gray-300">{p.description || "-"}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 font-bold">
                      ACTIVE (PERMITTED)
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* RBAC Users Table */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5">
        <h3 className="text-xs font-semibold text-white uppercase tracking-wider mb-3">
          Role-Based Access Control (RBAC) Accounts
        </h3>

        <div className="overflow-x-auto border border-[#1F2937] rounded-lg">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
              <tr>
                <th className="py-2.5 px-3">Username</th>
                <th className="py-2.5 px-3">Email</th>
                <th className="py-2.5 px-3">RBAC Role</th>
                <th className="py-2.5 px-3">Account Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937] text-gray-300">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-[#151E32]">
                  <td className="py-2.5 px-3 font-semibold text-white">{u.username}</td>
                  <td className="py-2.5 px-3 text-gray-400">{u.email}</td>
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-blue-500/10 text-blue-400 font-bold uppercase">
                      {u.role.replace("_", " ")}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-emerald-400 uppercase">{u.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
