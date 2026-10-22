"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Activity,
  Server,
  Radio,
  Network,
  Zap,
  ShieldAlert,
  Sliders,
  History,
  Settings,
  ShieldCheck,
} from "lucide-react";

const navigationItems = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  { name: "Traffic Intelligence", href: "/traffic", icon: Activity },
  { name: "Devices & Inventory", href: "/devices", icon: Server },
  { name: "Flow Collectors", href: "/collectors", icon: Radio },
  { name: "BGP Visibility", href: "/bgp", icon: Network },
  { name: "Route Optimization", href: "/optimization", icon: Zap },
  { name: "Alerts & Incidents", href: "/alerts", icon: ShieldAlert },
  { name: "Audit Trail", href: "/audit", icon: History },
  { name: "Administration", href: "/admin", icon: Settings },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-[#0D1322] border-r border-[#1F2937] flex flex-col h-screen fixed left-0 top-0 z-30 select-none">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-6 border-b border-[#1F2937] gap-3">
        <div className="w-8 h-8 rounded bg-blue-600 flex items-center justify-center font-bold text-white shadow-lg shadow-blue-500/30">
          JDP
        </div>
        <div>
          <h1 className="font-bold text-sm tracking-wide text-white">ROUTE INTEL</h1>
          <p className="text-[10px] text-gray-400 uppercase tracking-wider font-mono">Platform NOC / ISP</p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navigationItems.map((item) => {
          const isActive = pathname === item.href;
          const Icon = item.icon;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? "bg-blue-600/15 text-blue-400 border border-blue-500/30 font-semibold"
                  : "text-gray-300 hover:bg-[#111827] hover:text-white"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-blue-400" : "text-gray-400"}`} />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Safety Guardrail Status Card at Sidebar Bottom */}
      <div className="p-4 border-t border-[#1F2937] bg-[#090D16]">
        <div className="flex items-center gap-2 mb-1.5">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span className="text-[11px] font-semibold text-gray-200 uppercase tracking-wider">Guardrails Active</span>
        </div>
        <p className="text-[10px] text-gray-400 leading-relaxed font-mono">
          Execution: <span className="text-amber-400 font-bold">LOCKED (OFF)</span>
          <br />
          Prefix Policy: <span className="text-emerald-400 font-bold">DENY-BY-DEFAULT</span>
        </p>
      </div>
    </aside>
  );
}
