"use client";

import React, { useEffect, useState } from "react";
import { ShieldAlert, Radio, Clock, LogOut } from "lucide-react";
import { useAuth } from "@/components/AuthProvider";

export default function TopBar() {
  const { user, logout } = useAuth();
  const [timeUtc, setTimeUtc] = useState<string>("");

  useEffect(() => {
    const updateTime = () => {
      setTimeUtc(new Date().toUTCString().replace("GMT", "UTC"));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const initials = (user?.username || "AD").slice(0, 2).toUpperCase();

  return (
    <header className="h-16 bg-[#0B0F19]/90 backdrop-blur border-b border-[#1F2937] flex items-center justify-between px-6 sticky top-0 z-20">
      {/* Critical Guardrail Banner */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono font-medium">
          <ShieldAlert className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
          <span>ROUTING EXECUTION: DISABLED (READ-ONLY / LAB MODE)</span>
        </div>
        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono">
          <Radio className="w-3 h-3 animate-ping" />
          <span>High-Rate Collector: Online</span>
        </div>
      </div>

      {/* Clock & User Profile */}
      <div className="flex items-center gap-4 text-xs font-mono text-gray-400">
        <div className="flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-gray-400" />
          <span>{timeUtc || "Loading UTC..."}</span>
        </div>
        <div className="h-4 w-px bg-[#1F2937]" />
        <div className="flex items-center gap-2 text-gray-300">
          <div className="w-6 h-6 rounded-full bg-blue-600/30 border border-blue-500/40 flex items-center justify-center text-[10px] text-blue-300 font-bold">
            {initials}
          </div>
          <span className="font-sans font-medium text-xs">
            {user?.username || "admin"} ({user?.role?.toUpperCase() || "SUPER_ADMIN"})
          </span>
          <button
            onClick={logout}
            className="ml-2 flex items-center gap-1 px-2 py-1 bg-gray-800 hover:bg-rose-500/20 hover:text-rose-300 text-gray-400 border border-gray-700 hover:border-rose-500/30 rounded text-xs transition-colors"
            title="Sign out"
          >
            <LogOut className="w-3 h-3" />
            <span className="hidden sm:inline">Logout</span>
          </button>
        </div>
      </div>
    </header>
  );
}
