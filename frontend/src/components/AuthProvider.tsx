"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { ShieldCheck, Lock, User as UserIcon, AlertCircle, ArrowRight, Loader2 } from "lucide-react";
import { api, getAuthToken, setAuthToken, clearAuthToken } from "@/lib/api";

interface UserProfile {
  id?: number;
  username: string;
  role: string;
  full_name?: string;
  email?: string;
}

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  logout: () => {},
  refreshUser: async () => {},
});

export const useAuth = () => useContext(AuthContext);

export default function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setTokenState] = useState<string | null>(null);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [checking, setChecking] = useState<boolean>(true);

  // Form states for Login
  const [usernameInput, setUsernameInput] = useState("");
  const [passwordInput, setPasswordInput] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchProfile = async () => {
    try {
      const profile = await api.getMe();
      setUser(profile);
    } catch {
      // Token expired or invalid
      handleLogout();
    }
  };

  useEffect(() => {
    const existingToken = getAuthToken();
    if (existingToken) {
      setTokenState(existingToken);
      fetchProfile().finally(() => setChecking(false));
    } else {
      setChecking(false);
    }
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSubmitting(true);

    try {
      const res = await api.login(usernameInput, passwordInput);
      setAuthToken(res.access_token);
      setTokenState(res.access_token);
      setUser({
        username: res.username,
        role: res.role,
      });
      // Also fetch full user details if needed
      try {
        const profile = await api.getMe();
        setUser(profile);
      } catch {
        // Fallback to res if getMe is delayed
      }
    } catch (err: any) {
      setErrorMessage(err?.message || "Invalid username or password. Please verify your credentials.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleLogout = () => {
    clearAuthToken();
    setTokenState(null);
    setUser(null);
  };

  // 1. Initial Checking Screen
  if (checking) {
    return (
      <div className="min-h-screen bg-[#0B0F19] flex flex-col items-center justify-center text-gray-400 font-mono">
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin mb-4" />
        <p className="text-xs">Authenticating NOC Session...</p>
      </div>
    );
  }

  // 2. Unauthenticated: Full-Page Login Screen
  if (!token || !user) {
    return (
      <div className="min-h-screen bg-[#0B0F19] flex items-center justify-center p-4 relative overflow-hidden">
        {/* Subtle grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f293715_1px,transparent_1px),linear-gradient(to_bottom,#1f293715_1px,transparent_1px)] bg-[size:4rem_4rem]" />
        
        <div className="relative w-full max-w-md bg-[#111827] border border-gray-800 rounded-2xl shadow-2xl p-8 backdrop-blur-xl">
          {/* Header */}
          <div className="flex flex-col items-center text-center mb-8">
            <div className="w-14 h-14 rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 mb-4 shadow-lg shadow-blue-500/10">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <h1 className="text-xl font-bold text-white tracking-tight font-mono">
              JDP Route Intelligence
            </h1>
            <p className="text-xs text-gray-400 mt-1 font-mono">
              NOC Flow Analytics & Intelligent BGP Optimization
            </p>
          </div>

          {/* Error Banner */}
          {errorMessage && (
            <div className="mb-6 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg flex items-start gap-2.5 text-xs text-rose-300 font-mono">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-gray-300 mb-1.5 font-medium">
                Username / Operator ID
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-500">
                  <UserIcon className="w-4 h-4" />
                </div>
                <input
                  type="text"
                  required
                  autoFocus
                  placeholder="e.g. admin"
                  value={usernameInput}
                  onChange={(e) => setUsernameInput(e.target.value)}
                  className="w-full bg-[#0B0F19] border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-mono text-gray-300 mb-1.5 font-medium">
                Password
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-500">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  className="w-full bg-[#0B0F19] border border-gray-700 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono transition-colors"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full mt-2 flex items-center justify-center gap-2 py-2.5 px-4 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 disabled:opacity-50 text-white rounded-lg text-sm font-semibold font-mono transition-colors shadow-lg shadow-blue-600/20"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <span>Sign In to NOC Portal</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Footer note */}
          <div className="mt-8 pt-4 border-t border-gray-800 text-center">
            <p className="text-[11px] text-gray-500 font-mono">
              Protected by 5-Level RBAC & Dual-Audit Trail
            </p>
          </div>
        </div>
      </div>
    );
  }

  // 3. Authenticated: Render dashboard children with Auth Context
  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        logout: handleLogout,
        refreshUser: fetchProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
