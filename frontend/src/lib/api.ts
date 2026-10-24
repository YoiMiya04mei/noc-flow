// API Client for JDP Route Intelligence Platform

function getApiBase(): string {
  if (typeof window !== "undefined") {
    // In client browser: ALWAYS use relative path so requests go through Nginx to current origin (https://nocflow.jembatandata.com/api/v1/...)
    return "";
  }
  // In server-side SSR: route to backend container
  return process.env.NEXT_PUBLIC_API_URL || "http://backend:8000";
}

let authToken: string | null = null;

export function setAuthToken(token: string) {
  authToken = token;
  if (typeof window !== "undefined") {
    localStorage.setItem("jdp_token", token);
  }
}

export function getAuthToken(): string | null {
  if (authToken) return authToken;
  if (typeof window !== "undefined") {
    return localStorage.getItem("jdp_token");
  }
  return null;
}

export function clearAuthToken() {
  authToken = null;
  if (typeof window !== "undefined") {
    localStorage.removeItem("jdp_token");
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const base = getApiBase();
  const res = await fetch(`${base}${endpoint}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let errorDetail = `API request failed with status ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorDetail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // fallback
    }
    throw new Error(errorDetail);
  }

  return res.json();
}

export const api = {
  // Auth
  login: (username: string, password: string) =>
    request<{ access_token: string; role: string; username: string }>("/api/v1/auth/login-json", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  getMe: () => request<any>("/api/v1/auth/me"),

  // Dashboard
  getDashboardSummary: () => request<any>("/api/v1/dashboard/summary"),

  // Flow Analytics
  getFlows: (params: Record<string, any> = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.append(k, String(v));
    });
    return request<any[]>(`/api/v1/flows?${qs.toString()}`);
  },
  getTopTalkers: (dimension = "src_ip", limit = 10) =>
    request<any[]>(`/api/v1/flows/top-talkers?dimension=${dimension}&limit=${limit}`),
  getTrafficMatrix: (limit = 10) =>
    request<any[]>(`/api/v1/flows/traffic-matrix?limit=${limit}`),

  // Devices & Inventory & SNMP
  getDevices: () => request<any[]>("/api/v1/devices"),
  getDevice: (id: number) => request<any>(`/api/v1/devices/${id}`),
  createDevice: (data: any) =>
    request<any>("/api/v1/devices", { method: "POST", body: JSON.stringify(data) }),
  deleteDevice: (id: number) =>
    request<void>(`/api/v1/devices/${id}`, { method: "DELETE" }),
  getCollectors: () => request<any[]>("/api/v1/collectors"),
  getCollectorHealth: (id: number) => request<any>(`/api/v1/collectors/${id}/health`),
  getSNMPProfiles: () => request<any[]>("/api/v1/devices/snmp/profiles"),
  createSNMPProfile: (data: any) =>
    request<any>("/api/v1/devices/snmp/profiles", { method: "POST", body: JSON.stringify(data) }),
  updateSNMPProfile: (id: number, data: any) =>
    request<any>(`/api/v1/devices/snmp/profiles/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  deleteSNMPProfile: (id: number) =>
    request<void>(`/api/v1/devices/snmp/profiles/${id}`, { method: "DELETE" }),
  assignDeviceSNMPProfile: (deviceId: number, snmpProfileId: number | null) =>
    request<any>(`/api/v1/devices/${deviceId}/snmp-profile`, {
      method: "PUT",
      body: JSON.stringify({ snmp_profile_id: snmpProfileId }),
    }),
  pollDevice: (deviceId: number, forceMock = false) =>
    request<any>(`/api/v1/devices/${deviceId}/poll`, {
      method: "POST",
      body: JSON.stringify({ force_mock: forceMock }),
    }),
  getInterfaceHistory: (deviceId: number, interfaceId: number, limit = 50) =>
    request<any[]>(`/api/v1/devices/${deviceId}/interfaces/${interfaceId}/history?limit=${limit}`),
  getSNMPWorkerStatus: () => request<any>("/api/v1/devices/snmp/worker-status"),
  triggerSNMPWorkerCycle: () => request<any>("/api/v1/devices/snmp/worker-trigger", { method: "POST" }),

  // BGP & BMP (RFC 7854)
  getBGPPeers: () => request<any[]>("/api/v1/bgp/peers"),
  getBGPPeer: (id: number) => request<any>(`/api/v1/bgp/peers/${id}`),
  getBGPRoutes: (prefix?: string) =>
    request<any[]>(`/api/v1/bgp/routes${prefix ? `?prefix=${encodeURIComponent(prefix)}` : ""}`),
  getBGPRouteEvents: (limit = 50) => request<any[]>(`/api/v1/bgp/events?limit=${limit}`),
  getBMPStatus: () => request<any>("/api/v1/bgp/bmp/status"),
  simulateBMPPacket: (data: any) =>
    request<any>("/api/v1/bgp/bmp/simulate", { method: "POST", body: JSON.stringify(data) }),

  // Active Path Probing
  getProbeTargets: () => request<any[]>("/api/v1/probes/targets"),
  createProbeTarget: (data: any) =>
    request<any>("/api/v1/probes/targets", { method: "POST", body: JSON.stringify(data) }),
  updateProbeTarget: (id: number, data: any) =>
    request<any>(`/api/v1/probes/targets/${id}`, { method: "PUT", body: JSON.stringify(data) }),
  deleteProbeTarget: (id: number) =>
    request<void>(`/api/v1/probes/targets/${id}`, { method: "DELETE" }),
  getProbeResults: (targetId?: number, limit = 50) =>
    request<any[]>(`/api/v1/probes/results?${targetId ? `target_id=${targetId}&` : ""}limit=${limit}`),
  getProbeWorkerStatus: () => request<any>("/api/v1/probes/worker-status"),
  executeProbeNow: (targetId?: number) =>
    request<any>(`/api/v1/probes/execute-now${targetId ? `?target_id=${targetId}` : ""}`, { method: "POST" }),
  getEgressCapabilities: () => request<any>("/api/v1/probes/egress-capabilities"),

  // Recommendations & Simulation (Phase 5)
  getRecommendations: (params?: { prefix?: string; status?: string; risk_level?: string; min_score?: number }) => {
    const q = new URLSearchParams();
    if (params?.prefix) q.append("prefix", params.prefix);
    if (params?.status) q.append("status", params.status);
    if (params?.risk_level) q.append("risk_level", params.risk_level);
    if (params?.min_score !== undefined) q.append("min_score", params.min_score.toString());
    const qs = q.toString();
    return request<any[]>(`/api/v1/recommendations${qs ? `?${qs}` : ""}`);
  },
  getRecommendationDetail: (id: number) => request<any>(`/api/v1/recommendations/${id}`),
  evaluateRecommendations: (data: { prefix?: string; policy_id?: number; force_refresh?: boolean }) =>
    request<any>("/api/v1/recommendations/evaluate", { method: "POST", body: JSON.stringify(data) }),
  simulateRecommendation: (id: number) =>
    request<any>(`/api/v1/recommendations/${id}/simulate`, { method: "POST" }),
  simulateCustomRoute: (data: { prefix: string; target_peer: string; current_path?: string; as_path_prepend?: number; community?: string }) =>
    request<any>("/api/v1/recommendations/simulate-custom", { method: "POST", body: JSON.stringify(data) }),

  // Change Management & Dual-Approval Workflow (Phase 5)
  getChangeRequests: (params?: { status?: string; prefix?: string }) => {
    const q = new URLSearchParams();
    if (params?.status) q.append("status", params.status);
    if (params?.prefix) q.append("prefix", params.prefix);
    const qs = q.toString();
    return request<any[]>(`/api/v1/change-requests${qs ? `?${qs}` : ""}`);
  },
  getChangeRequest: (id: number) => request<any>(`/api/v1/change-requests/${id}`),
  createChangeRequest: (data: any) =>
    request<any>("/api/v1/change-requests", { method: "POST", body: JSON.stringify(data) }),
  approveChangeRequest: (id: number, notes?: string) =>
    request<any>(`/api/v1/change-requests/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),
  rejectChangeRequest: (id: number, reason: string) =>
    request<any>(`/api/v1/change-requests/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  cancelChangeRequest: (id: number, reason: string) =>
    request<any>(`/api/v1/change-requests/${id}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  executeChangeRequest: (id: number) =>
    request<any>(`/api/v1/change-requests/${id}/execute`, { method: "POST" }),
  rollbackChangeRequest: (id: number) =>
    request<any>(`/api/v1/change-requests/${id}/rollback`, { method: "POST" }),

  // Alerts & Incidents
  getAlerts: () => request<any[]>("/api/v1/alerts"),
  acknowledgeAlert: (id: number, notes?: string) =>
    request<any>(`/api/v1/alerts/${id}/ack`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),

  // Audit
  getAuditEvents: (limit = 100) => request<any[]>(`/api/v1/audit?limit=${limit}`),

  // Policies
  getPrefixAllowlists: () => request<any[]>("/api/v1/admin/policies/prefixes"),
  addPrefixAllowlist: (data: { prefix: string; description?: string }) =>
    request<any>("/api/v1/admin/policies/prefixes", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  getPeerAllowlists: () => request<any[]>("/api/v1/admin/policies/peers"),
  getUsers: () => request<any[]>("/api/v1/admin/users"),

  // Isolated BGP Lab (Phase 6)
  getLabStatus: () => request<any>("/api/v1/bgp-lab/status"),
  getLabHistory: (prefix?: string, status?: string) => {
    let url = "/api/v1/bgp-lab/history";
    const params = new URLSearchParams();
    if (prefix) params.append("prefix", prefix);
    if (status) params.append("status", status);
    if (params.toString()) url += `?${params.toString()}`;
    return request<any[]>(url);
  },
  getLabTestDetail: (testId: number) => request<any>(`/api/v1/bgp-lab/history/${testId}`),
  triggerAnnounceTest: (data: { prefix: string; target_speaker?: string; change_request_id?: number }) =>
    request<any>("/api/v1/bgp-lab/test/announce", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  triggerWithdrawTest: (data: { prefix: string; target_speaker?: string; change_request_id?: number }) =>
    request<any>("/api/v1/bgp-lab/test/withdraw", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  triggerRoundtripTest: (data: { prefix: string; target_speaker?: string; change_request_id?: number }) =>
    request<any>("/api/v1/bgp-lab/test/roundtrip", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  submitManualReview: (testId: number, notes: string) =>
    request<any>(`/api/v1/bgp-lab/history/${testId}/manual-review`, {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),

  // Production-Gated Optimization & Mitigation (Phase 7)
  getThreatCandidates: (status?: string) => {
    let url = "/api/v1/mitigation/threats";
    if (status) url += `?status=${encodeURIComponent(status)}`;
    return request<any[]>(url);
  },
  triggerThreatDetection: () =>
    request<any[]>("/api/v1/mitigation/threats/detect", { method: "POST" }),
  previewFlowSpecRule: (data: any) =>
    request<any>("/api/v1/mitigation/flowspec/preview", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  createFlowSpecRule: (data: any) =>
    request<any>("/api/v1/mitigation/flowspec/rules", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  previewRTBHRule: (data: any) =>
    request<any>("/api/v1/mitigation/rtbh/preview", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  createRTBHRule: (data: any) =>
    request<any>("/api/v1/mitigation/rtbh/rules", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  getMitigationRules: (ruleType?: string, status?: string) => {
    let url = "/api/v1/mitigation/rules";
    const params = new URLSearchParams();
    if (ruleType) params.append("rule_type", ruleType);
    if (status) params.append("status", status);
    if (params.toString()) url += `?${params.toString()}`;
    return request<any[]>(url);
  },
  approveMitigationRule: (ruleId: number) =>
    request<any>(`/api/v1/mitigation/rules/${ruleId}/approve`, { method: "POST" }),
  withdrawMitigationRule: (ruleId: number) =>
    request<any>(`/api/v1/mitigation/rules/${ruleId}/withdraw`, { method: "POST" }),
  evaluateExecutionGate: (changeId: number, opType: string = "UNICAST") =>
    request<any>(`/api/v1/mitigation/execution-gate/evaluate/${changeId}?operation_type=${encodeURIComponent(opType)}`),
  getProductionAdapterStatus: () =>
    request<any>("/api/v1/mitigation/production-adapter/status"),
  getCircuitBreakerStatus: () =>
    request<any>("/api/v1/mitigation/circuit-breaker/status"),
  triggerCircuitBreaker: (data: { reason: string; scope?: string; scope_target?: string }) =>
    request<any>("/api/v1/mitigation/circuit-breaker/trigger", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  resetCircuitBreaker: (notes: string) =>
    request<any>("/api/v1/mitigation/circuit-breaker/reset", {
      method: "POST",
      body: JSON.stringify({ notes }),
    }),
  triggerEmergencyStop: (reason: string) =>
    request<any>("/api/v1/mitigation/emergency-stop", {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  createRolloutPlan: (data: any) =>
    request<any>("/api/v1/mitigation/rollout/plans", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  getRolloutPlans: () =>
    request<any[]>("/api/v1/mitigation/rollout/plans"),
  advanceRolloutStage: (rolloutId: number, targetStatus: string, notes?: string) => {
    let url = `/api/v1/mitigation/rollout/plans/${rolloutId}/advance?target_status=${encodeURIComponent(targetStatus)}`;
    if (notes) url += `&notes=${encodeURIComponent(notes)}`;
    return request<any>(url, { method: "POST" });
  },
};
