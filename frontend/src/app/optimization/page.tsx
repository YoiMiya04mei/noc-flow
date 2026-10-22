"use client";

import React, { useEffect, useState } from "react";
import {
  Zap,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldAlert,
  ArrowRight,
  ShieldCheck,
  RefreshCw,
  Sliders,
  FileText,
  UserCheck,
  Layers,
  Activity,
  Lock,
  Clock,
  Info,
  Shield,
  ShieldX,
  Radio,
  Terminal,
  AlertOctagon,
  StopCircle,
} from "lucide-react";
import { api } from "@/lib/api";

export default function RouteOptimizationPage() {
  const [activeTab, setActiveTab] = useState<"recommendations" | "simulator" | "changes" | "mitigation" | "rollout">("recommendations");
  const [recommendations, setRecommendations] = useState<any[]>([]);
  const [changeRequests, setChangeRequests] = useState<any[]>([]);
  const [selectedRec, setSelectedRec] = useState<any | null>(null);
  const [inspectingRec, setInspectingRec] = useState<any | null>(null);

  // Phase 7 Mitigation & Defense State
  const [threats, setThreats] = useState<any[]>([]);
  const [mitigationRules, setMitigationRules] = useState<any[]>([]);
  const [rolloutPlans, setRolloutPlans] = useState<any[]>([]);
  const [circuitBreaker, setCircuitBreaker] = useState<any | null>(null);
  const [gateReport, setGateReport] = useState<any | null>(null);
  const [evaluatingGateId, setEvaluatingGateId] = useState<number | null>(null);
  const [showResetModal, setShowResetModal] = useState(false);
  const [resetNotes, setResetNotes] = useState("");

  // FlowSpec Form & Preview
  const [showFlowSpecModal, setShowFlowSpecModal] = useState(false);
  const [fsTargetPrefix, setFsTargetPrefix] = useState("10.100.1.0/24");
  const [fsProtocol, setFsProtocol] = useState<number>(6);
  const [fsDstPort, setFsDstPort] = useState("80");
  const [fsActionType, setFsActionType] = useState("RATE_LIMIT");
  const [fsActionValue, setFsActionValue] = useState("500000");
  const [fsTtl, setFsTtl] = useState(60);
  const [fsPreview, setFsPreview] = useState<any | null>(null);

  // RTBH Form & Preview
  const [showRTBHModal, setShowRTBHModal] = useState(false);
  const [rtbhPrefix, setRtbhPrefix] = useState("10.100.1.50/32");
  const [rtbhCommunity, setRtbhCommunity] = useState("65535:666");
  const [rtbhTtl, setRtbhTtl] = useState(60);
  const [rtbhJustification, setRtbhJustification] = useState("Critical volumetric DDoS attack mitigation on customer host");
  const [rtbhPreview, setRtbhPreview] = useState<any | null>(null);

  // Simulator State
  const [simPrefix, setSimPrefix] = useState("103.145.2.0/24");
  const [simTargetPeer, setSimTargetPeer] = useState("198.51.100.5 (Indosat Ooredoo)");
  const [simCurrentPath, setSimCurrentPath] = useState("AS7713 (Telkom DWS)");
  const [simPrepend, setSimPrepend] = useState(0);
  const [simCommunity, setSimCommunity] = useState("");
  const [simResult, setSimResult] = useState<any | null>(null);
  const [simulating, setSimulating] = useState(false);

  // Status & Filters
  const [loading, setLoading] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Change Request Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [crPrefix, setCrPrefix] = useState("");
  const [crTargetPeer, setCrTargetPeer] = useState("");
  const [crDiffPayload, setCrDiffPayload] = useState("");
  const [crJustification, setCrJustification] = useState("");
  const [crRollback, setCrRollback] = useState("");
  const [crRecId, setCrRecId] = useState<number | null>(null);

  async function loadData() {
    setLoading(true);
    try {
      const [recs, crs, thrs, rules, rollouts, cb] = await Promise.all([
        api.getRecommendations().catch(() => []),
        api.getChangeRequests().catch(() => []),
        api.getThreatCandidates().catch(() => []),
        api.getMitigationRules().catch(() => []),
        api.getRolloutPlans().catch(() => []),
        api.getCircuitBreakerStatus().catch(() => null),
      ]);
      setRecommendations(recs);
      setChangeRequests(crs);
      setThreats(thrs);
      setMitigationRules(rules);
      setRolloutPlans(rollouts);
      setCircuitBreaker(cb);
    } catch (err: any) {
      console.error("Failed to load optimization & mitigation data:", err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  async function handleEvaluateAll() {
    setEvaluating(true);
    setStatusMessage(null);
    try {
      const res = await api.evaluateRecommendations({ force_refresh: true });
      setStatusMessage(
        `Evaluation complete: ${res.recommendations_generated_count} recommendations generated (${res.suppressed_anti_oscillation_count} suppressed by anti-oscillation).`
      );
      await loadData();
    } catch (err: any) {
      alert(`Evaluation failed: ${err.message}`);
    } finally {
      setEvaluating(false);
    }
  }

  async function handleSimulate(id: number) {
    setSimulating(true);
    try {
      const res = await api.simulateRecommendation(id);
      setSimResult(res);
      setActiveTab("simulator");
    } catch (err: any) {
      alert(`Simulation failed: ${err.message}`);
    } finally {
      setSimulating(false);
    }
  }

  async function handleCustomSimulate(e: React.FormEvent) {
    e.preventDefault();
    setSimulating(true);
    try {
      const res = await api.simulateCustomRoute({
        prefix: simPrefix,
        target_peer: simTargetPeer,
        current_path: simCurrentPath,
        as_path_prepend: Number(simPrepend),
        community: simCommunity || undefined,
      });
      setSimResult(res);
    } catch (err: any) {
      alert(`Custom simulation failed: ${err.message}`);
    } finally {
      setSimulating(false);
    }
  }

  async function handleInspect(id: number) {
    try {
      const res = await api.getRecommendationDetail(id);
      setInspectingRec(res);
    } catch (err: any) {
      alert(`Failed to load details: ${err.message}`);
    }
  }

  function openCreateChangeRequestModal(rec: any) {
    setCrRecId(rec.id);
    setCrPrefix(rec.prefix);
    setCrTargetPeer(rec.candidate_path);
    setCrDiffPayload(
      `router bgp 136052\n neighbor ${rec.candidate_path.split(" ")[0]} route-map RM-OPTIMIZE-IN permit 10\n set local-preference 200`
    );
    setCrJustification(rec.reason);
    setCrRollback(
      `router bgp 136052\n no neighbor ${rec.candidate_path.split(" ")[0]} route-map RM-OPTIMIZE-IN permit 10\n set local-preference 100`
    );
    setShowCreateModal(true);
  }

  async function submitCreateChangeRequest(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.createChangeRequest({
        recommendation_id: crRecId,
        prefix: crPrefix,
        target_peer: crTargetPeer,
        diff_payload: crDiffPayload,
        justification: crJustification,
        rollback_instructions: crRollback,
        requires_dual_approval: true,
      });
      setShowCreateModal(false);
      setStatusMessage(`Change request created for ${crPrefix} with dual-approval requirement.`);
      await loadData();
      setActiveTab("changes");
    } catch (err: any) {
      alert(`Failed to create change request: ${err.message}`);
    }
  }

  async function handleApprove(id: number) {
    try {
      await api.approveChangeRequest(id);
      await loadData();
    } catch (err: any) {
      alert(`Approval error: ${err.message}`);
    }
  }

  async function handleReject(id: number) {
    const reason = prompt("Enter justification for rejecting this change request:");
    if (!reason) return;
    try {
      await api.rejectChangeRequest(id, reason);
      await loadData();
    } catch (err: any) {
      alert(`Rejection error: ${err.message}`);
    }
  }

  async function handleCancel(id: number) {
    const reason = prompt("Enter cancellation reason:");
    if (!reason) return;
    try {
      await api.cancelChangeRequest(id, reason);
      await loadData();
    } catch (err: any) {
      alert(`Cancellation error: ${err.message}`);
    }
  }

  // Phase 7 Handlers
  async function handleDetectThreats() {
    try {
      const res = await api.triggerThreatDetection();
      setStatusMessage(`Traffic anomaly scan completed: ${res.length} threat candidates evaluated.`);
      await loadData();
    } catch (err: any) {
      alert(`Threat detection error: ${err.message}`);
    }
  }

  async function handlePreviewFlowSpec() {
    try {
      const prev = await api.previewFlowSpecRule({
        target_prefix: fsTargetPrefix,
        protocol: Number(fsProtocol),
        dst_port_range: fsDstPort || undefined,
        action_type: fsActionType,
        action_value: fsActionValue,
        ttl_minutes: Number(fsTtl),
      });
      setFsPreview(prev);
    } catch (err: any) {
      alert(`FlowSpec preview error: ${err.message}`);
    }
  }

  async function handleCreateFlowSpec(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.createFlowSpecRule({
        target_prefix: fsTargetPrefix,
        protocol: Number(fsProtocol),
        dst_port_range: fsDstPort || undefined,
        action_type: fsActionType,
        action_value: fsActionValue,
        ttl_minutes: Number(fsTtl),
      });
      setShowFlowSpecModal(false);
      setStatusMessage(`FlowSpec mitigation rule created in DRAFT for ${fsTargetPrefix}.`);
      await loadData();
    } catch (err: any) {
      alert(`Failed to create FlowSpec rule: ${err.message}`);
    }
  }

  async function handlePreviewRTBH() {
    try {
      const prev = await api.previewRTBHRule({
        target_prefix: rtbhPrefix,
        blackhole_community: rtbhCommunity,
        ttl_minutes: Number(rtbhTtl),
        justification: rtbhJustification,
      });
      setRtbhPreview(prev);
    } catch (err: any) {
      alert(`RTBH preview error: ${err.message}`);
    }
  }

  async function handleCreateRTBH(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.createRTBHRule({
        target_prefix: rtbhPrefix,
        blackhole_community: rtbhCommunity,
        ttl_minutes: Number(rtbhTtl),
        justification: rtbhJustification,
      });
      setShowRTBHModal(false);
      setStatusMessage(`RTBH blackhole rule created in DRAFT for ${rtbhPrefix}. Dual approval required.`);
      await loadData();
    } catch (err: any) {
      alert(`Failed to create RTBH rule: ${err.message}`);
    }
  }

  async function handleApproveRule(id: number) {
    try {
      await api.approveMitigationRule(id);
      setStatusMessage(`Mitigation rule #${id} approval updated.`);
      await loadData();
    } catch (err: any) {
      alert(`Approval error: ${err.message}`);
    }
  }

  async function handleWithdrawRule(id: number) {
    try {
      await api.withdrawMitigationRule(id);
      setStatusMessage(`Mitigation rule #${id} marked as WITHDRAWN.`);
      await loadData();
    } catch (err: any) {
      alert(`Withdrawal error: ${err.message}`);
    }
  }

  async function handleEvaluateGate(changeId: number) {
    setEvaluatingGateId(changeId);
    try {
      const report = await api.evaluateExecutionGate(changeId);
      setGateReport(report);
    } catch (err: any) {
      alert(`Gate evaluation error: ${err.message}`);
    } finally {
      setEvaluatingGateId(null);
    }
  }

  async function handleEmergencyStop() {
    const reason = prompt("EMERGENCY STOP TRIGGER: Enter explicit operational reason for halting ALL routing executions:");
    if (!reason) return;
    try {
      await api.triggerEmergencyStop(reason);
      alert("EMERGENCY STOP ACTIVATED: All router executions halted immediately.");
      await loadData();
    } catch (err: any) {
      alert(`Emergency stop error: ${err.message}`);
    }
  }

  async function handleResetCircuitBreaker(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api.resetCircuitBreaker(resetNotes);
      setShowResetModal(false);
      setResetNotes("");
      setStatusMessage("Circuit breaker successfully reset to CLOSED.");
      await loadData();
    } catch (err: any) {
      alert(`Reset error: ${err.message}`);
    }
  }

  async function handleAdvanceRollout(rolloutId: number, targetStatus: string) {
    try {
      await api.advanceRolloutStage(rolloutId, targetStatus);
      await loadData();
    } catch (err: any) {
      alert(`Rollout stage error: ${err.message}`);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            Route Recommendation Engine & Policy Simulator
            <span className="noc-badge-guardrail text-[10px] px-2 py-0.5 rounded font-mono font-semibold">
              EXECUTION LOCKED (OBSERVE-ONLY)
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Phase 5: Multivariate route scoring (0.0 to 100.0), anti-oscillation, what-if dry-run simulation, and dual-approval workflow.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1F2937] hover:bg-[#374151] text-gray-300 rounded-lg text-xs font-mono transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={handleEvaluateAll}
            disabled={evaluating}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-mono font-medium transition-colors"
          >
            <Zap className={`w-3.5 h-3.5 ${evaluating ? "animate-pulse" : ""}`} />
            <span>{evaluating ? "Evaluating..." : "Run Engine Evaluation"}</span>
          </button>
        </div>
      </div>

      {/* Safety Notice Banner */}
      <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-start gap-3">
        <ShieldAlert className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-gray-300 leading-relaxed font-mono">
          <span className="font-bold text-amber-400">CRITICAL SAFETY GUARDRAILS ACTIVE:</span> ROUTING_EXECUTION_ENABLED is
          permanently FALSE in Phase 5. The recommendation engine and dry-run simulator evaluate path candidates, anti-oscillation
          thresholds, and prefix allowlists without modifying router forwarding planes or sending live BGP announcements.
        </div>
      </div>

      {statusMessage && (
        <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-3 text-xs font-mono text-blue-300 flex items-center justify-between">
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage(null)} className="text-gray-400 hover:text-white">
            &times;
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex border-b border-[#1F2937] gap-6 text-xs font-mono">
        <button
          onClick={() => setActiveTab("recommendations")}
          className={`pb-3 flex items-center gap-2 font-medium border-b-2 transition-colors ${
            activeTab === "recommendations"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Recommendations ({recommendations.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("simulator")}
          className={`pb-3 flex items-center gap-2 font-medium border-b-2 transition-colors ${
            activeTab === "simulator"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <Sliders className="w-4 h-4" />
          <span>Route Simulator (Dry-Run)</span>
        </button>

        <button
          onClick={() => setActiveTab("changes")}
          className={`pb-3 flex items-center gap-2 font-medium border-b-2 transition-colors ${
            activeTab === "changes"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>Change Requests & Dual Approval ({changeRequests.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("mitigation")}
          className={`pb-3 flex items-center gap-2 font-medium border-b-2 transition-colors ${
            activeTab === "mitigation"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <span>Mitigation & Defense ({threats.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("rollout")}
          className={`pb-3 flex items-center gap-2 font-medium border-b-2 transition-colors ${
            activeTab === "rollout"
              ? "border-blue-500 text-blue-400"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <Radio className="w-4 h-4 text-emerald-400" />
          <span>Controlled Rollout & Circuit Breaker ({rolloutPlans.length})</span>
        </button>
      </div>

      {/* TAB 1: RECOMMENDATIONS */}
      {activeTab === "recommendations" && (
        <div className="space-y-4">
          {recommendations.length === 0 ? (
            <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-8 text-center text-xs font-mono text-gray-400">
              No recommendations generated yet. Click &quot;Run Engine Evaluation&quot; to correlate active BGP routes, path probes, and SNMP interface health.
            </div>
          ) : (
            recommendations.map((rec) => (
              <div key={rec.id} className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 hover:border-gray-700 transition-all">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1F2937] pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-white font-mono">{rec.prefix}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                        rec.risk_level === "low" ? "bg-emerald-500/10 text-emerald-400" :
                        rec.risk_level === "medium" ? "bg-amber-500/10 text-amber-400" : "bg-red-500/10 text-red-400"
                      }`}>
                        Risk: {rec.risk_level}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-400 font-semibold">
                        Confidence: {rec.confidence_pct}%
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-400 font-semibold uppercase">
                        {rec.status}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 mt-2 text-xs font-mono">
                      <span className="text-gray-400">Current: {rec.current_path}</span>
                      <ArrowRight className="w-3.5 h-3.5 text-gray-500" />
                      <span className="text-emerald-400 font-semibold">Candidate: {rec.candidate_path}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleInspect(rec.id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1F2937] hover:bg-[#374151] text-gray-300 rounded-lg text-xs font-mono font-medium transition-colors"
                    >
                      <Info className="w-3.5 h-3.5 text-blue-400" />
                      <span>Inspect Breakdown</span>
                    </button>
                    <button
                      onClick={() => handleSimulate(rec.id)}
                      disabled={simulating}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-mono font-medium transition-colors"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Simulate</span>
                    </button>
                    <button
                      onClick={() => openCreateChangeRequestModal(rec)}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-white rounded-lg text-xs font-mono font-medium transition-colors"
                    >
                      <UserCheck className="w-3.5 h-3.5" />
                      <span>Create CR</span>
                    </button>
                  </div>
                </div>

                <div className="mt-4 flex flex-col md:flex-row md:items-center justify-between gap-4 text-xs font-mono">
                  <div className="text-gray-300 leading-relaxed flex-1">
                    <span className="text-gray-500">Reasoning: </span>
                    {rec.reason}
                  </div>

                  <div className="flex items-center gap-4 bg-[#0D1322] px-4 py-2.5 rounded-lg border border-[#1F2937]">
                    <div>
                      <span className="text-[10px] text-gray-500 block">CURRENT SCORE</span>
                      <span className="text-sm font-bold text-gray-300">{rec.score_current}</span>
                    </div>
                    <div className="text-gray-600 font-bold">&rarr;</div>
                    <div>
                      <span className="text-[10px] text-gray-500 block">CANDIDATE SCORE</span>
                      <span className="text-sm font-bold text-emerald-400">+{rec.score_candidate}</span>
                    </div>
                    <div className="text-[10px] text-emerald-500 font-bold pl-2 border-l border-gray-800">
                      &Delta; +{(rec.score_candidate - rec.score_current).toFixed(1)} pts
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* SCORE BREAKDOWN INSPECTOR MODAL */}
      {inspectingRec && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-2xl w-full p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
              <div>
                <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-blue-400" />
                  Score Breakdown: {inspectingRec.prefix}
                </h3>
                <p className="text-xs text-gray-400 font-mono mt-0.5">
                  Convention: HIGHER IS BETTER (0.0 to 100.0) | Deterministic multivariate model
                </p>
              </div>
              <button
                onClick={() => setInspectingRec(null)}
                className="text-gray-400 hover:text-white font-mono text-sm"
              >
                &times;
              </button>
            </div>

            {inspectingRec.parsed_breakdown ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="bg-[#0D1322] p-3 rounded-lg border border-[#1F2937]">
                    <span className="text-[10px] text-gray-500 block">COMPOSITE SCORE</span>
                    <span className="text-xl font-bold text-emerald-400">
                      {inspectingRec.parsed_breakdown.composite_score} / 100.0
                    </span>
                  </div>
                  <div className="bg-[#0D1322] p-3 rounded-lg border border-[#1F2937]">
                    <span className="text-[10px] text-gray-500 block">HARD CONSTRAINTS</span>
                    <span className={`text-sm font-bold ${
                      inspectingRec.parsed_breakdown.hard_constraints_passed ? "text-emerald-400" : "text-red-400"
                    }`}>
                      {inspectingRec.parsed_breakdown.hard_constraints_passed ? "PASSED (ALLOWLIST OK)" : "FAILED"}
                    </span>
                  </div>
                </div>

                <div className="space-y-3">
                  <h4 className="text-xs font-bold text-gray-300 font-mono">Metric Weight Contributions:</h4>
                  {inspectingRec.parsed_breakdown.metrics.map((m: any, idx: number) => (
                    <div key={idx} className="bg-[#0D1322] p-3 rounded-lg border border-[#1F2937] text-xs font-mono space-y-1.5">
                      <div className="flex justify-between items-center">
                        <span className="font-semibold text-white uppercase">{m.metric_name}</span>
                        <span className="text-gray-400">
                          Raw: {m.raw_value !== null ? `${m.raw_value} ${m.unit}` : "N/A (Missing)"}
                        </span>
                      </div>
                      <div className="w-full bg-gray-800 rounded-full h-2">
                        <div
                          className="bg-blue-500 h-2 rounded-full"
                          style={{ width: `${m.normalized_score}%` }}
                        />
                      </div>
                      <div className="flex justify-between text-[11px] text-gray-400">
                        <span>Score: {m.normalized_score} / 100</span>
                        <span>Weight: {(m.weight * 100).toFixed(0)}%</span>
                        <span className="text-emerald-400 font-bold">Contribution: +{m.weighted_contribution}</span>
                      </div>
                    </div>
                  ))}
                </div>

                {inspectingRec.parsed_data_quality && (
                  <div className="bg-[#0D1322] p-3 rounded-lg border border-[#1F2937] text-xs font-mono space-y-1">
                    <span className="text-[10px] text-gray-500 block">TELEMETRY FRESHNESS & QUALITY</span>
                    <p className="text-gray-300">{inspectingRec.parsed_data_quality.explanation}</p>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs font-mono text-gray-400">Raw breakdown: {inspectingRec.score_breakdown || "N/A"}</p>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setInspectingRec(null)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg text-xs font-mono font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: ROUTE SIMULATOR (WHAT-IF DRY-RUN) */}
      {activeTab === "simulator" && (
        <div className="space-y-6">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-6">
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2 mb-4">
              <Sliders className="w-4 h-4 text-blue-400" />
              Configure What-If Route Simulation
            </h3>

            <form onSubmit={handleCustomSimulate} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
              <div>
                <label className="text-gray-400 block mb-1">Target Prefix *</label>
                <input
                  type="text"
                  value={simPrefix}
                  onChange={(e) => setSimPrefix(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2.5 text-white font-mono focus:border-blue-500 focus:outline-none"
                  placeholder="e.g. 103.145.2.0/24"
                  required
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Proposed Next-Hop / Peer *</label>
                <input
                  type="text"
                  value={simTargetPeer}
                  onChange={(e) => setSimTargetPeer(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2.5 text-white font-mono focus:border-blue-500 focus:outline-none"
                  placeholder="e.g. 198.51.100.5 (Indosat Ooredoo)"
                  required
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Current Active Path (Optional)</label>
                <input
                  type="text"
                  value={simCurrentPath}
                  onChange={(e) => setSimCurrentPath(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2.5 text-white font-mono focus:border-blue-500 focus:outline-none"
                  placeholder="e.g. AS7713 (Telkom DWS)"
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">AS-PATH Prepend Count</label>
                <input
                  type="number"
                  min="0"
                  max="5"
                  value={simPrepend}
                  onChange={(e) => setSimPrepend(Number(e.target.value))}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2.5 text-white font-mono focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">BGP Community Tag</label>
                <input
                  type="text"
                  value={simCommunity}
                  onChange={(e) => setSimCommunity(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2.5 text-white font-mono focus:border-blue-500 focus:outline-none"
                  placeholder="e.g. 136052:100"
                />
              </div>

              <div className="flex items-end">
                <button
                  type="submit"
                  disabled={simulating}
                  className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-mono font-medium transition-colors flex items-center justify-center gap-2"
                >
                  <Play className={`w-3.5 h-3.5 ${simulating ? "animate-spin" : ""}`} />
                  <span>{simulating ? "Simulating..." : "Run Policy Dry-Run"}</span>
                </button>
              </div>
            </form>
          </div>

          {/* SIMULATION OUTCOME PANEL */}
          {simResult && (
            <div className="bg-[#0D1322] border border-blue-500/40 rounded-xl p-6 shadow-2xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-sm font-bold text-white font-mono">
                    Dry-Run Simulation Impact Analysis: {simResult.prefix}
                  </h3>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                    simResult.allowed ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"
                  }`}>
                    {simResult.allowed ? "VALIDATED (ALLOWLIST PASS)" : "POLICY REJECTED"}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-400 font-semibold uppercase">
                    Risk: {simResult.risk_assessment}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-mono text-xs">
                <div className="bg-[#111827] p-3 rounded border border-[#1F2937]">
                  <span className="text-gray-500 text-[10px] block">PREDICTED LATENCY DELTA</span>
                  <div className={`text-base font-bold mt-1 ${
                    simResult.predicted_latency_change_ms <= 0 ? "text-emerald-400" : "text-amber-400"
                  }`}>
                    {simResult.predicted_latency_change_ms} ms
                  </div>
                </div>

                <div className="bg-[#111827] p-3 rounded border border-[#1F2937]">
                  <span className="text-gray-500 text-[10px] block">PREDICTED LOSS DELTA</span>
                  <div className={`text-base font-bold mt-1 ${
                    simResult.predicted_loss_change_pct <= 0 ? "text-emerald-400" : "text-red-400"
                  }`}>
                    {simResult.predicted_loss_change_pct}%
                  </div>
                </div>

                <div className="bg-[#111827] p-3 rounded border border-[#1F2937]">
                  <span className="text-gray-500 text-[10px] block">ESTIMATED FLOW SHIFT</span>
                  <div className="text-base font-bold text-blue-400 mt-1">
                    {simResult.estimated_bandwidth_shift_mbps} Mbps
                  </div>
                </div>

                <div className="bg-[#111827] p-3 rounded border border-[#1F2937]">
                  <span className="text-gray-500 text-[10px] block">POST-SHIFT LINK UTIL</span>
                  <div className="text-base font-bold text-gray-200 mt-1">
                    {simResult.post_shift_utilization_pct}%
                  </div>
                </div>
              </div>

              <div className="bg-[#111827] p-3 rounded border border-[#1F2937] text-xs font-mono space-y-2">
                <span className="text-[10px] text-gray-500 block uppercase font-bold">Simulator Assumptions & Limitations</span>
                <ul className="list-disc pl-4 text-gray-300 space-y-1">
                  {simResult.assumptions?.map((a: string, i: number) => (
                    <li key={i}>{a}</li>
                  ))}
                  {simResult.limitations?.map((l: string, i: number) => (
                    <li key={i} className="text-amber-300/80">{l}</li>
                  ))}
                </ul>
              </div>

              <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded font-mono text-xs text-amber-300">
                {simResult.guardrail_notice}
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => openCreateChangeRequestModal({
                    id: null,
                    prefix: simResult.prefix,
                    candidate_path: simResult.target_peer,
                    reason: `Simulated: ${simResult.predicted_latency_change_ms}ms latency delta and ${simResult.predicted_loss_change_pct}% loss delta.`,
                  })}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-mono font-medium flex items-center gap-2"
                >
                  <UserCheck className="w-4 h-4" />
                  <span>Promote Simulation to Change Request</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: CHANGE REQUESTS & DUAL APPROVAL */}
      {activeTab === "changes" && (
        <div className="space-y-4">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[#1F2937] flex justify-between items-center">
              <div>
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <FileText className="w-4 h-4 text-blue-400" />
                  Routing Change Requests & Approval Pipeline
                </h3>
                <p className="text-xs text-gray-400 font-mono mt-0.5">
                  Dual-approval required for routing changes. Self-approval strictly rejected by backend policy.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-[#0D1322] text-gray-400 border-b border-[#1F2937]">
                  <tr>
                    <th className="p-3">ID</th>
                    <th className="p-3">Prefix</th>
                    <th className="p-3">Target Peer</th>
                    <th className="p-3">Requester</th>
                    <th className="p-3">Approver 1</th>
                    <th className="p-3">Approver 2</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Lab Verification</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2937]">
                  {changeRequests.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="p-6 text-center text-gray-500">
                        No change requests submitted yet.
                      </td>
                    </tr>
                  ) : (
                    changeRequests.map((cr) => (
                      <tr key={cr.id} className="hover:bg-[#1A2234]">
                        <td className="p-3 text-gray-400">#{cr.id}</td>
                        <td className="p-3 font-bold text-white">{cr.prefix}</td>
                        <td className="p-3 text-gray-300">{cr.target_peer}</td>
                        <td className="p-3 text-gray-400">User #{cr.requester_id}</td>
                        <td className="p-3 text-gray-400">
                          {cr.approver_id ? `User #${cr.approver_id}` : "-"}
                        </td>
                        <td className="p-3 text-gray-400">
                          {cr.second_approver_id ? `User #${cr.second_approver_id}` : (cr.requires_dual_approval ? "Required" : "N/A")}
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            cr.execution_status === "approved" ? "bg-emerald-500/10 text-emerald-400" :
                            cr.execution_status === "partially_approved" ? "bg-blue-500/10 text-blue-400" :
                            cr.execution_status === "rejected" ? "bg-red-500/10 text-red-400" :
                            cr.execution_status === "cancelled" ? "bg-gray-500/10 text-gray-400" :
                            "bg-amber-500/10 text-amber-400"
                          }`}>
                            {cr.execution_status}
                          </span>
                        </td>
                        <td className="p-3">
                          {cr.lab_tested ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-300 border border-purple-500/30 flex items-center gap-1 w-fit">
                              <span>LAB TESTED ✓</span>
                              {cr.lab_test_run_id && <span className="text-[9px] text-gray-400">#{cr.lab_test_run_id}</span>}
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-gray-500/10 text-gray-400 border border-gray-700">
                              UNTESTED IN LAB
                            </span>
                          )}
                        </td>
                        <td className="p-3 text-right space-x-1.5 whitespace-nowrap">
                          {!cr.lab_tested && (
                            <a
                              href={`/bgp?tab=lab&prefix=${encodeURIComponent(cr.prefix)}&cr=${cr.id}`}
                              className="px-2.5 py-1 bg-purple-600/20 hover:bg-purple-600 text-purple-300 hover:text-white rounded text-[10px] font-medium inline-block border border-purple-500/30"
                            >
                              Test in Lab
                            </a>
                          )}
                          {cr.execution_status === "pending_approval" && (
                            <>
                              <button
                                onClick={() => handleApprove(cr.id)}
                                className="px-2.5 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-[10px] font-medium"
                              >
                                Approve (Step 1/2)
                              </button>
                              <button
                                onClick={() => handleReject(cr.id)}
                                className="px-2.5 py-1 bg-red-600/20 hover:bg-red-600 text-red-300 hover:text-white rounded text-[10px] font-medium"
                              >
                                Reject
                              </button>
                            </>
                          )}
                          {cr.execution_status === "partially_approved" && (
                            <>
                              <button
                                onClick={() => handleApprove(cr.id)}
                                className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[10px] font-medium"
                              >
                                Approve (Step 2/2)
                              </button>
                              <button
                                onClick={() => handleReject(cr.id)}
                                className="px-2.5 py-1 bg-red-600/20 hover:bg-red-600 text-red-300 hover:text-white rounded text-[10px] font-medium"
                              >
                                Reject
                              </button>
                            </>
                          )}
                          {["pending_approval", "partially_approved"].includes(cr.execution_status) && (
                            <button
                              onClick={() => handleCancel(cr.id)}
                              className="px-2.5 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-[10px] font-medium"
                            >
                              Cancel
                            </button>
                          )}
                          <button
                            onClick={() => handleEvaluateGate(cr.id)}
                            disabled={evaluatingGateId === cr.id}
                            className="px-2.5 py-1 bg-purple-600/20 hover:bg-purple-600 text-purple-300 hover:text-white rounded text-[10px] font-medium"
                          >
                            {evaluatingGateId === cr.id ? "Checking..." : "Gate 12-Pt"}
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: MITIGATION & DEFENSE (FLOWSPEC & RTBH) */}
      {activeTab === "mitigation" && (
        <div className="space-y-6 font-mono text-xs">
          {/* Phase 7 Guardrail Banner */}
          <div className="bg-rose-500/10 border border-rose-500/30 rounded-xl p-4 flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-rose-400">
                PHASE 7 PRODUCTION MITIGATION GATES ACTIVE (LOCKED BY DEFAULT)
              </div>
              <div className="text-gray-300 leading-relaxed text-[11px]">
                FLOWSPEC_EXECUTION_ENABLED is <span className="text-rose-400 font-bold">FALSE</span> & RTBH_EXECUTION_ENABLED is <span className="text-rose-400 font-bold">FALSE</span>.
                Threat candidates, FlowSpec rule compilation, and RTBH blackhole previews execute safely in dry-run/preview mode without transmitting live filtering updates to edge transit peers.
              </div>
            </div>
          </div>

          {/* Threat Candidates Section */}
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[#1F2937] flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  Traffic Anomaly & Threat Candidates ({threats.length})
                </h3>
                <p className="text-[11px] text-gray-400 mt-0.5">
                  Automated threat detection based on telemetry spikes (pps/bps, protocol, port).
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleDetectThreats}
                  className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-[11px] font-medium flex items-center gap-1.5"
                >
                  <Activity className="w-3.5 h-3.5" />
                  <span>Scan Flow Anomalies</span>
                </button>
                <button
                  onClick={() => setShowFlowSpecModal(true)}
                  className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-[11px] font-medium flex items-center gap-1.5"
                >
                  <span>+ New FlowSpec</span>
                </button>
                <button
                  onClick={() => setShowRTBHModal(true)}
                  className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded text-[11px] font-medium flex items-center gap-1.5"
                >
                  <span>+ New RTBH Blackhole</span>
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0D1322] text-gray-400 uppercase text-[10px] border-b border-[#1F2937]">
                  <tr>
                    <th className="p-3">ID / Severity</th>
                    <th className="p-3">Threat Type</th>
                    <th className="p-3">Target Prefix</th>
                    <th className="p-3">Protocol / Port</th>
                    <th className="p-3">Rate (PPS / BPS)</th>
                    <th className="p-3">Confidence</th>
                    <th className="p-3">Status</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2937]">
                  {threats.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="p-6 text-center text-gray-400">
                        No threat candidates currently detected. Click &quot;Scan Flow Anomalies&quot; to inspect traffic streams.
                      </td>
                    </tr>
                  ) : (
                    threats.map((t) => (
                      <tr key={t.id} className="hover:bg-[#1F2937]/30">
                        <td className="p-3">
                          <span className="font-bold text-white">#{t.id}</span>
                          <span className={`ml-2 px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            t.severity === "CRITICAL" ? "bg-rose-500/20 text-rose-400" :
                            t.severity === "HIGH" ? "bg-amber-500/20 text-amber-400" :
                            "bg-blue-500/20 text-blue-400"
                          }`}>
                            {t.severity}
                          </span>
                        </td>
                        <td className="p-3 font-semibold text-gray-200">{t.threat_type}</td>
                        <td className="p-3 text-emerald-400 font-mono font-bold">{t.target_prefix}</td>
                        <td className="p-3 text-gray-300">
                          {t.protocol === 6 ? "TCP" : t.protocol === 17 ? "UDP" : t.protocol === 1 ? "ICMP" : `Proto ${t.protocol || 'any'}`}
                          {t.target_port ? ` : ${t.target_port}` : ""}
                        </td>
                        <td className="p-3 text-gray-300">
                          {(t.detected_pps / 1000).toFixed(1)}k pps / {(t.detected_bps / 1000000).toFixed(1)} Mbps
                        </td>
                        <td className="p-3 font-bold text-blue-400">{t.confidence_score.toFixed(1)}%</td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-300 border border-amber-500/30">
                            {t.status}
                          </span>
                        </td>
                        <td className="p-3 text-right space-x-1">
                          <button
                            onClick={() => {
                              setFsTargetPrefix(t.target_prefix);
                              setFsProtocol(t.protocol || 6);
                              setFsDstPort(t.target_port ? String(t.target_port) : "");
                              setShowFlowSpecModal(true);
                            }}
                            className="px-2 py-1 bg-blue-600/20 hover:bg-blue-600 text-blue-300 hover:text-white rounded text-[10px]"
                          >
                            FlowSpec
                          </button>
                          <button
                            onClick={() => {
                              setRtbhPrefix(t.target_prefix.includes("/") ? t.target_prefix : `${t.target_prefix}/32`);
                              setShowRTBHModal(true);
                            }}
                            className="px-2 py-1 bg-amber-600/20 hover:bg-amber-600 text-amber-300 hover:text-white rounded text-[10px]"
                          >
                            RTBH
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Mitigation Rules Table */}
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[#1F2937]">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Active & Draft Mitigation Rules ({mitigationRules.length})
              </h3>
              <p className="text-[11px] text-gray-400 mt-0.5">
                BGP FlowSpec filtering and RTBH blackhole rules with dual-approval workflow.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0D1322] text-gray-400 uppercase text-[10px] border-b border-[#1F2937]">
                  <tr>
                    <th className="p-3">ID / Type</th>
                    <th className="p-3">Target Prefix</th>
                    <th className="p-3">Match Filters</th>
                    <th className="p-3">Action</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">TTL / Expiry</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2937]">
                  {mitigationRules.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-6 text-center text-gray-400">
                        No mitigation rules recorded yet. Create a FlowSpec or RTBH rule above.
                      </td>
                    </tr>
                  ) : (
                    mitigationRules.map((r) => (
                      <tr key={r.id} className="hover:bg-[#1F2937]/30">
                        <td className="p-3">
                          <span className="font-bold text-white">#{r.id}</span>
                          <span className={`ml-2 px-1.5 py-0.5 rounded text-[9px] font-bold ${
                            r.rule_type === "FLOWSPEC" ? "bg-blue-500/20 text-blue-300" : "bg-purple-500/20 text-purple-300"
                          }`}>
                            {r.rule_type}
                          </span>
                        </td>
                        <td className="p-3 text-emerald-400 font-mono font-bold">{r.target_prefix}</td>
                        <td className="p-3 text-gray-300">
                          {r.protocol ? `Proto ${r.protocol}` : "Any proto"}
                          {r.dst_port_range ? ` | DstPort ${r.dst_port_range}` : ""}
                          {r.tcp_flags ? ` | Flags ${r.tcp_flags}` : ""}
                        </td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                            {r.action_type} {r.action_value ? `(${r.action_value})` : ""}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                            r.status === "APPROVED" || r.status === "ACTIVE" ? "bg-emerald-500/20 text-emerald-300" :
                            r.status === "AWAITING_APPROVAL" ? "bg-purple-500/20 text-purple-300" :
                            r.status === "WITHDRAWN" ? "bg-gray-700 text-gray-300" :
                            "bg-amber-500/20 text-amber-300"
                          }`}>
                            {r.status}
                          </span>
                        </td>
                        <td className="p-3 text-gray-400 text-[11px]">
                          {r.ttl_minutes}m (Expires {new Date(r.expires_at).toLocaleTimeString()})
                        </td>
                        <td className="p-3 text-right space-x-1">
                          {["DRAFT", "AWAITING_APPROVAL"].includes(r.status) && (
                            <button
                              onClick={() => handleApproveRule(r.id)}
                              className="px-2 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[10px]"
                            >
                              Approve
                            </button>
                          )}
                          {["APPROVED", "ACTIVE"].includes(r.status) && (
                            <button
                              onClick={() => handleWithdrawRule(r.id)}
                              className="px-2 py-1 bg-rose-600/20 hover:bg-rose-600 text-rose-300 hover:text-white rounded text-[10px]"
                            >
                              Withdraw
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: CONTROLLED ROLLOUT & CIRCUIT BREAKER */}
      {activeTab === "rollout" && (
        <div className="space-y-6 font-mono text-xs">
          {/* Circuit Breaker Status Banner */}
          <div className={`border rounded-xl p-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 ${
            circuitBreaker?.is_execution_blocked
              ? "bg-rose-500/10 border-rose-500/40"
              : "bg-emerald-500/10 border-emerald-500/30"
          }`}>
            <div className="flex items-start gap-3">
              {circuitBreaker?.is_execution_blocked ? (
                <AlertOctagon className="w-6 h-6 text-rose-400 flex-shrink-0 mt-0.5" />
              ) : (
                <ShieldCheck className="w-6 h-6 text-emerald-400 flex-shrink-0 mt-0.5" />
              )}
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm text-white">CIRCUIT BREAKER:</span>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                    circuitBreaker?.is_execution_blocked
                      ? "bg-rose-600 text-white"
                      : "bg-emerald-600/30 text-emerald-300 border border-emerald-500/30"
                  }`}>
                    {circuitBreaker?.state || "CLOSED"}
                  </span>
                  {circuitBreaker?.emergency_stop_active && (
                    <span className="bg-rose-700 text-white px-2 py-0.5 rounded text-[10px] font-bold animate-pulse">
                      GLOBAL EMERGENCY STOP ACTIVE
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-gray-300 mt-1">
                  Consecutive Failures: {circuitBreaker?.consecutive_failures || 0} / {circuitBreaker?.failure_threshold || 3}.
                  {circuitBreaker?.last_trigger_reason ? ` Reason: ${circuitBreaker.last_trigger_reason}` : " All systems nominal."}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleEmergencyStop}
                className="px-3.5 py-2 bg-rose-700 hover:bg-rose-600 text-white font-bold rounded flex items-center gap-1.5 shadow-lg shadow-rose-900/40"
              >
                <StopCircle className="w-4 h-4" />
                <span>EMERGENCY STOP</span>
              </button>
              {circuitBreaker?.is_execution_blocked && (
                <button
                  onClick={() => setShowResetModal(true)}
                  className="px-3 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded font-medium flex items-center gap-1.5"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Manual Reset</span>
                </button>
              )}
            </div>
          </div>

          {/* Rollout Staged Execution Plans Table */}
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[#1F2937] flex justify-between items-center">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Radio className="w-4 h-4 text-emerald-400" />
                  Controlled Staged Rollouts ({rolloutPlans.length})
                </h3>
                <p className="text-[11px] text-gray-400 mt-0.5">
                  Canary staging (1/3 $\to$ 2/3 $\to$ 3/3), change window limits ($\le$ 5 prefixes), and correlation IDs.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0D1322] text-gray-400 uppercase text-[10px] border-b border-[#1F2937]">
                  <tr>
                    <th className="p-3">ID / Correlation</th>
                    <th className="p-3">Type</th>
                    <th className="p-3">Canary Stage</th>
                    <th className="p-3">Prefixes</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Created</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2937]">
                  {rolloutPlans.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="p-6 text-center text-gray-400">
                        No active rollout plans recorded. Promote an approved Change Request or Mitigation Rule into a rollout plan.
                      </td>
                    </tr>
                  ) : (
                    rolloutPlans.map((rp) => (
                      <tr key={rp.id} className="hover:bg-[#1F2937]/30">
                        <td className="p-3 font-mono">
                          <span className="font-bold text-white">#{rp.id}</span>
                          <div className="text-[10px] text-gray-400">{rp.correlation_id}</div>
                        </td>
                        <td className="p-3 font-semibold text-blue-400">{rp.rollout_type}</td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-300 font-bold border border-emerald-500/20">
                            Stage {rp.current_stage} / {rp.total_stages}
                          </span>
                        </td>
                        <td className="p-3 text-gray-300 font-mono text-[11px]">{rp.scope_prefixes}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            rp.status === "COMPLETED" ? "bg-emerald-500/20 text-emerald-300" :
                            rp.status === "EXECUTING" ? "bg-blue-500/20 text-blue-300 animate-pulse" :
                            rp.status === "FAILED" || rp.status === "ROLLED_BACK" ? "bg-rose-500/20 text-rose-300" :
                            "bg-amber-500/20 text-amber-300"
                          }`}>
                            {rp.status}
                          </span>
                        </td>
                        <td className="p-3 text-gray-400 text-[11px]">
                          {new Date(rp.created_at).toLocaleTimeString()}
                        </td>
                        <td className="p-3 text-right space-x-1">
                          {rp.status === "DRAFT" && (
                            <button
                              onClick={() => handleAdvanceRollout(rp.id, "POLICY_VALIDATED")}
                              className="px-2.5 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-[10px]"
                            >
                              Validate
                            </button>
                          )}
                          {rp.status === "POLICY_VALIDATED" && (
                            <button
                              onClick={() => handleAdvanceRollout(rp.id, "LAB_TESTED")}
                              className="px-2.5 py-1 bg-purple-600 hover:bg-purple-500 text-white rounded text-[10px]"
                            >
                              Mark Lab-Tested
                            </button>
                          )}
                          {rp.status === "APPROVED" && (
                            <button
                              onClick={() => handleAdvanceRollout(rp.id, "PRE_CHECK")}
                              className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[10px]"
                            >
                              Run Pre-Check
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* GATE EVALUATION REPORT MODAL (12 CRITERIA) */}
      {gateReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 font-mono">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-purple-400" />
                  12-Point Production Execution Gate Evaluation
                </h3>
                <p className="text-[11px] text-gray-400 mt-0.5">{gateReport.summary}</p>
              </div>
              <button
                onClick={() => setGateReport(null)}
                className="text-gray-400 hover:text-white text-lg"
              >
                &times;
              </button>
            </div>

            <div className="space-y-2 max-h-[60vh] overflow-y-auto text-xs">
              {gateReport.items?.map((item: any, idx: number) => (
                <div
                  key={idx}
                  className={`p-2.5 rounded border flex items-start justify-between gap-3 ${
                    item.status === "PASS"
                      ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                      : "bg-rose-500/10 border-rose-500/30 text-rose-300"
                  }`}
                >
                  <div className="space-y-0.5">
                    <div className="font-bold text-white">{item.criterion}</div>
                    <div className="text-[11px] text-gray-300">{item.details}</div>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      item.status === "PASS"
                        ? "bg-emerald-600 text-white"
                        : "bg-rose-600 text-white"
                    }`}
                  >
                    {item.status}
                  </span>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-3 border-t border-[#1F2937]">
              <button
                onClick={() => setGateReport(null)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-xs"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FLOWSPEC CREATION & PREVIEW MODAL */}
      {showFlowSpecModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 font-mono">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-blue-400" />
                Configure BGP FlowSpec (RFC 8955) Mitigation Rule
              </h3>
              <button onClick={() => setShowFlowSpecModal(false)} className="text-gray-400 hover:text-white">
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateFlowSpec} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-gray-400 block mb-1">Target Destination Prefix *</label>
                  <input
                    type="text"
                    value={fsTargetPrefix}
                    onChange={(e) => setFsTargetPrefix(e.target.value)}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-emerald-400 font-bold"
                    required
                  />
                </div>
                <div>
                  <label className="text-gray-400 block mb-1">IP Protocol</label>
                  <select
                    value={fsProtocol}
                    onChange={(e) => setFsProtocol(Number(e.target.value))}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  >
                    <option value={6}>6 (TCP)</option>
                    <option value={17}>17 (UDP)</option>
                    <option value={1}>1 (ICMP)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-gray-400 block mb-1">Destination Port / Range</label>
                  <input
                    type="text"
                    value={fsDstPort}
                    onChange={(e) => setFsDstPort(e.target.value)}
                    placeholder="e.g. 80, 443, 1024-65535"
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-gray-400 block mb-1">Action Type</label>
                  <select
                    value={fsActionType}
                    onChange={(e) => setFsActionType(e.target.value)}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  >
                    <option value="RATE_LIMIT">RATE_LIMIT (Traffic policing)</option>
                    <option value="DISCARD">DISCARD (Filter drop)</option>
                    <option value="MARK_DSCP">MARK_DSCP</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-gray-400 block mb-1">Action Rate (BPS if Rate-Limit)</label>
                  <input
                    type="text"
                    value={fsActionValue}
                    onChange={(e) => setFsActionValue(e.target.value)}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-gray-400 block mb-1">TTL / Expiry Duration (Minutes)</label>
                  <input
                    type="number"
                    value={fsTtl}
                    onChange={(e) => setFsTtl(Number(e.target.value))}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                    min={5}
                    max={1440}
                  />
                </div>
              </div>

              <div className="flex justify-between items-center pt-2">
                <button
                  type="button"
                  onClick={handlePreviewFlowSpec}
                  className="px-3 py-1.5 bg-[#1F2937] hover:bg-[#374151] text-gray-200 rounded flex items-center gap-1.5"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Preview Vendor Syntax</span>
                </button>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setShowFlowSpecModal(false)}
                    className="px-3 py-1.5 bg-gray-800 text-gray-300 rounded"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium"
                  >
                    Create FlowSpec Rule
                  </button>
                </div>
              </div>
            </form>

            {fsPreview && (
              <div className="mt-3 p-3 bg-[#0D1322] border border-[#1F2937] rounded space-y-2 text-[11px]">
                <div className="font-bold text-gray-300">Compiled Junos Syntax:</div>
                <pre className="p-2 bg-black/60 rounded text-emerald-400 font-mono overflow-x-auto">
                  {fsPreview.formatted_junos}
                </pre>
                <div className="font-bold text-gray-300">Compiled Cisco IOS-XR Syntax:</div>
                <pre className="p-2 bg-black/60 rounded text-blue-400 font-mono overflow-x-auto">
                  {fsPreview.formatted_cisco}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* RTBH BLACKHOLE MODAL */}
      {showRTBHModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 font-mono">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldX className="w-4 h-4 text-amber-400" />
                Configure RTBH Blackhole (RFC 7999) Rule
              </h3>
              <button onClick={() => setShowRTBHModal(false)} className="text-gray-400 hover:text-white">
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateRTBH} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-gray-400 block mb-1">Target Host / Subnet (/32 or /24-/32) *</label>
                  <input
                    type="text"
                    value={rtbhPrefix}
                    onChange={(e) => setRtbhPrefix(e.target.value)}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-rose-400 font-bold"
                    required
                  />
                </div>
                <div>
                  <label className="text-gray-400 block mb-1">Blackhole BGP Community *</label>
                  <input
                    type="text"
                    value={rtbhCommunity}
                    onChange={(e) => setRtbhCommunity(e.target.value)}
                    className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Operational Justification *</label>
                <textarea
                  rows={2}
                  value={rtbhJustification}
                  onChange={(e) => setRtbhJustification(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  required
                />
              </div>

              <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded text-[11px] text-amber-300">
                CRITICAL WARNING: RTBH will blackhole (drop) all ingress traffic to this host prefix. Dual approval from two separate network approvers is mandatory prior to activation.
              </div>

              <div className="flex justify-between items-center pt-2">
                <button
                  type="button"
                  onClick={handlePreviewRTBH}
                  className="px-3 py-1.5 bg-[#1F2937] hover:bg-[#374151] text-gray-200 rounded flex items-center gap-1.5"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Preview RTBH Update</span>
                </button>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setShowRTBHModal(false)}
                    className="px-3 py-1.5 bg-gray-800 text-gray-300 rounded"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded font-medium"
                  >
                    Create RTBH Rule
                  </button>
                </div>
              </div>
            </form>

            {rtbhPreview && (
              <div className="mt-3 p-3 bg-[#0D1322] border border-[#1F2937] rounded space-y-2 text-[11px]">
                <div className="font-bold text-gray-300">BGP UPDATE Payload Preview:</div>
                <pre className="p-2 bg-black/60 rounded text-amber-300 font-mono overflow-x-auto">
                  {JSON.stringify(rtbhPreview.formatted_bgp_update, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* RESET CIRCUIT BREAKER MODAL */}
      {showResetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 font-mono">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <RefreshCw className="w-4 h-4 text-amber-400" />
                Reset Safety Circuit Breaker
              </h3>
              <button onClick={() => setShowResetModal(false)} className="text-gray-400 hover:text-white">
                &times;
              </button>
            </div>

            <form onSubmit={handleResetCircuitBreaker} className="space-y-3 text-xs">
              <div>
                <label className="text-gray-400 block mb-1">Root Cause Explanation & Resolution Notes *</label>
                <textarea
                  rows={3}
                  value={resetNotes}
                  onChange={(e) => setResetNotes(e.target.value)}
                  placeholder="Explain why the circuit breaker tripped and why it is now safe to resume operations..."
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowResetModal(false)}
                  className="px-3 py-1.5 bg-gray-800 text-gray-300 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded font-medium"
                >
                  Confirm Reset to CLOSED
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CREATE CHANGE REQUEST MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
          <div className="bg-[#111827] border border-[#1F2937] rounded-xl max-w-xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1F2937]">
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                <FileText className="w-4 h-4 text-emerald-400" />
                Submit Routing Change Request
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-gray-400 hover:text-white font-mono text-sm"
              >
                &times;
              </button>
            </div>

            <form onSubmit={submitCreateChangeRequest} className="space-y-3 font-mono text-xs">
              <div>
                <label className="text-gray-400 block mb-1">Prefix *</label>
                <input
                  type="text"
                  value={crPrefix}
                  onChange={(e) => setCrPrefix(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  required
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Target BGP Peer *</label>
                <input
                  type="text"
                  value={crTargetPeer}
                  onChange={(e) => setCrTargetPeer(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  required
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Proposed BGP Diff Payload *</label>
                <textarea
                  rows={3}
                  value={crDiffPayload}
                  onChange={(e) => setCrDiffPayload(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-emerald-400 font-mono"
                  required
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Justification & Business Reason *</label>
                <textarea
                  rows={2}
                  value={crJustification}
                  onChange={(e) => setCrJustification(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-white"
                  required
                />
              </div>

              <div>
                <label className="text-gray-400 block mb-1">Rollback Procedure Instructions *</label>
                <textarea
                  rows={2}
                  value={crRollback}
                  onChange={(e) => setCrRollback(e.target.value)}
                  className="w-full bg-[#0D1322] border border-[#1F2937] rounded p-2 text-amber-300 font-mono"
                  required
                />
              </div>

              <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded text-[11px] text-blue-300">
                Notice: Change requests for routing optimization mandate dual-approval from two separate network approver accounts before validation.
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-medium"
                >
                  Submit Change Request
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
