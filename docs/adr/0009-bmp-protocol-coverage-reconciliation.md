# ADR 0009: RFC 7854 BGP Monitoring Protocol (BMP) Coverage Reconciliation

## Status
Accepted / Authoritative Scope Defined

## Context
During earlier project milestones, documentation and technical summaries presented varying descriptions of RFC 7854 BMP protocol support:
- In Phase 4, BMP Statistics Report (Type 1) and Route Mirroring (Type 6) were designated as out-of-scope for the core routing observability engine.
- Subsequent high-level summaries made generalized statements implying support across "Message types 0 to 6".

To eliminate ambiguity ahead of the Controlled Acceptance Test (UAT), an exhaustive source code audit of `backend/app/services/bmp_parser.py` and `backend/tests/test_bgp_and_probe.py` was conducted to formally document the exact wire-level parsing capabilities.

---

## 1. Authoritative BMP Message Type Matrix

The JDP Route Intelligence Platform's binary BMP parser strictly enforces the following RFC 7854 message type support:

| Type ID | Message Name | Implementation Status | Functional Behavior |
|---|---|---|---|
| **Type 0** | **Route Monitoring** | **FULLY IMPLEMENTED & PARSED** | Decodes Per-Peer Header and encapsulated RFC 4271 BGP UPDATE messages: NLRI prefix announcements (IPv4/IPv6 CIDR), withdrawn routes, AS_PATH sequences/sets, NEXT_HOP IP, BGP COMMUNITIES, MULTI_EXIT_DISC (MED), and LOCAL_PREF. Updates `BGPRoute` and `RouteEvent` tables. |
| **Type 1** | **Statistics Report** | **UNSUPPORTED / OUT OF SCOPE** | RFC 7854 Section 4.8 statistical counters (routes rejected, prefixes invalid, etc.) are **not parsed**. Receiving Type 1 raises a controlled `BMPParseError("Unsupported or unimplemented BMP message type 1")`. |
| **Type 2** | **Peer Down Notification** | **FULLY IMPLEMENTED & PARSED** | Decodes Per-Peer Header, reason code (1: Local BGP Notification, 2: Local FSM Down, 3: Remote BGP Notification, 4: Remote No Notification, 5: Peer De-configured), human-readable description, and trailing BGP notification byte data. Emits `PEER_DOWN` route events. |
| **Type 3** | **Peer Up Notification** | **FULLY IMPLEMENTED & PARSED** | Decodes Per-Peer Header, local IP address, local port, remote port, and parses sent/received BGP OPEN messages (ASN, BGP ID, Hold Time). Updates `BGPPeer` state to `Established`. |
| **Type 4** | **Initiation Message** | **FULLY IMPLEMENTED & PARSED** | Decodes Type-Length-Value (TLV) headers: Type 1 (`sysName`) and Type 2 (`sysDescr`). Normalizes router identity into device metadata. |
| **Type 5** | **Termination Message** | **FULLY IMPLEMENTED & PARSED** | Decodes TLV headers: Type 1 (Reason codes 0: Admin close, 1: Unspecified, 2: Out of resources, 3: Redundant connection, 4: Permanently administratively down) and Type 0 (String description). Gracefully closes listener context. |
| **Type 6** | **Route Mirroring** | **UNSUPPORTED / OUT OF SCOPE** | RFC 7854 Section 4.9 raw PDU mirroring is **not parsed**. Receiving Type 6 raises a controlled `BMPParseError("Unsupported or unimplemented BMP message type 6")`. |

---

## 2. Test Fixture Methodology vs Live Parser Execution

The test suite in `backend/tests/test_bgp_and_probe.py` evaluates the BMP engine through a rigorous multi-tier strategy:

1. **RFC 7854 Wire-Format Binary Fixtures**:
   - Synthetically constructed binary byte streams adhering precisely to network byte order (`!B`, `!H`, `!I`).
   - Validates parser determinism against standard frames (Initiation, Peer Up, Peer Down, Route Monitoring).
2. **Adversarial & Boundary Frame Handling**:
   - `test_bmp_common_header_truncated`: Incomplete headers ($<6$ bytes) return `None` (awaiting more TCP data) without raising exceptions.
   - `test_bmp_excessive_length_detection`: Frames claiming length $>1\text{ MB}$ or $<6\text{ bytes}$ trigger immediate `BMPParseError` to prevent memory exhaustion attacks.
   - `test_bmp_corrupted_payload_graceful_handling`: Random noise and truncated BGP Update attributes are handled gracefully without application crashes (`zero-crash guarantee`).
3. **Database & Event Pipeline Integration**:
   - `test_bmp_pipeline_peer_up_and_route_monitoring_lifecycle`: End-to-end integration test feeding binary Peer Up and Route Monitoring frames through the parser and verifying database updates in `BGPPeer`, `BGPRoute`, and `RouteEvent`.

---

## 3. Operational Guarantees for UAT
- The supported message types (0, 2, 3, 4, 5) satisfy 100% of NOC visibility requirements: session state monitoring, route advertisement tracking, withdrawal detection, and AS path analytics.
- Unhandled message types (1 and 6) do not crash the TCP listener worker; the parser logs a warning, skips the frame, and continues listening for subsequent valid frames.
