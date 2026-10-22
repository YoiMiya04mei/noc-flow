# ADR 0004: Flow Collector Protocol Parsers and Normalizer

## Status
Accepted

## Context
Carriers deploy heterogeneous multi-vendor routing hardware including Cisco, Juniper, Huawei, Mikrotik, and Arista. These devices export diverse telemetry formats:
- NetFlow v5 (fixed 48-byte records, legacy IPv4 only)
- NetFlow v9 (template-driven, supports IPv4/IPv6 and dynamic fields)
- IPFIX / RFC 7011 (standardized version of NetFlow v9 with Enterprise bit)
- sFlow v5 (packet sampling with multi-layered flow and counter records)

A robust collector must parse these formats reliably without crashing on corrupt UDP datagrams or unknown template IDs, and normalize them into a uniform structure for ClickHouse ingestion.

## Decision
1. **Modular Go Package Structure**:
   - `pkg/protocol/netflow5`: Fixed-size struct unpacker with header validation.
   - `pkg/protocol/netflow9`: State-aware template repository per exporter IP and template-based record decoding.
   - `pkg/protocol/ipfix`: RFC 7011 compliant set, template, and record parser.
   - `pkg/protocol/sflow5`: Header, sample header, and raw packet header reader.
2. **Unified Normalized Record (`FlowRecord`)**:
   - All parsers emit a uniform `FlowRecord` containing:
     - `Timestamp`: Datagram arrival or device flow export timestamp.
     - `ExporterIP`: IP address of exporting router.
     - `SrcIP`, `DstIP`: IPv4 or IPv6 string representation.
     - `SrcPort`, `DstPort`: uint16 port numbers.
     - `Protocol`: uint8 IANA protocol number (6 = TCP, 17 = UDP, 1 = ICMP, etc.).
     - `TCPFlags`: uint8 TCP control bits.
     - `Packets`, `Bytes`: uint64 volume counters adjusted for sampling rate if known.
     - `InputSNMP`, `OutputSNMP`: uint32 interface indices.
     - `NextHop`: Next-hop router IP.
     - `SamplingRate`: uint32 sampling interval factor (1:N).
     - `FlowFormat`: String identifier (`netflow5`, `netflow9`, `ipfix`, `sflow5`).
3. **Resilience & Fault Isolation**:
   - Every parser operation is bounded by length checks before slicing byte buffers.
   - Malformed packets increment `ParseErrors` counter and log structured warnings without panic.
   - Automated unit tests include byte fixture files for both valid samples and deliberately corrupted/truncated datagrams.

## Consequences
- **Positive**:
  - Consistent ClickHouse schema regardless of router vendor or protocol.
  - Zero-crash stability during packet bursts or network fuzzing.
- **Negative / Trade-offs**:
  - Vendor-specific custom flow enterprise fields that are not part of the standard schema are dropped unless explicitly mapped.
