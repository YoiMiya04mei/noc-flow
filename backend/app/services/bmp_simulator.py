"""BMP (RFC 7854) Binary Frame Synthesizer / Simulator

Generates compliant binary BMP packets for lab simulation, automated unit tests,
and demo verification when physical Juniper/FRRouting routers are not yet attached.
"""
import struct
import socket
import math
import time
from typing import List, Optional, Tuple


def _encode_ip(ip_str: str) -> bytes:
    """Encodes IPv4 into 16-byte field (12 zero octets + 4 octets)."""
    try:
        raw_v4 = socket.inet_aton(ip_str)
        return b"\x00" * 12 + raw_v4
    except Exception:
        return b"\x00" * 16


def _encode_per_peer_header(
    peer_ip: str,
    peer_asn: int,
    bgp_id_str: str = "198.51.100.1",
    is_ipv6: bool = False,
    peer_type: int = 0,
) -> bytes:
    """Encodes standard 42-byte BMP per-peer header."""
    peer_flags = 0x80 if is_ipv6 else 0x00
    peer_distinguisher = b"\x00" * 8
    peer_addr_bytes = _encode_ip(peer_ip)
    try:
        bgp_id_int = struct.unpack("!I", socket.inet_aton(bgp_id_str))[0]
    except Exception:
        bgp_id_int = 0
    now = time.time()
    ts_sec = int(now)
    ts_usec = int((now - ts_sec) * 1000000)

    header = struct.pack(
        "!BB8s16sIIII",
        peer_type,
        peer_flags,
        peer_distinguisher,
        peer_addr_bytes,
        peer_asn,
        bgp_id_int,
        ts_sec,
        ts_usec,
    )
    return header


def _encode_prefix(prefix_str: str) -> bytes:
    """Encodes IPv4 prefix (e.g. '1.1.1.0/24') into (prefix_len byte + octets)."""
    parts = prefix_str.strip().split("/")
    ip_str = parts[0]
    pfx_len = int(parts[1]) if len(parts) > 1 else 32
    octets_needed = math.ceil(pfx_len / 8.0)
    raw_ip = socket.inet_aton(ip_str)
    return struct.pack("!B", pfx_len) + raw_ip[:octets_needed]


def build_bmp_initiation(sys_name: str = "jdp-lab-mx480", sys_descr: str = "Junos 22.4R1.10 Lab Engine") -> bytes:
    """Builds RFC 7854 BMP Initiation Message (Type 4)."""
    tlvs = bytearray()
    # TLV 1: sysDescr
    desc_bytes = sys_descr.encode("utf-8")
    tlvs.extend(struct.pack("!HH", 1, len(desc_bytes)) + desc_bytes)
    # TLV 2: sysName
    name_bytes = sys_name.encode("utf-8")
    tlvs.extend(struct.pack("!HH", 2, len(name_bytes)) + name_bytes)

    total_len = 6 + len(tlvs)
    common_hdr = struct.pack("!BIB", 3, total_len, 4)
    return common_hdr + bytes(tlvs)


def build_bmp_peer_up(
    peer_ip: str,
    peer_asn: int,
    local_ip: str = "198.51.100.254",
    local_port: int = 179,
    remote_port: int = 49152,
    bgp_id: str = "198.51.100.1",
) -> bytes:
    """Builds RFC 7854 BMP Peer Up Notification (Type 3)."""
    per_peer = _encode_per_peer_header(peer_ip=peer_ip, peer_asn=peer_asn, bgp_id_str=bgp_id)
    local_addr_bytes = _encode_ip(local_ip)
    ports = struct.pack("!HH", local_port, remote_port)

    # Minimal simulated BGP OPEN messages (19 bytes minimum)
    simulated_open = b"\xff" * 16 + struct.pack("!HBBHI", 29, 1, 4, 136052 & 0xFFFF, 180) + socket.inet_aton(local_ip) + b"\x00"
    body = per_peer + local_addr_bytes + ports + simulated_open + simulated_open
    total_len = 6 + len(body)
    common_hdr = struct.pack("!BIB", 3, total_len, 3)
    return common_hdr + body


def build_bmp_peer_down(
    peer_ip: str,
    peer_asn: int,
    reason: int = 1,
    bgp_id: str = "198.51.100.1",
) -> bytes:
    """Builds RFC 7854 BMP Peer Down Notification (Type 2)."""
    per_peer = _encode_per_peer_header(peer_ip=peer_ip, peer_asn=peer_asn, bgp_id_str=bgp_id)
    reason_byte = struct.pack("!B", reason)
    body = per_peer + reason_byte
    total_len = 6 + len(body)
    common_hdr = struct.pack("!BIB", 3, total_len, 2)
    return common_hdr + body


def build_bmp_route_monitoring(
    peer_ip: str,
    peer_asn: int,
    announced_prefixes: Optional[List[str]] = None,
    withdrawn_prefixes: Optional[List[str]] = None,
    next_hop: str = "198.51.100.1",
    as_path_asns: Optional[List[int]] = None,
    communities: Optional[List[Tuple[int, int]]] = None,
    bgp_id: str = "198.51.100.1",
) -> bytes:
    """Builds RFC 7854 BMP Route Monitoring Message (Type 0) with encapsulated BGP Update."""
    if announced_prefixes is None:
        announced_prefixes = []
    if withdrawn_prefixes is None:
        withdrawn_prefixes = []
    if as_path_asns is None:
        as_path_asns = [peer_asn]

    per_peer = _encode_per_peer_header(peer_ip=peer_ip, peer_asn=peer_asn, bgp_id_str=bgp_id)

    # 1. Withdrawn routes bytes
    withdrawn_bytes = bytearray()
    for wp in withdrawn_prefixes:
        withdrawn_bytes.extend(_encode_prefix(wp))
    withdrawn_hdr = struct.pack("!H", len(withdrawn_bytes))

    # 2. Path Attributes
    attrs = bytearray()
    # ORIGIN (Type 1, IGP = 0)
    attrs.extend(struct.pack("!BBB", 0x40, 1, 1) + b"\x00")
    # AS_PATH (Type 2, 4-byte ASN sequence)
    as_seg = struct.pack("!BB", 2, len(as_path_asns)) # AS_SEQUENCE
    for a in as_path_asns:
        as_seg += struct.pack("!I", a)
    attrs.extend(struct.pack("!BBB", 0x40, 2, len(as_seg)) + as_seg)
    # NEXT_HOP (Type 3)
    nh_bytes = socket.inet_aton(next_hop)
    attrs.extend(struct.pack("!BBB", 0x40, 3, 4) + nh_bytes)

    # COMMUNITIES (Type 8)
    if communities:
        comm_bytes = bytearray()
        for c_high, c_low in communities:
            comm_bytes.extend(struct.pack("!HH", c_high, c_low))
        attrs.extend(struct.pack("!BBB", 0xC0, 8, len(comm_bytes)) + comm_bytes)

    path_attrs_hdr = struct.pack("!H", len(attrs))

    # 3. NLRI announced prefixes
    nlri_bytes = bytearray()
    for ap in announced_prefixes:
        nlri_bytes.extend(_encode_prefix(ap))

    # BGP Update PDU
    bgp_body = withdrawn_hdr + bytes(withdrawn_bytes) + path_attrs_hdr + bytes(attrs) + bytes(nlri_bytes)
    bgp_total_len = 19 + len(bgp_body)
    bgp_pdu = b"\xff" * 16 + struct.pack("!HB", bgp_total_len, 2) + bgp_body

    bmp_body = per_peer + bgp_pdu
    bmp_total_len = 6 + len(bmp_body)
    common_hdr = struct.pack("!BIB", 3, bmp_total_len, 0)
    return common_hdr + bmp_body
