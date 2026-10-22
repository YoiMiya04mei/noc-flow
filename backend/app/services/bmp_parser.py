"""BMP (BGP Monitoring Protocol - RFC 7854) Binary Parser

Implements RFC 7854 message parsing:
- Common Header (Version 3)
- Per-Peer Header (IPv4 & IPv6, 4-byte ASN)
- Message Type 0: Route Monitoring (with BGP Update NLRI, Withdrawn, AS-PATH, Next-Hop, Communities)
- Message Type 2: Peer Down Notification
- Message Type 3: Peer Up Notification
- Message Type 4: Initiation Message (sysName, sysDescr)
- Message Type 5: Termination Message

Guaranteed to never raise unhandled exceptions / crash on malformed or truncated binary frames.
"""
import struct
import socket
import math
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone


class BMPParseError(Exception):
    """Raised when a BMP frame cannot be parsed or violates protocol specifications."""
    pass


# BMP Constants per RFC 7854
BMP_VERSION = 3
BMP_COMMON_HEADER_LEN = 6
BMP_PER_PEER_HEADER_LEN = 42

# BMP Message Types
BMP_MSG_ROUTE_MONITORING = 0
BMP_MSG_STATS_REPORT = 1
BMP_MSG_PEER_DOWN = 2
BMP_MSG_PEER_UP = 3
BMP_MSG_INITIATION = 4
BMP_MSG_TERMINATION = 5
BMP_MSG_ROUTE_MIRRORING = 6

# BGP Update Path Attribute Types
BGP_ATTR_ORIGIN = 1
BGP_ATTR_AS_PATH = 2
BGP_ATTR_NEXT_HOP = 3
BGP_ATTR_MED = 4
BGP_ATTR_LOCAL_PREF = 5
BGP_ATTR_COMMUNITIES = 8


@dataclass
class BMPCommonHeader:
    version: int
    msg_length: int
    msg_type: int


@dataclass
class BMPPeerHeader:
    peer_type: int
    peer_flags: int
    is_ipv6: bool
    is_post_policy: bool
    is_2byte_as: bool
    peer_distinguisher: bytes
    peer_ip: str
    peer_asn: int
    peer_bgp_id: str
    timestamp: datetime


@dataclass
class BMPInitiationMessage:
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None
    info_strings: List[str] = field(default_factory=list)


@dataclass
class BMPPeerUpMessage:
    peer: BMPPeerHeader
    local_address: str
    local_port: int
    remote_port: int
    sent_open: Optional[Dict[str, Any]] = None
    received_open: Optional[Dict[str, Any]] = None
    sys_info: Optional[str] = None


@dataclass
class BMPPeerDownMessage:
    peer: BMPPeerHeader
    reason: int
    reason_text: str
    data: bytes = b""


@dataclass
class BGPRouteItem:
    prefix: str
    next_hop: Optional[str] = None
    as_path: Optional[str] = None
    origin: str = "IGP"
    med: Optional[int] = None
    local_pref: Optional[int] = None
    communities: Optional[str] = None


@dataclass
class BMPRouteMonitoringMessage:
    peer: BMPPeerHeader
    announced_routes: List[BGPRouteItem] = field(default_factory=list)
    withdrawn_routes: List[str] = field(default_factory=list)
    raw_bgp_update: bytes = b""


@dataclass
class BMPTerminationMessage:
    reason: int
    reason_text: str
    description: Optional[str] = None


def parse_common_header(data: bytes) -> BMPCommonHeader:
    """Parses and validates 6-byte BMP common header."""
    if len(data) < BMP_COMMON_HEADER_LEN:
        raise BMPParseError(f"BMP packet truncated: length {len(data)} < {BMP_COMMON_HEADER_LEN}")
    
    version, msg_length, msg_type = struct.unpack("!BIB", data[:BMP_COMMON_HEADER_LEN])
    if version != BMP_VERSION:
        raise BMPParseError(f"Unsupported BMP version {version}, expected version {BMP_VERSION}")
    if msg_length < BMP_COMMON_HEADER_LEN:
        raise BMPParseError(f"Invalid BMP message length {msg_length} < {BMP_COMMON_HEADER_LEN}")
    if msg_length > len(data):
        raise BMPParseError(f"Incomplete BMP message: declared {msg_length} bytes, got {len(data)}")

    return BMPCommonHeader(version=version, msg_length=msg_length, msg_type=msg_type)


def parse_per_peer_header(data: bytes, offset: int = BMP_COMMON_HEADER_LEN) -> Tuple[BMPPeerHeader, int]:
    """Parses 42-byte BMP per-peer header starting at offset."""
    if len(data) < offset + BMP_PER_PEER_HEADER_LEN:
        raise BMPParseError(f"Per-peer header truncated: required {offset + BMP_PER_PEER_HEADER_LEN}, got {len(data)}")

    header_bytes = data[offset : offset + BMP_PER_PEER_HEADER_LEN]
    peer_type, peer_flags = struct.unpack("!BB", header_bytes[0:2])
    peer_distinguisher = header_bytes[2:10]
    peer_addr_bytes = header_bytes[10:26]
    peer_asn, bgp_id_int, ts_sec, ts_usec = struct.unpack("!IIII", header_bytes[26:42])

    is_ipv6 = bool(peer_flags & 0x80)
    is_post_policy = bool(peer_flags & 0x40)
    is_2byte_as = not bool(peer_flags & 0x20) # 0 = legacy 2-byte, 1 = 4-byte

    if is_ipv6:
        try:
            peer_ip = socket.inet_ntop(socket.AF_INET6, peer_addr_bytes)
        except Exception:
            peer_ip = "::"
    else:
        # IPv4 is located in last 4 bytes of 16-byte field
        try:
            peer_ip = socket.inet_ntop(socket.AF_INET, peer_addr_bytes[12:16])
        except Exception:
            peer_ip = "0.0.0.0"

    try:
        peer_bgp_id = socket.inet_ntoa(struct.pack("!I", bgp_id_int))
    except Exception:
        peer_bgp_id = "0.0.0.0"

    ts_float = float(ts_sec) + float(ts_usec) / 1000000.0
    try:
        ts = datetime.fromtimestamp(ts_float, tz=timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)

    peer_header = BMPPeerHeader(
        peer_type=peer_type,
        peer_flags=peer_flags,
        is_ipv6=is_ipv6,
        is_post_policy=is_post_policy,
        is_2byte_as=is_2byte_as,
        peer_distinguisher=peer_distinguisher,
        peer_ip=peer_ip,
        peer_asn=peer_asn,
        peer_bgp_id=peer_bgp_id,
        timestamp=ts,
    )
    return peer_header, offset + BMP_PER_PEER_HEADER_LEN


def parse_bgp_prefixes(data: bytes, offset: int, length: int) -> Tuple[List[str], int]:
    """Parses BGP NLRI / Withdrawn prefix list (1-byte length + ceil(len/8) octets)."""
    prefixes: List[str] = []
    end = offset + length
    curr = offset

    while curr < end:
        if curr >= len(data):
            break
        prefix_len = data[curr]
        curr += 1
        octets_count = math.ceil(prefix_len / 8.0)
        if curr + octets_count > end or curr + octets_count > len(data):
            break
        
        prefix_bytes = data[curr : curr + octets_count]
        curr += octets_count

        # Pad to 4 bytes for IPv4
        padded = prefix_bytes + b"\x00" * (4 - len(prefix_bytes))
        try:
            ip_str = socket.inet_ntoa(padded[:4])
            prefixes.append(f"{ip_str}/{prefix_len}")
        except Exception:
            continue

    return prefixes, end


def parse_bgp_path_attributes(data: bytes, offset: int, length: int) -> Dict[str, Any]:
    """Parses BGP Path Attributes (AS_PATH, NEXT_HOP, ORIGIN, COMMUNITIES, etc.)."""
    attrs: Dict[str, Any] = {
        "as_path": "",
        "next_hop": None,
        "origin": "IGP",
        "med": None,
        "local_pref": None,
        "communities": None,
    }
    end = offset + length
    curr = offset

    while curr < end:
        if curr + 2 > end or curr + 2 > len(data):
            break
        flags = data[curr]
        attr_type = data[curr + 1]
        curr += 2

        # Check extended length bit (0x10)
        is_extended = bool(flags & 0x10)
        if is_extended:
            if curr + 2 > end or curr + 2 > len(data):
                break
            attr_len = struct.unpack("!H", data[curr : curr + 2])[0]
            curr += 2
        else:
            if curr + 1 > end or curr + 1 > len(data):
                break
            attr_len = data[curr]
            curr += 1

        if curr + attr_len > end or curr + attr_len > len(data):
            break

        val_bytes = data[curr : curr + attr_len]
        curr += attr_len

        # Decode specific attribute types
        if attr_type == BGP_ATTR_ORIGIN and len(val_bytes) >= 1:
            code = val_bytes[0]
            attrs["origin"] = "IGP" if code == 0 else ("EGP" if code == 1 else "INCOMPLETE")

        elif attr_type == BGP_ATTR_NEXT_HOP and len(val_bytes) >= 4:
            try:
                attrs["next_hop"] = socket.inet_ntoa(val_bytes[:4])
            except Exception:
                pass

        elif attr_type == BGP_ATTR_MED and len(val_bytes) >= 4:
            attrs["med"] = struct.unpack("!I", val_bytes[:4])[0]

        elif attr_type == BGP_ATTR_LOCAL_PREF and len(val_bytes) >= 4:
            attrs["local_pref"] = struct.unpack("!I", val_bytes[:4])[0]

        elif attr_type == BGP_ATTR_AS_PATH and len(val_bytes) >= 2:
            asns: List[str] = []
            as_curr = 0
            while as_curr + 2 <= len(val_bytes):
                seg_type = val_bytes[as_curr]
                seg_len = val_bytes[as_curr + 1]
                as_curr += 2

                # Detect 4-byte vs 2-byte ASN heuristic based on segment length
                asn_size = 4 if (len(val_bytes) - as_curr) >= seg_len * 4 and seg_len > 0 else 2
                for _ in range(seg_len):
                    if as_curr + asn_size > len(val_bytes):
                        break
                    if asn_size == 4:
                        asn_val = struct.unpack("!I", val_bytes[as_curr : as_curr + 4])[0]
                    else:
                        asn_val = struct.unpack("!H", val_bytes[as_curr : as_curr + 2])[0]
                    asns.append(str(asn_val))
                    as_curr += asn_size
            attrs["as_path"] = " ".join(asns)

        elif attr_type == BGP_ATTR_COMMUNITIES:
            comms: List[str] = []
            for i in range(0, len(val_bytes) - 3, 4):
                val = struct.unpack("!I", val_bytes[i : i + 4])[0]
                high = val >> 16
                low = val & 0xFFFF
                comms.append(f"{high}:{low}")
            if comms:
                attrs["communities"] = ", ".join(comms)

    return attrs


def parse_bgp_update(data: bytes, offset: int, length: int) -> Tuple[List[BGPRouteItem], List[str]]:
    """Parses encapsulated BGP UPDATE PDU inside a BMP Route Monitoring message."""
    announced_routes: List[BGPRouteItem] = []
    withdrawn_prefixes: List[str] = []

    # Check minimum BGP header length: 16 (marker) + 2 (length) + 1 (type) = 19
    if length < 19 or offset + length > len(data):
        return announced_routes, withdrawn_prefixes

    bgp_data = data[offset : offset + length]
    # Check marker (16 bytes of 0xFF)
    if bgp_data[:16] != b"\xff" * 16:
        return announced_routes, withdrawn_prefixes

    bgp_len, bgp_type = struct.unpack("!HB", bgp_data[16:19])
    if bgp_type != 2: # 2 = UPDATE
        return announced_routes, withdrawn_prefixes

    curr = 19
    # 1. Withdrawn Routes
    if curr + 2 > len(bgp_data):
        return announced_routes, withdrawn_prefixes
    withdrawn_len = struct.unpack("!H", bgp_data[curr : curr + 2])[0]
    curr += 2

    if withdrawn_len > 0:
        withdrawn_prefixes, curr = parse_bgp_prefixes(bgp_data, curr, withdrawn_len)

    # 2. Total Path Attributes
    if curr + 2 > len(bgp_data):
        return announced_routes, withdrawn_prefixes
    path_attr_len = struct.unpack("!H", bgp_data[curr : curr + 2])[0]
    curr += 2

    attrs = {}
    if path_attr_len > 0:
        attrs = parse_bgp_path_attributes(bgp_data, curr, path_attr_len)
        curr += path_attr_len

    # 3. NLRI (Announced prefixes)
    nlri_len = len(bgp_data) - curr
    if nlri_len > 0:
        announced_prefixes, _ = parse_bgp_prefixes(bgp_data, curr, nlri_len)
        for pfx in announced_prefixes:
            announced_routes.append(
                BGPRouteItem(
                    prefix=pfx,
                    next_hop=attrs.get("next_hop"),
                    as_path=attrs.get("as_path"),
                    origin=attrs.get("origin", "IGP"),
                    med=attrs.get("med"),
                    local_pref=attrs.get("local_pref"),
                    communities=attrs.get("communities"),
                )
            )

    return announced_routes, withdrawn_prefixes


def parse_bmp_message(data: bytes) -> Any:
    """
    Main parser entrypoint. Parses a single complete BMP frame.
    Returns one of:
      - BMPInitiationMessage
      - BMPPeerUpMessage
      - BMPPeerDownMessage
      - BMPRouteMonitoringMessage
      - BMPTerminationMessage
    """
    hdr = parse_common_header(data)
    body = data[BMP_COMMON_HEADER_LEN : hdr.msg_length]

    # Type 4: Initiation Message
    if hdr.msg_type == BMP_MSG_INITIATION:
        msg = BMPInitiationMessage()
        curr = 0
        while curr + 4 <= len(body):
            tlv_type, tlv_len = struct.unpack("!HH", body[curr : curr + 4])
            curr += 4
            val_bytes = body[curr : curr + tlv_len]
            curr += tlv_len
            val_str = val_bytes.decode("utf-8", errors="replace")
            if tlv_type == 1:
                msg.sys_descr = val_str
            elif tlv_type == 2:
                msg.sys_name = val_str
            else:
                msg.info_strings.append(val_str)
        return msg

    # Type 3: Peer Up Notification
    elif hdr.msg_type == BMP_MSG_PEER_UP:
        peer, next_offset = parse_per_peer_header(data)
        # Offset in body
        body_offset = next_offset - BMP_COMMON_HEADER_LEN
        local_addr = "0.0.0.0"
        local_port = 0
        remote_port = 0
        if len(body) >= body_offset + 20:
            local_addr_bytes = body[body_offset : body_offset + 16]
            local_port, remote_port = struct.unpack("!HH", body[body_offset + 16 : body_offset + 20])
            if peer.is_ipv6:
                try:
                    local_addr = socket.inet_ntop(socket.AF_INET6, local_addr_bytes)
                except Exception:
                    pass
            else:
                try:
                    local_addr = socket.inet_ntop(socket.AF_INET, local_addr_bytes[12:16])
                except Exception:
                    pass

        return BMPPeerUpMessage(
            peer=peer,
            local_address=local_addr,
            local_port=local_port,
            remote_port=remote_port,
            sys_info=f"BGP Peer Up {peer.peer_ip} (AS{peer.peer_asn})",
        )

    # Type 2: Peer Down Notification
    elif hdr.msg_type == BMP_MSG_PEER_DOWN:
        peer, next_offset = parse_per_peer_header(data)
        body_offset = next_offset - BMP_COMMON_HEADER_LEN
        reason = 0
        if len(body) > body_offset:
            reason = body[body_offset]

        reason_names = {
            1: "Local BGP Notification",
            2: "Local FSM down",
            3: "Remote BGP Notification",
            4: "Remote No notification",
            5: "Peer de-configured",
        }
        reason_text = reason_names.get(reason, f"Reason Code {reason}")
        return BMPPeerDownMessage(
            peer=peer,
            reason=reason,
            reason_text=reason_text,
            data=body[body_offset + 1 :],
        )

    # Type 0: Route Monitoring
    elif hdr.msg_type == BMP_MSG_ROUTE_MONITORING:
        peer, next_offset = parse_per_peer_header(data)
        bgp_length = hdr.msg_length - next_offset
        announced, withdrawn = parse_bgp_update(data, next_offset, bgp_length)
        return BMPRouteMonitoringMessage(
            peer=peer,
            announced_routes=announced,
            withdrawn_routes=withdrawn,
            raw_bgp_update=data[next_offset : hdr.msg_length],
        )

    # Type 5: Termination Message
    elif hdr.msg_type == BMP_MSG_TERMINATION:
        reason = 1
        desc = None
        curr = 0
        while curr + 4 <= len(body):
            tlv_type, tlv_len = struct.unpack("!HH", body[curr : curr + 4])
            curr += 4
            val_bytes = body[curr : curr + tlv_len]
            curr += tlv_len
            if tlv_type == 1 and len(val_bytes) >= 2:
                reason = struct.unpack("!H", val_bytes[:2])[0]
            elif tlv_type == 0:
                desc = val_bytes.decode("utf-8", errors="replace")

        reasons = {
            0: "Administrative Close",
            1: "Unspecified Reason",
            2: "Out of Resources",
            3: "Redundant Connection",
            4: "Permanently Administratively Down",
        }
        return BMPTerminationMessage(
            reason=reason,
            reason_text=reasons.get(reason, f"Code {reason}"),
            description=desc,
        )

    else:
        raise BMPParseError(f"Unsupported or unimplemented BMP message type {hdr.msg_type}")
