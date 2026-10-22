"""Egress Binding & Network Path Isolation Manager

Documents and enforces path isolation mechanisms across operating system kernels:

1. SO_BINDTODEVICE (Linux Only):
   - Directly forces layer-2 egress on a specific physical or sub-interface (e.g. eth1, vlan100).
   - Requires CAP_NET_RAW capability or superuser permissions.
   - Truly isolates upstream paths regardless of main routing table default gateway.

2. SOURCE_IP_BIND (Cross-Platform: Windows, Linux, Darwin):
   - Binds the socket local endpoint to a specific assigned IP address (sock.bind((source_ip, 0))).
   - Works on all major operating systems without special root privileges.
   - CAVEAT: Under standard Linux/Windows kernel routing, source IP binding alone does NOT guarantee
     the packet exits via the desired upstream link unless policy routing (PBR / 'ip rule add from ... table')
     is configured on the host. The packet may still follow the system default route while having the source IP rewritten.

3. OS_ROUTING_FALLBACK (Standard Kernel Routing):
   - The OS kernel routing table selects the egress interface based on destination IP longest prefix match.
   - Used when no specific egress interface or source IP is designated.
"""
import sys
import socket
import logging
from enum import Enum
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("jdp_platform.egress")


class EgressBindingMode(str, Enum):
    SO_BINDTODEVICE = "so_bindtodevice"
    SOURCE_IP_BIND = "source_ip_bind"
    OS_ROUTING_FALLBACK = "os_routing"


# Linux socket constant for SO_BINDTODEVICE
SO_BINDTODEVICE_OPT = 25


class EgressBindingManager:
    """Detects host platform capabilities and configures socket egress binding safely."""

    def __init__(self):
        self.platform = sys.platform
        self.is_linux = self.platform.startswith("linux")
        self.is_windows = self.platform == "win32"
        self.is_darwin = self.platform == "darwin"

        # Check SO_BINDTODEVICE support
        self.has_so_bindtodevice = hasattr(socket, "SO_BINDTODEVICE") or self.is_linux

    def get_capabilities(self) -> Dict[str, Any]:
        """Returns comprehensive diagnostic information on host egress binding capabilities."""
        return {
            "platform": self.platform,
            "so_bindtodevice_supported": self.has_so_bindtodevice,
            "source_ip_bind_supported": True,
            "os_routing_fallback_supported": True,
            "recommended_mode": "so_bindtodevice" if self.has_so_bindtodevice else "source_ip_bind",
            "documentation": {
                "so_bindtodevice": (
                    "Linux kernel socket option (25) binding layer-2 egress interface. "
                    "Forces packets onto specified interface regardless of default route. "
                    "Requires CAP_NET_RAW."
                ),
                "source_ip_bind": (
                    "Standard BSD socket bind((ip, 0)). Supported on Windows and Linux. "
                    "Note: In multi-homed hosts without policy routing (PBR), OS routing table "
                    "may still route packet via primary gateway despite source IP."
                ),
                "os_routing_fallback": (
                    "Standard kernel routing table selection. Destined IP dictates interface."
                ),
            },
            "environment_caveat": (
                "Running on Windows: SO_BINDTODEVICE is not supported by NT kernel. "
                "Active probes utilize Source IP binding (bind((src_ip, 0))) or OS routing table."
                if self.is_windows
                else "Running on POSIX: SO_BINDTODEVICE is available when CAP_NET_RAW is granted."
            ),
        }

    def configure_socket_binding(
        self,
        sock: socket.socket,
        egress_interface: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> Tuple[EgressBindingMode, Optional[str]]:
        """
        Attempts to bind a created socket to the requested egress interface or source IP.
        Returns:
            (EgressBindingMode, warning_or_info_message)
        """
        # 1. Attempt SO_BINDTODEVICE if requested and supported
        if egress_interface and self.has_so_bindtodevice and self.is_linux:
            try:
                # Interface name as null-terminated or raw bytes
                iface_bytes = egress_interface.encode("utf-8")
                sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE_OPT, iface_bytes)
                logger.debug("Successfully bound socket to device '%s'", egress_interface)
                return EgressBindingMode.SO_BINDTODEVICE, f"Bound to interface '{egress_interface}' via SO_BINDTODEVICE"
            except PermissionError:
                logger.warning(
                    "SO_BINDTODEVICE failed with PermissionError (CAP_NET_RAW required). Falling back to source IP."
                )
            except OSError as e:
                logger.warning("SO_BINDTODEVICE failed for '%s': %s. Falling back.", egress_interface, e)

        # 2. Attempt SOURCE_IP_BIND if source_ip is provided
        if source_ip:
            try:
                sock.bind((source_ip, 0))
                notice = (
                    f"Bound socket endpoint to local source IP '{source_ip}'. "
                    + ("(SO_BINDTODEVICE unsupported on Windows)" if self.is_windows else "")
                )
                logger.debug("Bound socket to source IP '%s'", source_ip)
                return EgressBindingMode.SOURCE_IP_BIND, notice
            except OSError as e:
                logger.warning("Failed to bind socket to source IP '%s': %s", source_ip, e)

        # 3. Fallback to OS routing table
        return EgressBindingMode.OS_ROUTING_FALLBACK, "Using standard OS kernel routing table"


# Global singleton egress manager
egress_manager = EgressBindingManager()
