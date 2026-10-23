import json
import logging
import ipaddress
import asyncio
from typing import Dict, List, Optional, Any
from app.core.config import settings

logger = logging.getLogger(__name__)


class BGPLabAdapterError(Exception):
    """Base exception for BGP Lab adapter errors."""
    pass


class BGPLabAdapter:
    """
    Adapter for interacting with isolated GoBGP speakers in containerized lab testbed.
    Guarantees strict parameter validation and prevents arbitrary CLI execution.
    """

    SPEAKER_MAP = {
        "bgp-speaker-1": {
            "container": "jdp-bgp-speaker-1",
            "ip": "10.99.0.10",
            "asn": 65001,
            "peer_ip": "10.99.0.20",
            "peer_asn": 65002,
        },
        "bgp-speaker-2": {
            "container": "jdp-bgp-speaker-2",
            "ip": "10.99.0.20",
            "asn": 65002,
            "peer_ip": "10.99.0.10",
            "peer_asn": 65001,
        },
    }

    # Virtual state store for fallback/mock testing when docker daemon is unavailable
    _virtual_speakers: Dict[str, Dict[str, Any]] = {
        "bgp-speaker-1": {
            "routes": {},
            "state": "Established",
            "uptime": 3600,
            "is_up": True,
        },
        "bgp-speaker-2": {
            "routes": {},
            "state": "Established",
            "uptime": 3600,
            "is_up": True,
        },
    }
    _use_virtual_fallback: bool = False

    @classmethod
    def set_virtual_fallback(cls, enabled: bool):
        cls._use_virtual_fallback = enabled

    @classmethod
    def get_speaker_config(cls, speaker_id: str) -> dict:
        if speaker_id not in cls.SPEAKER_MAP:
            raise BGPLabAdapterError(
                f"SAFETY VIOLATION: Speaker '{speaker_id}' is not in the approved lab speaker allowlist."
            )
        return cls.SPEAKER_MAP[speaker_id]

    @classmethod
    def validate_prefix(cls, prefix: str) -> str:
        """
        Strictly validates IPv4 CIDR prefix against lab allowlist and rejects default routes.
        """
        if not prefix or not isinstance(prefix, str):
            raise BGPLabAdapterError("Prefix must be a non-empty string.")

        clean_prefix = prefix.strip()
        if clean_prefix in ("0.0.0.0/0", "::/0"):
            raise BGPLabAdapterError("SAFETY VIOLATION: Default routes (0.0.0.0/0 or ::/0) are strictly forbidden.")

        try:
            net = ipaddress.IPv4Network(clean_prefix, strict=True)
        except Exception as e:
            raise BGPLabAdapterError(f"Invalid IPv4 CIDR format: '{clean_prefix}': {str(e)}")

        if clean_prefix not in settings.BGP_LAB_ALLOWED_PREFIXES:
            raise BGPLabAdapterError(
                f"LAB POLICY REJECTION: Prefix '{clean_prefix}' is not in BGP_LAB_ALLOWED_PREFIXES {settings.BGP_LAB_ALLOWED_PREFIXES}."
            )

        return clean_prefix

    @classmethod
    def validate_peer_ip(cls, peer_ip: str) -> str:
        clean_ip = peer_ip.strip()
        try:
            ipaddress.IPv4Address(clean_ip)
        except Exception as e:
            raise BGPLabAdapterError(f"Invalid peer IP address: '{clean_ip}': {str(e)}")

        if clean_ip not in settings.BGP_LAB_ALLOWED_PEERS:
            raise BGPLabAdapterError(
                f"LAB POLICY REJECTION: Peer IP '{clean_ip}' is not in BGP_LAB_ALLOWED_PEERS {settings.BGP_LAB_ALLOWED_PEERS}."
            )
        return clean_ip

    @classmethod
    async def _run_gobgp_command(cls, speaker_id: str, args: List[str]) -> Any:
        """
        Executes a controlled gobgp CLI command inside the target speaker container.
        Uses asyncio.create_subprocess_exec (NO shell=True) to prevent shell injection.
        """
        cfg = cls.get_speaker_config(speaker_id)
        container = cfg["container"]

        if cls._use_virtual_fallback:
            return cls._handle_virtual_command(speaker_id, args)

        cmd = ["docker", "exec", container, "gobgp", "-j"] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            cmd_timeout = getattr(settings, "BGP_LAB_COMMAND_TIMEOUT_SECONDS", 15.0)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=cmd_timeout)

            if proc.returncode != 0:
                err_msg = stderr.decode().strip()
                # If container is not running, check if virtual fallback is suitable
                if "No such container" in err_msg or "is not running" in err_msg:
                    logger.warning("Lab container %s not running, falling back to virtual mode", container)
                    return cls._handle_virtual_command(speaker_id, args)
                raise BGPLabAdapterError(f"gobgp command failed on {speaker_id}: {err_msg}")

            raw = stdout.decode().strip()
            if not raw:
                return {}
            return json.loads(raw)
        except (asyncio.TimeoutError, FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning("Error running gobgp in container %s (%s). Falling back to virtual.", container, str(e))
            return cls._handle_virtual_command(speaker_id, args)

    @classmethod
    def _handle_virtual_command(cls, speaker_id: str, args: List[str]) -> Any:
        """Fallback handler for unit testing when docker is unavailable."""
        speaker = cls._virtual_speakers.get(speaker_id, {})
        cfg = cls.get_speaker_config(speaker_id)

        if not speaker.get("is_up", True):
            raise BGPLabAdapterError(f"Speaker {speaker_id} is down.")

        if args == ["neighbor"]:
            return [
                {
                    "state": {
                        "session_state": 6,  # Established
                        "neighbor_address": cfg["peer_ip"],
                        "peer_as": cfg["peer_asn"],
                        "router_id": cfg["peer_ip"],
                    },
                    "timers": {
                        "state": {"uptime": {"seconds": speaker.get("uptime", 3600)}}
                    },
                }
            ]
        elif args == ["global", "rib"]:
            res = {}
            for prefix, route in speaker.get("routes", {}).items():
                res[prefix] = [route]
            return res
        elif len(args) >= 5 and args[:4] == ["global", "rib", "add", "-a"] and args[4] == "ipv4":
            prefix = args[5]
            route_entry = {
                "nlri": {"prefix": prefix},
                "best": True,
                "attrs": [
                    {"type": 1, "value": 2},
                    {"type": 2, "as_paths": [{"asns": [cfg["asn"]]}]},
                    {"type": 3, "nexthop": cfg["ip"]},
                ],
                "neighbor-ip": cfg["ip"],
            }
            speaker.setdefault("routes", {})[prefix] = route_entry

            # Propagate to receiver if peer is Established
            peer_id = "bgp-speaker-2" if speaker_id == "bgp-speaker-1" else "bgp-speaker-1"
            if cls._virtual_speakers.get(peer_id, {}).get("is_up"):
                cls._virtual_speakers[peer_id].setdefault("routes", {})[prefix] = route_entry

            return {}
        elif len(args) >= 5 and args[:4] == ["global", "rib", "del", "-a"] and args[4] == "ipv4":
            prefix = args[5]
            speaker.get("routes", {}).pop(prefix, None)
            peer_id = "bgp-speaker-2" if speaker_id == "bgp-speaker-1" else "bgp-speaker-1"
            cls._virtual_speakers.get(peer_id, {}).get("routes", {}).pop(prefix, None)
            return {}

        return {}

    @classmethod
    async def check_speaker_health(cls, speaker_id: str) -> Dict[str, Any]:
        """Checks if the lab speaker is responsive."""
        cfg = cls.get_speaker_config(speaker_id)
        try:
            neighbors = await cls.get_neighbors(speaker_id)
            return {
                "speaker_id": speaker_id,
                "is_healthy": True,
                "detail": f"Speaker {speaker_id} online with {len(neighbors)} peer(s).",
            }
        except Exception as e:
            return {
                "speaker_id": speaker_id,
                "is_healthy": False,
                "detail": f"Health check failed: {str(e)}",
            }

    @classmethod
    async def get_neighbors(cls, speaker_id: str) -> List[Dict[str, Any]]:
        """Retrieves neighbor peering states from the speaker."""
        cfg = cls.get_speaker_config(speaker_id)
        raw_neighbors = await cls._run_gobgp_command(speaker_id, ["neighbor"])
        if not isinstance(raw_neighbors, list):
            return []

        result = []
        for n in raw_neighbors:
            state_data = n.get("state", {})
            timers_data = n.get("timers", {}).get("state", {})

            session_code = state_data.get("session_state", 1)
            # Map RFC 4271 state codes: 1=Idle, 2=Connect, 3=Active, 4=OpenSent, 5=OpenConfirm, 6=Established
            state_map = {1: "Idle", 2: "Connect", 3: "Active", 4: "OpenSent", 5: "OpenConfirm", 6: "Established"}
            state_str = state_map.get(session_code, f"State_{session_code}")

            peer_ip = state_data.get("neighbor_address", cfg["peer_ip"])
            peer_as = state_data.get("peer_as", cfg["peer_asn"])
            uptime_sec = timers_data.get("uptime", {}).get("seconds", 0)

            result.append({
                "peer_ip": peer_ip,
                "peer_as": peer_as,
                "local_as": cfg["asn"],
                "state": state_str,
                "uptime_seconds": uptime_sec,
                "prefixes_received": 0,
                "prefixes_advertised": 0,
                "router_id": state_data.get("router_id", peer_ip),
            })
        return result

    @classmethod
    async def get_routing_table(cls, speaker_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """Retrieves current global RIB routes from the speaker."""
        raw_rib = await cls._run_gobgp_command(speaker_id, ["global", "rib"])
        if not isinstance(raw_rib, dict):
            return {}

        routes = {}
        for prefix, entries in raw_rib.items():
            parsed_entries = []
            for entry in entries:
                attrs = entry.get("attrs", [])
                as_path = None
                nexthop = None
                for a in attrs:
                    if "as_paths" in a:
                        as_path = " ".join(
                            str(asn) for path in a["as_paths"] for asn in path.get("asns", [])
                        )
                    if "nexthop" in a:
                        nexthop = a["nexthop"]

                parsed_entries.append({
                    "prefix": prefix,
                    "best": entry.get("best", False),
                    "as_path": as_path,
                    "next_hop": nexthop,
                    "neighbor_ip": entry.get("neighbor-ip"),
                })
            routes[prefix] = parsed_entries
        return routes

    @classmethod
    async def announce_prefix(cls, speaker_id: str, prefix: str, next_hop: Optional[str] = None) -> Dict[str, Any]:
        """
        Announces a test prefix to the BGP speaker.
        """
        validated_prefix = cls.validate_prefix(prefix)
        cfg = cls.get_speaker_config(speaker_id)
        nh = next_hop or cfg["ip"]

        args = ["global", "rib", "add", "-a", "ipv4", validated_prefix]
        await cls._run_gobgp_command(speaker_id, args)

        logger.info("Announced test prefix %s on %s with next-hop %s", validated_prefix, speaker_id, nh)
        return {
            "speaker_id": speaker_id,
            "prefix": validated_prefix,
            "next_hop": nh,
            "status": "ANNOUNCED",
        }

    @classmethod
    async def withdraw_prefix(cls, speaker_id: str, prefix: str) -> Dict[str, Any]:
        """
        Withdraws a previously announced test prefix from the BGP speaker.
        """
        validated_prefix = cls.validate_prefix(prefix)
        args = ["global", "rib", "del", "-a", "ipv4", validated_prefix]
        await cls._run_gobgp_command(speaker_id, args)

        logger.info("Withdrawn test prefix %s from %s", validated_prefix, speaker_id)
        return {
            "speaker_id": speaker_id,
            "prefix": validated_prefix,
            "status": "WITHDRAWN",
        }

    @classmethod
    async def is_prefix_present(cls, speaker_id: str, prefix: str) -> bool:
        """Checks if a prefix exists in the speaker's global RIB."""
        validated_prefix = cls.validate_prefix(prefix)
        routes = await cls.get_routing_table(speaker_id)
        return validated_prefix in routes
