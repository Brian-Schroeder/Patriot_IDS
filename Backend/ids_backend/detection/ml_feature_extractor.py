"""
Feature extraction for ML anomaly detection.
Extracts numerical features from a rolling window of packets.
Features inspired by NSL-KDD / flow-based IDS datasets.
"""
from collections import defaultdict
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import math

from detection.packet_analyzer import PacketInfo

# Protocol encoding for ML
PROTOCOL_MAP = {"tcp": 0, "udp": 1, "icmp": 2}
DEFAULT_PROTOCOL = 3


@dataclass
class FeatureVector:
    """Extracted features from a packet window"""
    values: List[float]
    source_ip: str  # primary IP this vector describes
    packet_count: int
    feature_names: List[str] = None

    def to_array(self):
        import numpy as np
        return np.array(self.values, dtype=np.float64).reshape(1, -1)


# Standard feature names for consistency
FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "unique_dest_ports",
    "unique_dest_ips",
    "unique_src_ips",
    "max_packets_per_src_ip",
    "max_ports_per_src_ip",
    "syn_ratio",
    "avg_packet_size",
    "protocol_tcp_ratio",
]


class PacketWindow:
    """
    Rolling window of packets for feature extraction.
    Accumulates packets and emits feature vectors for ML anomaly detection.
    """

    def __init__(self, max_size: int = 500):
        self.max_size = max_size
        self._packets: List[PacketInfo] = []
        self._extraction_interval = 30
        self._packets_since_extraction = 0

    def add(self, packet: PacketInfo) -> None:
        """Add a packet to the window"""
        self._packets.append(packet)
        if len(self._packets) > self.max_size:
            self._packets = self._packets[-self.max_size:]
        self._packets_since_extraction += 1

    def should_extract(self) -> bool:
        """Whether to extract features (every N packets)"""
        return self._packets_since_extraction >= self._extraction_interval

    def extract_features(self, for_source_ip: Optional[str] = None) -> Optional[FeatureVector]:
        """
        Extract a feature vector from the current window.
        If for_source_ip is set, features describe that IP's behavior.
        Otherwise, features are global window statistics.
        """
        if len(self._packets) < 10:
            return None

        self._packets_since_extraction = 0

        # Aggregate by source IP
        by_src: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "packets": 0, "bytes": 0, "ports": set(), "dests": set(),
            "syn_count": 0, "tcp_count": 0
        })

        for p in self._packets:
            s = by_src[p.source_ip]
            s["packets"] += 1
            s["bytes"] += p.size
            s["ports"].add(p.destination_port)
            s["dests"].add(p.destination_ip)
            if p.protocol.lower() == "tcp":
                s["tcp_count"] += 1
                if p.flags.get("syn") and not p.flags.get("ack"):
                    s["syn_count"] += 1

        if for_source_ip and for_source_ip in by_src:
            s = by_src[for_source_ip]
            packet_count = s["packets"]
            byte_count = s["bytes"]
            unique_ports = len(s["ports"])
            unique_dests = len(s["dests"])
            syn_ratio = s["syn_count"] / max(1, s["tcp_count"])
            protocol_tcp_ratio = s["tcp_count"] / max(1, packet_count)
        else:
            # Global stats
            packet_count = len(self._packets)
            byte_count = sum(p.size for p in self._packets)
            all_ports = set()
            all_dests = set()
            total_syn = 0
            total_tcp = 0
            for s in by_src.values():
                all_ports.update(s["ports"])
                all_dests.update(s["dests"])
                total_syn += s["syn_count"]
                total_tcp += s["tcp_count"]
            unique_ports = len(all_ports)
            unique_dests = len(all_dests)
            syn_ratio = total_syn / max(1, total_tcp)
            protocol_tcp_ratio = total_tcp / max(1, packet_count)
            for_source_ip = "multiple"

        max_packets_per_ip = max(s["packets"] for s in by_src.values()) if by_src else 0
        max_ports_per_ip = max(len(s["ports"]) for s in by_src.values()) if by_src else 0
        unique_src_ips = len(by_src)
        avg_packet_size = byte_count / max(1, packet_count)

        # Log-scale for large values to avoid skew
        values = [
            min(packet_count, 1000),
            min(math.log1p(byte_count), 15),
            min(unique_ports, 1000),
            min(unique_dests, 500),
            min(unique_src_ips, 200),
            min(max_packets_per_ip, 500),
            min(max_ports_per_ip, 500),
            min(syn_ratio, 1.0),
            min(avg_packet_size, 1500),
            min(protocol_tcp_ratio, 1.0),
        ]

        return FeatureVector(
            values=values,
            source_ip=for_source_ip,
            packet_count=packet_count,
            feature_names=FEATURE_NAMES,
        )

    def get_baseline_samples(self, n: int = 100) -> List[FeatureVector]:
        """
        Get feature vectors for initial model fitting.
        Call this after accumulating enough 'normal' traffic.
        """
        samples = []
        orig_interval = self._extraction_interval
        self._extraction_interval = 10  # Extract more frequently
        self._packets_since_extraction = 0

        # Extract from current window multiple times with different "views"
        # Simulate by extracting now
        for _ in range(min(n, max(1, len(self._packets) // 20))):
            fv = self.extract_features()
            if fv:
                samples.append(fv)

        self._extraction_interval = orig_interval
        return samples
