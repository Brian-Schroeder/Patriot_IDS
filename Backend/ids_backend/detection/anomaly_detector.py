from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
import statistics
import logging

from models.alert import Alert, AlertLevel
from detection.packet_analyzer import PacketInfo
from detection.anomaly_classifier import AnomalyEvent

logger = logging.getLogger(__name__)

@dataclass
class TrafficBaseline:
    """Stores baseline metrics for anomaly comparison"""
    avg_packets_per_second: float = 0.0
    avg_bytes_per_second: float = 0.0
    avg_connections_per_ip: float = 0.0
    std_packets_per_second: float = 0.0
    std_bytes_per_second: float = 0.0
    common_ports: Dict[int, int] = field(default_factory=dict)
    common_protocols: Dict[str, int] = field(default_factory=dict)
    sample_count: int = 0

class AnomalyDetector:
    """Statistical anomaly-based intrusion detection"""
    
    def __init__(self, time_window_minutes: int = 1):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.baseline = TrafficBaseline()
        
        # Traffic tracking
        self.packet_timestamps: List[datetime] = []
        self.byte_counts: List[int] = []
        self.connection_tracker: Dict[str, List[datetime]] = defaultdict(list)
        self.port_scan_tracker: Dict[str, set] = defaultdict(set)
        self.failed_auth_tracker: Dict[str, List[datetime]] = defaultdict(list)
        self.syn_tracker: Dict[str, List[datetime]] = defaultdict(list)
        
        # Thresholds (configurable)
        self.thresholds = {
            'packets_per_second': 1000,
            'bytes_per_second': 10_000_000,  # 10 MB/s
            'connections_per_ip': 100,
            'port_scan_threshold': 20,
            'failed_auth_threshold': 5,
            'syn_flood_threshold': 500,
            'std_deviation_multiplier': 3.0  # Alert if > 3 std deviations
        }
    
    def update_thresholds(self, new_thresholds: Dict[str, float]) -> None:
        """Update detection thresholds"""
        self.thresholds.update(new_thresholds)
        logger.info(f"Updated thresholds: {new_thresholds}")
    
    def _cleanup_old_data(self, current_time: datetime) -> None:
        """Remove data outside the time window"""
        cutoff = current_time - self.time_window
        
        # Clean packet timestamps
        self.packet_timestamps = [
            ts for ts in self.packet_timestamps if ts > cutoff
        ]
        
        # Clean connection tracker
        for ip in list(self.connection_tracker.keys()):
            self.connection_tracker[ip] = [
                ts for ts in self.connection_tracker[ip] if ts > cutoff
            ]
            if not self.connection_tracker[ip]:
                del self.connection_tracker[ip]
        
        # Clean port scan tracker (reset periodically)
        # Keep for longer window to detect slow scans
        scan_cutoff = current_time - timedelta(minutes=5)
        for ip in list(self.port_scan_tracker.keys()):
            # Simple approach: clear if no recent activity
            if ip in self.connection_tracker and not self.connection_tracker[ip]:
                del self.port_scan_tracker[ip]
        
        # Clean failed auth tracker
        for ip in list(self.failed_auth_tracker.keys()):
            self.failed_auth_tracker[ip] = [
                ts for ts in self.failed_auth_tracker[ip] if ts > cutoff
            ]
            if not self.failed_auth_tracker[ip]:
                del self.failed_auth_tracker[ip]
        
        # Clean SYN tracker
        for ip in list(self.syn_tracker.keys()):
            self.syn_tracker[ip] = [
                ts for ts in self.syn_tracker[ip] if ts > cutoff
            ]
            if not self.syn_tracker[ip]:
                del self.syn_tracker[ip]
    
    def _update_baseline(self, packets_per_sec: float, bytes_per_sec: float) -> None:
        """Update rolling baseline statistics"""
        n = self.baseline.sample_count
        
        if n == 0:
            self.baseline.avg_packets_per_second = packets_per_sec
            self.baseline.avg_bytes_per_second = bytes_per_sec
            self.baseline.std_packets_per_second = 0
            self.baseline.std_bytes_per_second = 0
        else:
            # Welford's online algorithm for running mean and variance
            old_avg_pps = self.baseline.avg_packets_per_second
            old_avg_bps = self.baseline.avg_bytes_per_second
            
            self.baseline.avg_packets_per_second = old_avg_pps + (packets_per_sec - old_avg_pps) / (n + 1)
            self.baseline.avg_bytes_per_second = old_avg_bps + (bytes_per_sec - old_avg_bps) / (n + 1)
            
            # Update standard deviation (simplified)
            if n > 1:
                self.baseline.std_packets_per_second = abs(packets_per_sec - self.baseline.avg_packets_per_second) * 0.1 + self.baseline.std_packets_per_second * 0.9
                self.baseline.std_bytes_per_second = abs(bytes_per_sec - self.baseline.avg_bytes_per_second) * 0.1 + self.baseline.std_bytes_per_second * 0.9
        
        self.baseline.sample_count = n + 1
    
    def record_packet(self, packet: PacketInfo) -> None:
        """Record packet for statistical analysis"""
        now = packet.timestamp
        self._cleanup_old_data(now)
        
        self.packet_timestamps.append(now)
        self.byte_counts.append(packet.size)
        self.connection_tracker[packet.source_ip].append(now)
        self.port_scan_tracker[packet.source_ip].add(packet.destination_port)
        
        # Track SYN packets for SYN flood detection
        if packet.flags.get('syn') and not packet.flags.get('ack'):
            self.syn_tracker[packet.source_ip].append(now)
        
        # Update baseline
        if len(self.packet_timestamps) > 0:
            window_seconds = self.time_window.total_seconds()
            pps = len(self.packet_timestamps) / window_seconds
            bps = sum(self.byte_counts[-len(self.packet_timestamps):]) / window_seconds
            self._update_baseline(pps, bps)
        
        # Track port/protocol distribution
        self.baseline.common_ports[packet.destination_port] = \
            self.baseline.common_ports.get(packet.destination_port, 0) + 1
        self.baseline.common_protocols[packet.protocol] = \
            self.baseline.common_protocols.get(packet.protocol, 0) + 1
    
    def record_failed_auth(self, source_ip: str) -> None:
        """Record a failed authentication attempt"""
        self.failed_auth_tracker[source_ip].append(datetime.utcnow())
    
    def detect_anomalies(self, packet: PacketInfo) -> List[AnomalyEvent]:
        """Detect anomalies and return raw anomaly events for classification"""
        anomalies: List[AnomalyEvent] = []
        now = packet.timestamp
        source_ip = packet.source_ip

        # Record the packet first
        self.record_packet(packet)

        # 1. Check for traffic volume anomalies
        vol = self._check_volume_anomaly(now)
        if vol:
            anomalies.append(vol)

        # 2. Check for connection flood from single IP
        conn = self._check_connection_flood(source_ip)
        if conn:
            anomalies.append(conn)

        # 3. Check for port scanning
        scan = self._check_port_scan(source_ip)
        if scan:
            anomalies.append(scan)

        # 4. Check for SYN flood
        syn = self._check_syn_flood(source_ip)
        if syn:
            anomalies.append(syn)

        # 5. Check for brute force (failed auth)
        brute = self._check_brute_force(source_ip)
        if brute:
            anomalies.append(brute)

        return anomalies

    def analyze(self, packet: PacketInfo) -> List[Alert]:
        """Legacy: Analyze and return alerts. Use detect_anomalies + classifier for pipeline."""
        from detection.anomaly_classifier import AnomalyClassifier
        anomalies = self.detect_anomalies(packet)
        classifier = AnomalyClassifier()
        return classifier.classify_batch(anomalies, packet)
    
    def _check_volume_anomaly(self, current_time: datetime) -> Optional[AnomalyEvent]:
        """Detect abnormal traffic volume"""
        if len(self.packet_timestamps) < 10:
            return None

        window_seconds = self.time_window.total_seconds()
        current_pps = len(self.packet_timestamps) / window_seconds

        # Check against absolute threshold
        if current_pps > self.thresholds['packets_per_second']:
            return AnomalyEvent(
                anomaly_type="ANOMALY:HIGH_TRAFFIC_VOLUME",
                source_ip="multiple",
                timestamp=current_time,
                description=f"Abnormally high traffic: {current_pps:.2f} packets/sec (threshold: {self.thresholds['packets_per_second']})",
                suggested_severity="HIGH",
                features={
                    'packets_per_second': current_pps,
                    'threshold': self.thresholds['packets_per_second'],
                    'baseline_avg': self.baseline.avg_packets_per_second
                }
            )

        # Check against baseline (statistical anomaly)
        if self.baseline.sample_count > 100 and self.baseline.std_packets_per_second > 0:
            z_score = (current_pps - self.baseline.avg_packets_per_second) / self.baseline.std_packets_per_second
            if z_score > self.thresholds['std_deviation_multiplier']:
                return AnomalyEvent(
                    anomaly_type="ANOMALY:TRAFFIC_SPIKE",
                    source_ip="multiple",
                    timestamp=current_time,
                    description=f"Traffic spike detected: {z_score:.2f} standard deviations above baseline",
                    suggested_severity="MEDIUM",
                    features={
                        'z_score': z_score,
                        'current_pps': current_pps,
                        'baseline_avg': self.baseline.avg_packets_per_second,
                        'baseline_std': self.baseline.std_packets_per_second
                    }
                )
        return None
    
    def _check_connection_flood(self, source_ip: str) -> Optional[AnomalyEvent]:
        """Detect connection flood from single IP"""
        connection_count = len(self.connection_tracker.get(source_ip, []))
        if connection_count > self.thresholds['connections_per_ip']:
            return AnomalyEvent(
                anomaly_type="ANOMALY:CONNECTION_FLOOD",
                source_ip=source_ip,
                timestamp=datetime.utcnow(),
                description=f"Excessive connections from single IP: {connection_count} in {self.time_window.total_seconds()}s",
                suggested_severity="HIGH",
                features={
                    'connection_count': connection_count,
                    'threshold': self.thresholds['connections_per_ip'],
                    'time_window_seconds': self.time_window.total_seconds()
                }
            )
        return None
    
    def _check_port_scan(self, source_ip: str) -> Optional[AnomalyEvent]:
        """Detect port scanning activity"""
        ports_scanned = len(self.port_scan_tracker.get(source_ip, set()))
        if ports_scanned > self.thresholds['port_scan_threshold']:
            return AnomalyEvent(
                anomaly_type="ANOMALY:PORT_SCAN",
                source_ip=source_ip,
                timestamp=datetime.utcnow(),
                description=f"Port scan detected: {ports_scanned} unique ports accessed",
                suggested_severity="MEDIUM",
                features={
                    'ports_scanned': ports_scanned,
                    'ports': list(self.port_scan_tracker[source_ip])[:50],
                    'threshold': self.thresholds['port_scan_threshold']
                }
            )
        return None
    
    def _check_syn_flood(self, source_ip: str) -> Optional[AnomalyEvent]:
        """Detect SYN flood attack"""
        syn_count = len(self.syn_tracker.get(source_ip, []))
        if syn_count > self.thresholds['syn_flood_threshold']:
            return AnomalyEvent(
                anomaly_type="ANOMALY:SYN_FLOOD",
                source_ip=source_ip,
                timestamp=datetime.utcnow(),
                description=f"Potential SYN flood: {syn_count} SYN packets in {self.time_window.total_seconds()}s",
                suggested_severity="CRITICAL",
                features={
                    'syn_count': syn_count,
                    'threshold': self.thresholds['syn_flood_threshold']
                }
            )
        return None
    
    def _check_brute_force(self, source_ip: str) -> Optional[AnomalyEvent]:
        """Detect brute force authentication attempts"""
        failed_count = len(self.failed_auth_tracker.get(source_ip, []))
        if failed_count > self.thresholds['failed_auth_threshold']:
            return AnomalyEvent(
                anomaly_type="ANOMALY:BRUTE_FORCE",
                source_ip=source_ip,
                timestamp=datetime.utcnow(),
                description=f"Brute force attempt: {failed_count} failed authentications",
                suggested_severity="HIGH",
                features={
                    'failed_attempts': failed_count,
                    'threshold': self.thresholds['failed_auth_threshold']
                }
            )
        return None
    
    def get_statistics(self) -> Dict:
        """Get current detection statistics"""
        return {
            'baseline': {
                'avg_packets_per_second': self.baseline.avg_packets_per_second,
                'avg_bytes_per_second': self.baseline.avg_bytes_per_second,
                'std_packets_per_second': self.baseline.std_packets_per_second,
                'sample_count': self.baseline.sample_count,
                'top_ports': sorted(
                    self.baseline.common_ports.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10],
                'protocols': self.baseline.common_protocols
            },
            'current_window': {
                'active_connections': len(self.connection_tracker),
                'tracked_ips': list(self.connection_tracker.keys())[:20],
                'potential_scanners': [
                    ip for ip, ports in self.port_scan_tracker.items()
                    if len(ports) > 10
                ]
            },
            'thresholds': self.thresholds
        }