import logging
import threading
import queue
from typing import Optional, Callable, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass
import time

from detection.packet_analyzer import PacketAnalyzer, PacketInfo
from detection.rule_engine import RuleEngine
from detection.anomaly_detector import AnomalyDetector
from detection.anomaly_classifier import AnomalyClassifier, AnomalyEvent
from detection.ml_anomaly_detector import MLAnomalyDetector
from services.alert_service import AlertService
from models.alert import Alert, AlertLevel

logger = logging.getLogger(__name__)

@dataclass
class MonitorStats:
    """Traffic monitoring statistics"""
    start_time: datetime
    packets_processed: int = 0
    alerts_generated: int = 0
    errors: int = 0
    is_running: bool = False

class TrafficMonitor:
    """
    Main traffic monitoring service.
    Coordinates packet capture, analysis, and alert generation.
    """
    
    def __init__(
        self,
        alert_service: AlertService,
        interface: str = 'eth0',
        use_anomaly_detection: bool = True,
        use_signature_detection: bool = True,
        use_ml_anomaly_detection: bool = True,
    ):
        self.alert_service = alert_service
        self.interface = interface

        # Detection components
        self.packet_analyzer = PacketAnalyzer()
        self.rule_engine = RuleEngine() if use_signature_detection else None
        self.anomaly_detector = AnomalyDetector() if use_anomaly_detection else None
        self.anomaly_classifier = AnomalyClassifier() if use_anomaly_detection else None
        self.ml_anomaly_detector = MLAnomalyDetector() if use_ml_anomaly_detection else None
        
        # Processing queue
        self.packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        
        # Threading
        self._capture_thread: Optional[threading.Thread] = None
        self._processing_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Statistics
        self.stats = MonitorStats(start_time=datetime.utcnow())
        
        # Packet capture callback (can be overridden for testing)
        self._capture_callback: Optional[Callable] = None
    
    def _capture_packets_scapy(self) -> None:
        """
        Capture packets using Scapy.
        Requires: pip install scapy
        Note: Requires root/admin privileges
        """
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
            
            def packet_handler(packet):
                if self._stop_event.is_set():
                    return
                
                try:
                    if IP in packet:
                        packet_data = {
                            'src_ip': packet[IP].src,
                            'dst_ip': packet[IP].dst,
                            'protocol': 'unknown',
                            'src_port': 0,
                            'dst_port': 0,
                            'payload': b'',
                            'size': len(packet),
                            'flags': {}
                        }
                        
                        if TCP in packet:
                            packet_data['protocol'] = 'tcp'
                            packet_data['src_port'] = packet[TCP].sport
                            packet_data['dst_port'] = packet[TCP].dport
                            packet_data['flags'] = {
                                'syn': bool(packet[TCP].flags & 0x02),
                                'ack': bool(packet[TCP].flags & 0x10),
                                'fin': bool(packet[TCP].flags & 0x01),
                                'rst': bool(packet[TCP].flags & 0x04),
                                'psh': bool(packet[TCP].flags & 0x08),
                                'urg': bool(packet[TCP].flags & 0x20)
                            }
                        elif UDP in packet:
                            packet_data['protocol'] = 'udp'
                            packet_data['src_port'] = packet[UDP].sport
                            packet_data['dst_port'] = packet[UDP].dport
                        elif ICMP in packet:
                            packet_data['protocol'] = 'icmp'
                        
                        if Raw in packet:
                            packet_data['payload'] = bytes(packet[Raw].load)
                        
                        # Add to queue (non-blocking)
                        try:
                            self.packet_queue.put_nowait(packet_data)
                        except queue.Full:
                            self.stats.errors += 1
                            logger.warning("Packet queue full, dropping packet")
                
                except Exception as e:
                    self.stats.errors += 1
                    logger.error(f"Error processing captured packet: {e}")
            
            logger.info(f"Starting packet capture on interface: {self.interface}")
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: self._stop_event.is_set()
            )
        
        except ImportError:
            logger.error("Scapy not installed. Run: pip install scapy")
            raise
        except PermissionError:
            logger.error("Packet capture requires root/admin privileges")
            raise
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            raise
    
    def _capture_packets_socket(self) -> None:
        """
        Capture packets using raw sockets (Linux only).
        Fallback if Scapy is not available.
        """
        import socket
        import struct
        
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.interface, 0))
            sock.settimeout(1.0)
            
            logger.info(f"Starting raw socket capture on interface: {self.interface}")
            
            while not self._stop_event.is_set():
                try:
                    raw_data, addr = sock.recvfrom(65535)
                    
                    # Parse Ethernet header (14 bytes)
                    eth_header = raw_data[:14]
                    eth = struct.unpack('!6s6sH', eth_header)
                    eth_protocol = socket.ntohs(eth[2])
                    
                    # Only process IP packets (0x0800)
                    if eth_protocol != 0x0800:
                        continue
                    
                    # Parse IP header
                    ip_header = raw_data[14:34]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    
                    version_ihl = iph[0]
                    ihl = (version_ihl & 0xF) * 4
                    protocol = iph[6]
                    src_ip = socket.inet_ntoa(iph[8])
                    dst_ip = socket.inet_ntoa(iph[9])
                    
                    packet_data = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': 'unknown',
                        'src_port': 0,
                        'dst_port': 0,
                        'payload': b'',
                        'size': len(raw_data),
                        'flags': {}
                    }
                    
                    # TCP (protocol 6)
                    if protocol == 6:
                        tcp_header = raw_data[14 + ihl:14 + ihl + 20]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        packet_data['protocol'] = 'tcp'
                        packet_data['src_port'] = tcph[0]
                        packet_data['dst_port'] = tcph[1]
                        flags = tcph[5]
                        packet_data['flags'] = {
                            'fin': bool(flags & 0x01),
                            'syn': bool(flags & 0x02),
                            'rst': bool(flags & 0x04),
                            'psh': bool(flags & 0x08),
                            'ack': bool(flags & 0x10),
                            'urg': bool(flags & 0x20)
                        }
                        tcp_header_length = ((tcph[4] >> 4) & 0xF) * 4
                        payload_offset = 14 + ihl + tcp_header_length
                        packet_data['payload'] = raw_data[payload_offset:]
                    
                    # UDP (protocol 17)
                    elif protocol == 17:
                        udp_header = raw_data[14 + ihl:14 + ihl + 8]
                        udph = struct.unpack('!HHHH', udp_header)
                        packet_data['protocol'] = 'udp'
                        packet_data['src_port'] = udph[0]
                        packet_data['dst_port'] = udph[1]
                        packet_data['payload'] = raw_data[14 + ihl + 8:]
                    
                    # ICMP (protocol 1)
                    elif protocol == 1:
                        packet_data['protocol'] = 'icmp'
                    
                    try:
                        self.packet_queue.put_nowait(packet_data)
                    except queue.Full:
                        self.stats.errors += 1
                
                except socket.timeout:
                    continue
                except Exception as e:
                    self.stats.errors += 1
                    logger.error(f"Error in raw socket capture: {e}")
            
            sock.close()
        
        except PermissionError:
            logger.error("Raw socket capture requires root privileges")
            raise
        except Exception as e:
            logger.error(f"Raw socket error: {e}")
            raise
    
    def _process_packets(self) -> None:
        """Process packets from the queue"""
        logger.info("Starting packet processing thread")
        
        while not self._stop_event.is_set():
            try:
                # Get packet from queue with timeout
                try:
                    packet_data = self.packet_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Analyze packet
                packet_info = self.packet_analyzer.analyze(packet_data)
                self.stats.packets_processed += 1
                
                alerts: List[Alert] = []

                # Collect anomaly events to feed into classifier
                anomaly_events: List[AnomalyEvent] = []

                # Packet-level anomalies (feed into classifier)
                packet_anomalies = self.packet_analyzer.check_packet_anomalies(packet_info)
                for anomaly_desc in packet_anomalies:
                    anomaly_events.append(AnomalyEvent(
                        anomaly_type="PACKET_ANOMALY",
                        source_ip=packet_info.source_ip,
                        timestamp=packet_info.timestamp,
                        description=anomaly_desc,
                        suggested_severity="MEDIUM",
                        destination_ip=packet_info.destination_ip,
                        destination_port=packet_info.destination_port,
                        features={'packet_size': packet_info.size}
                    ))

                # Malicious payload signatures (feed into classifier)
                malicious_patterns = self.packet_analyzer.check_malicious_payload(packet_info.payload)
                for pattern in malicious_patterns:
                    anomaly_events.append(AnomalyEvent(
                        anomaly_type="MALICIOUS_PAYLOAD",
                        source_ip=packet_info.source_ip,
                        timestamp=packet_info.timestamp,
                        description=f"Malicious pattern detected in payload: {pattern}",
                        suggested_severity="HIGH",
                        destination_ip=packet_info.destination_ip,
                        destination_port=packet_info.destination_port,
                        features={'pattern': pattern}
                    ))

                # Statistical anomaly detection (feed into classifier)
                if self.anomaly_detector:
                    anomaly_events.extend(self.anomaly_detector.detect_anomalies(packet_info))

                # ML anomaly detection (Isolation Forest)
                if self.ml_anomaly_detector:
                    self.ml_anomaly_detector.add_packet(packet_info)
                    ml_event = self.ml_anomaly_detector.extract_and_predict(packet_info)
                    if ml_event:
                        anomaly_events.append(ml_event)

                # Classify anomalies into alerts
                if self.anomaly_classifier and anomaly_events:
                    alerts.extend(self.anomaly_classifier.classify_batch(anomaly_events, packet_info))

                # Run signature-based detection (rule engine - direct to alerts)
                if self.rule_engine:
                    rule_alerts = self.rule_engine.evaluate(packet_info)
                    alerts.extend(rule_alerts)
                
                # Submit alerts
                for alert in alerts:
                    if self.alert_service.add_alert(alert):
                        self.stats.alerts_generated += 1
                
                self.packet_queue.task_done()
            
            except Exception as e:
                self.stats.errors += 1
                logger.error(f"Error processing packet: {e}")
    
    def start(self, use_scapy: bool = True) -> None:
        """Start the traffic monitor"""
        if self.stats.is_running:
            logger.warning("Traffic monitor is already running")
            return
        
        self._stop_event.clear()
        self.stats = MonitorStats(start_time=datetime.utcnow(), is_running=True)
        
        # Start packet processing thread
        self._processing_thread = threading.Thread(
            target=self._process_packets,
            name="PacketProcessor",
            daemon=True
        )
        self._processing_thread.start()
        
        # Start packet capture thread
        capture_func = self._capture_packets_scapy if use_scapy else self._capture_packets_socket
        self._capture_thread = threading.Thread(
            target=capture_func,
            name="PacketCapture",
            daemon=True
        )
        self._capture_thread.start()
        
        logger.info("Traffic monitor started")
    
    def stop(self) -> None:
        """Stop the traffic monitor"""
        logger.info("Stopping traffic monitor...")
        self._stop_event.set()
        
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5.0)
        
        if self._processing_thread and self._processing_thread.is_alive():
            self._processing_thread.join(timeout=5.0)
        
        self.stats.is_running = False
        logger.info("Traffic monitor stopped")
    
    def inject_packet(self, packet_data: Dict[str, Any]) -> None:
        """
        Inject a packet for analysis (useful for testing or log replay).
        """
        try:
            self.packet_queue.put_nowait(packet_data)
        except queue.Full:
            logger.warning("Cannot inject packet: queue full")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current monitor status"""
        uptime = (datetime.utcnow() - self.stats.start_time).total_seconds()
        pps = self.stats.packets_processed / uptime if uptime > 0 else 0
        
        return {
            'is_running': self.stats.is_running,
            'interface': self.interface,
            'start_time': self.stats.start_time.isoformat(),
            'uptime_seconds': uptime,
            'packets_processed': self.stats.packets_processed,
            'packets_per_second': round(pps, 2),
            'alerts_generated': self.stats.alerts_generated,
            'errors': self.stats.errors,
            'queue_size': self.packet_queue.qsize(),
            'detection_modules': {
                'signature_detection': self.rule_engine is not None,
                'anomaly_detection': self.anomaly_detector is not None,
                'ml_anomaly_detection': self.ml_anomaly_detector is not None,
                'anomaly_classifier': self.anomaly_classifier is not None
            }
        }
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detailed detection statistics"""
        stats = {
            'packet_analyzer': self.packet_analyzer.get_stats()
        }
        
        if self.anomaly_detector:
            stats['anomaly_detector'] = self.anomaly_detector.get_statistics()

        if self.anomaly_classifier:
            stats['anomaly_classifier'] = self.anomaly_classifier.get_stats()

        if self.ml_anomaly_detector:
            stats['ml_anomaly_detector'] = self.ml_anomaly_detector.get_stats()

        if self.rule_engine:
            stats['rules'] = {
                'total_rules': len(self.rule_engine.rules),
                'enabled_rules': sum(1 for r in self.rule_engine.rules.values() if r.enabled)
            }
        
        return stats