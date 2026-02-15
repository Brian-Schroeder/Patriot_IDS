from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime

@dataclass
class PacketInfo:
    """Represents analyzed packet information"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    payload: bytes
    size: int
    flags: Dict[str, bool]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'size': self.size,
            'flags': self.flags
        }

class PacketAnalyzer:
    """Analyzes network packets for suspicious characteristics"""
    
    # Common suspicious ports
    SUSPICIOUS_PORTS = {
        22: 'SSH',
        23: 'Telnet',
        3389: 'RDP',
        445: 'SMB',
        1433: 'MSSQL',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB'
    }
    
    # Known malicious signatures (simplified)
    MALICIOUS_SIGNATURES = [
        b'/etc/passwd',
        b'/etc/shadow',
        b'cmd.exe',
        b'powershell',
        b'<script>',
        b'UNION SELECT',
        b'OR 1=1',
        b'../../../',
        b'%00',
        b'\x90\x90\x90\x90',  # NOP sled
    ]
    
    def __init__(self):
        self.packet_count = 0
        self.suspicious_count = 0
    
    def analyze(self, packet_data: Dict[str, Any]) -> PacketInfo:
        """Parse raw packet data into PacketInfo structure"""
        self.packet_count += 1

        ts = packet_data.get("timestamp") or packet_data.get("_ts")
        if not isinstance(ts, datetime):
            ts = datetime.utcnow()

        return PacketInfo(
            timestamp=ts,
            source_ip=packet_data.get('src_ip', '0.0.0.0'),
            destination_ip=packet_data.get('dst_ip', '0.0.0.0'),
            source_port=packet_data.get('src_port', 0),
            destination_port=packet_data.get('dst_port', 0),
            protocol=packet_data.get('protocol', 'unknown'),
            payload=packet_data.get('payload', b''),
            size=packet_data.get('size', 0),
            flags=packet_data.get('flags', {})
        )
    
    def check_suspicious_port(self, port: int) -> Optional[str]:
        """Check if port is commonly targeted"""
        return self.SUSPICIOUS_PORTS.get(port)
    
    def check_malicious_payload(self, payload: bytes) -> list:
        """Scan payload for known malicious signatures"""
        found = []
        for signature in self.MALICIOUS_SIGNATURES:
            if signature in payload:
                found.append(signature.decode('utf-8', errors='replace'))
        if found:
            self.suspicious_count += 1
        return found
    
    def check_packet_anomalies(self, packet: PacketInfo) -> list:
        """Check for packet-level anomalies"""
        anomalies = []
        
        # Check for suspicious TCP flags
        if packet.flags:
            # SYN+FIN is invalid
            if packet.flags.get('syn') and packet.flags.get('fin'):
                anomalies.append('Invalid TCP flags: SYN+FIN')
            
            # NULL scan (no flags)
            if not any(packet.flags.values()):
                anomalies.append('NULL scan detected: No TCP flags')
            
            # XMAS scan (all flags)
            if all(packet.flags.get(f, False) for f in ['fin', 'psh', 'urg']):
                anomalies.append('XMAS scan detected: FIN+PSH+URG')
        
        # Unusually large packet
        if packet.size > 65535:
            anomalies.append(f'Oversized packet: {packet.size} bytes')
        
        return anomalies
    
    def get_stats(self) -> Dict[str, int]:
        return {
            'total_packets': self.packet_count,
            'suspicious_packets': self.suspicious_count
        }