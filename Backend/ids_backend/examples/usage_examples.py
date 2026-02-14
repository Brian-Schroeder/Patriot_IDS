#!/usr/bin/env python3
"""
Usage examples for the IDS Backend API.
"""

import requests
import json
import time

BASE_URL = 'http://localhost:5000/api/v1'


def check_health():
    """Check system health"""
    response = requests.get(f'{BASE_URL}/health')
    print("Health Check:")
    print(json.dumps(response.json(), indent=2))
    print()


def get_system_status():
    """Get overall system status"""
    response = requests.get(f'{BASE_URL}/status')
    print("System Status:")
    print(json.dumps(response.json(), indent=2))
    print()


def start_monitor():
    """Start the traffic monitor"""
    response = requests.post(f'{BASE_URL}/monitor/start')
    print("Start Monitor:")
    print(json.dumps(response.json(), indent=2))
    print()


def stop_monitor():
    """Stop the traffic monitor"""
    response = requests.post(f'{BASE_URL}/monitor/stop')
    print("Stop Monitor:")
    print(json.dumps(response.json(), indent=2))
    print()


def inject_test_packet():
    """Inject a test packet for analysis"""
    packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 'tcp',
        'payload': 'GET /index.html HTTP/1.1',
        'size': 100
    }
    
    response = requests.post(
        f'{BASE_URL}/monitor/inject',
        json=packet
    )
    print("Inject Packet:")
    print(json.dumps(response.json(), indent=2))
    print()


def inject_malicious_packet():
    """Inject a malicious packet to test detection"""
    packet = {
        'src_ip': '10.0.0.50',
        'dst_ip': '192.168.1.1',
        'src_port': 45678,
        'dst_port': 80,
        'protocol': 'tcp',
        'payload': "GET /admin?id=1' UNION SELECT * FROM users-- HTTP/1.1",
        'size': 200
    }
    
    response = requests.post(
        f'{BASE_URL}/monitor/inject',
        json=packet
    )
    print("Inject Malicious Packet (SQL Injection):")
    print(json.dumps(response.json(), indent=2))
    print()


def inject_xss_packet():
    """Inject an XSS attack packet"""
    packet = {
        'src_ip': '10.0.0.51',
        'dst_ip': '192.168.1.1',
        'src_port': 45679,
        'dst_port': 80,
        'protocol': 'tcp',
        'payload': "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
        'size': 150
    }
    
    response = requests.post(
        f'{BASE_URL}/monitor/inject',
        json=packet
    )
    print("Inject XSS Packet:")
    print(json.dumps(response.json(), indent=2))
    print()


def simulate_port_scan():
    """Simulate a port scan attack"""
    print("Simulating Port Scan from 10.0.0.100...")
    
    for port in range(20, 45):
        packet = {
            'src_ip': '10.0.0.100',
            'dst_ip': '192.168.1.1',
            'src_port': 54321,
            'dst_port': port,
            'protocol': 'tcp',
            'payload': '',
            'size': 64,
            'flags': {'syn': True, 'ack': False}
        }
        requests.post(f'{BASE_URL}/monitor/inject', json=packet)
    
    print(f"Injected 25 packets to different ports")
    print()


def simulate_brute_force():
    """Simulate a brute force attack"""
    print("Simulating Brute Force Attack from 10.0.0.200...")
    
    for i in range(10):
        response = requests.post(
            f'{BASE_URL}/anomaly/failed-auth',
            json={'source_ip': '10.0.0.200'}
        )
        result = response.json()
        print(f"  Attempt {i+1}: {result.get('failed_attempts')} failed attempts, Alert: {result.get('alert_triggered')}")
    
    print()


def get_alerts(level=None, limit=10):
    """Get alerts with optional filtering"""
    params = {'limit': limit}
    if level:
        params['level'] = level
    
    response = requests.get(f'{BASE_URL}/alerts', params=params)
    print(f"Alerts (level={level}, limit={limit}):")
    print(json.dumps(response.json(), indent=2))
    print()


def get_alert_by_id(alert_id):
    """Get a specific alert by ID"""
    response = requests.get(f'{BASE_URL}/alerts/{alert_id}')
    print(f"Alert {alert_id}:")
    print(json.dumps(response.json(), indent=2))
    print()


def update_alert_status(alert_id, status, notes=None):
    """Update an alert's status"""
    data = {'status': status}
    if notes:
        data['notes'] = notes
    
    response = requests.put(
        f'{BASE_URL}/alerts/{alert_id}/status',
        json=data
    )
    print(f"Update Alert {alert_id} Status to {status}:")
    print(json.dumps(response.json(), indent=2))
    print()


def bulk_update_alerts(alert_ids, status):
    """Bulk update alert statuses"""
    response = requests.put(
        f'{BASE_URL}/alerts/bulk/status',
        json={'alert_ids': alert_ids, 'status': status}
    )
    print(f"Bulk Update Alerts to {status}:")
    print(json.dumps(response.json(), indent=2))
    print()


def get_alert_statistics():
    """Get alert statistics"""
    response = requests.get(f'{BASE_URL}/alerts/statistics')
    print("Alert Statistics:")
    print(json.dumps(response.json(), indent=2))
    print()


def export_alerts(format='json'):
    """Export alerts"""
    response = requests.get(f'{BASE_URL}/alerts/export', params={'format': format})
    print(f"Export Alerts ({format}):")
    if format == 'json':
        print(json.dumps(response.json(), indent=2))
    else:
        print(response.text[:500] + "..." if len(response.text) > 500 else response.text)
    print()


def get_rules():
    """Get all detection rules"""
    response = requests.get(f'{BASE_URL}/rules')
    print("Detection Rules:")
    print(json.dumps(response.json(), indent=2))
    print()


def create_rule():
    """Create a new detection rule"""
    rule = {
        'name': 'Custom Credential Leak Detection',
        'pattern': r'(password|passwd|pwd)\s*[=:]\s*["\']?\w+',
        'alert_level': 'HIGH',
        'action': 'alert',
        'description': 'Detects potential credential leaks in traffic',
        'tags': ['credentials', 'sensitive', 'custom']
    }
    
    response = requests.post(f'{BASE_URL}/rules', json=rule)
    print("Create Rule:")
    print(json.dumps(response.json(), indent=2))
    print()
    
    return response.json().get('rule', {}).get('id')


def test_rule_pattern():
    """Test a rule pattern without creating it"""
    test_data = {
        'pattern': r'(api[_-]?key|apikey)\s*[=:]\s*["\']?[\w-]+',
        'payload': 'Authorization: api_key = sk-12345abcdef'
    }
    
    response = requests.post(f'{BASE_URL}/rules/test', json=test_data)
    print("Test Rule Pattern:")
    print(json.dumps(response.json(), indent=2))
    print()


def toggle_rule(rule_id, enabled):
    """Enable or disable a rule"""
    response = requests.post(
        f'{BASE_URL}/rules/{rule_id}/toggle',
        json={'enabled': enabled}
    )
    print(f"Toggle Rule {rule_id} to {enabled}:")
    print(json.dumps(response.json(), indent=2))
    print()


def delete_rule(rule_id):
    """Delete a rule"""
    response = requests.delete(f'{BASE_URL}/rules/{rule_id}')
    print(f"Delete Rule {rule_id}:")
    print(json.dumps(response.json(), indent=2))
    print()


def get_anomaly_thresholds():
    """Get anomaly detection thresholds"""
    response = requests.get(f'{BASE_URL}/anomaly/thresholds')
    print("Anomaly Thresholds:")
    print(json.dumps(response.json(), indent=2))
    print()


def update_anomaly_thresholds():
    """Update anomaly detection thresholds"""
    thresholds = {
        'packets_per_second': 1500,
        'connections_per_ip': 150,
        'port_scan_threshold': 25
    }
    
    response = requests.put(f'{BASE_URL}/anomaly/thresholds', json=thresholds)
    print("Update Anomaly Thresholds:")
    print(json.dumps(response.json(), indent=2))
    print()


def get_anomaly_statistics():
    """Get anomaly detection statistics"""
    response = requests.get(f'{BASE_URL}/anomaly/statistics')
    print("Anomaly Statistics:")
    print(json.dumps(response.json(), indent=2))
    print()


def reset_anomaly_baseline():
    """Reset the anomaly detection baseline"""
    response = requests.post(f'{BASE_URL}/anomaly/baseline/reset')
    print("Reset Anomaly Baseline:")
    print(json.dumps(response.json(), indent=2))
    print()


def add_to_blocklist(ip, reason):
    """Add an IP to the blocklist"""
    response = requests.post(
        f'{BASE_URL}/blocklist',
        json={'ip': ip, 'reason': reason}
    )
    print(f"Add {ip} to Blocklist:")
    print(json.dumps(response.json(), indent=2))
    print()


def check_blocklist(ip):
    """Check if an IP is blocked"""
    response = requests.get(f'{BASE_URL}/blocklist/check/{ip}')
    print(f"Check Blocklist for {ip}:")
    print(json.dumps(response.json(), indent=2))
    print()


def get_blocklist():
    """Get all blocked IPs"""
    response = requests.get(f'{BASE_URL}/blocklist')
    print("Blocklist:")
    print(json.dumps(response.json(), indent=2))
    print()


def remove_from_blocklist(ip):
    """Remove an IP from the blocklist"""
    response = requests.delete(f'{BASE_URL}/blocklist/{ip}')
    print(f"Remove {ip} from Blocklist:")
    print(json.dumps(response.json(), indent=2))
    print()


def get_dashboard_summary():
    """Get dashboard summary"""
    response = requests.get(f'{BASE_URL}/dashboard/summary')
    print("Dashboard Summary:")
    print(json.dumps(response.json(), indent=2))
    print()


def get_dashboard_timeline():
    """Get alert timeline for dashboard"""
    response = requests.get(f'{BASE_URL}/dashboard/timeline', params={'hours': 24, 'interval': 60})
    print("Dashboard Timeline (24h, hourly):")
    print(json.dumps(response.json(), indent=2))
    print()


def get_daily_report():
    """Get daily security report"""
    response = requests.get(f'{BASE_URL}/reports/daily')
    print("Daily Report:")
    print(json.dumps(response.json(), indent=2))
    print()


def get_weekly_report():
    """Get weekly security report"""
    response = requests.get(f'{BASE_URL}/reports/weekly')
    print("Weekly Report:")
    print(json.dumps(response.json(), indent=2))
    print()


def generate_custom_report():
    """Generate a custom report"""
    report_params = {
        'start_date': '2026-02-07T00:00:00',
        'end_date': '2026-02-14T23:59:59',
        'filters': {
            'levels': ['HIGH', 'CRITICAL']
        },
        'include': {
            'summary': True,
            'timeline': True,
            'top_sources': True,
            'top_types': True,
            'raw_alerts': False
        }
    }
    
    response = requests.post(f'{BASE_URL}/reports/custom', json=report_params)
    print("Custom Report:")
    print(json.dumps(response.json(), indent=2))
    print()


def run_full_demo():
    """Run a full demonstration of the IDS API"""
    print("=" * 60)
    print("IDS Backend API Demo")
    print("=" * 60)
    print()
    
    # Health and status
    check_health()
    get_system_status()
    
    # Rules management
    print("-" * 40)
    print("RULES MANAGEMENT")
    print("-" * 40)
    get_rules()
    test_rule_pattern()
    rule_id = create_rule()
    if rule_id:
        toggle_rule(rule_id, False)
        toggle_rule(rule_id, True)
    
    # Anomaly detection configuration
    print("-" * 40)
    print("ANOMALY DETECTION")
    print("-" * 40)
    get_anomaly_thresholds()
    update_anomaly_thresholds()
    get_anomaly_statistics()
    
    # Simulate attacks
    print("-" * 40)
    print("ATTACK SIMULATION")
    print("-" * 40)
    inject_test_packet()
    inject_malicious_packet()
    inject_xss_packet()
    simulate_port_scan()
    simulate_brute_force()
    
    # Wait for processing
    print("Waiting for packet processing...")
    time.sleep(2)
    
    # Check alerts
    print("-" * 40)
    print("ALERTS")
    print("-" * 40)
    get_alerts(limit=5)
    get_alerts(level='HIGH', limit=5)
    get_alert_statistics()
    
    # Blocklist management
    print("-" * 40)
    print("BLOCKLIST MANAGEMENT")
    print("-" * 40)
    add_to_blocklist('10.0.0.100', 'Port scanning detected')
    add_to_blocklist('10.0.0.50', 'SQL injection attempts')
    get_blocklist()
    check_blocklist('10.0.0.100')
    check_blocklist('192.168.1.1')
    
    # Dashboard and reports
    print("-" * 40)
    print("DASHBOARD & REPORTS")
    print("-" * 40)
    get_dashboard_summary()
    get_daily_report()
    
    # Cleanup
    print("-" * 40)
    print("CLEANUP")
    print("-" * 40)
    if rule_id:
        delete_rule(rule_id)
    remove_from_blocklist('10.0.0.100')
    remove_from_blocklist('10.0.0.50')
    
    print("=" * 60)
    print("Demo Complete!")
    print("=" * 60)


def run_attack_simulation():
    """Run a comprehensive attack simulation"""
    print("=" * 60)
    print("Attack Simulation Suite")
    print("=" * 60)
    print()
    
    attacker_ips = ['10.0.0.50', '10.0.0.51', '10.0.0.52', '10.0.0.53']
    
    # 1. SQL Injection attacks
    print("[1/6] Simulating SQL Injection attacks...")
    sql_payloads = [
        "GET /login?user=admin'-- HTTP/1.1",
        "POST /search HTTP/1.1\r\n\r\nq=1' OR '1'='1",
        "GET /products?id=1 UNION SELECT * FROM users HTTP/1.1",
        "GET /api/user?id=1; DROP TABLE users;-- HTTP/1.1",
        "POST /login HTTP/1.1\r\n\r\nusername=admin'/*&password=*/OR'1'='1"
    ]
    
    for i, payload in enumerate(sql_payloads):
        packet = {
            'src_ip': attacker_ips[0],
            'dst_ip': '192.168.1.1',
            'src_port': 50000 + i,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': payload,
            'size': len(payload)
        }
        requests.post(f'{BASE_URL}/monitor/inject', json=packet)
    print(f"  Injected {len(sql_payloads)} SQL injection packets")
    
    # 2. XSS attacks
    print("[2/6] Simulating XSS attacks...")
    xss_payloads = [
        "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
        "GET /page?name=<img src=x onerror=alert('XSS')> HTTP/1.1",
        "POST /comment HTTP/1.1\r\n\r\nbody=<svg onload=alert('XSS')>",
        "GET /profile?bio=javascript:alert(document.cookie) HTTP/1.1"
    ]
    
    for i, payload in enumerate(xss_payloads):
        packet = {
            'src_ip': attacker_ips[1],
            'dst_ip': '192.168.1.1',
            'src_port': 51000 + i,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': payload,
            'size': len(payload)
        }
        requests.post(f'{BASE_URL}/monitor/inject', json=packet)
    print(f"  Injected {len(xss_payloads)} XSS packets")
    
    # 3. Path traversal attacks
    print("[3/6] Simulating Path Traversal attacks...")
    traversal_payloads = [
        "GET /files/../../../etc/passwd HTTP/1.1",
        "GET /download?file=....//....//etc/shadow HTTP/1.1",
        "GET /static/%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1",
        "GET /include?page=..\\..\\..\\windows\\system32\\config\\sam HTTP/1.1"
    ]
    
    for i, payload in enumerate(traversal_payloads):
        packet = {
            'src_ip': attacker_ips[2],
            'dst_ip': '192.168.1.1',
            'src_port': 52000 + i,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': payload,
            'size': len(payload)
        }
        requests.post(f'{BASE_URL}/monitor/inject', json=packet)
    print(f"  Injected {len(traversal_payloads)} path traversal packets")
    
    # 4. Port scan
    print("[4/6] Simulating Port Scan...")
    scan_ip = attacker_ips[3]
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
                   1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    
    for port in common_ports:
        packet = {
            'src_ip': scan_ip,
            'dst_ip': '192.168.1.1',
            'src_port': 54321,
            'dst_port': port,
            'protocol': 'tcp',
            'payload': '',
            'size': 64,
            'flags': {'syn': True, 'ack': False}
        }
        requests.post(f'{BASE_URL}/monitor/inject', json=packet)
    print(f"  Scanned {len(common_ports)} common ports")
    
    # 5. SYN flood simulation
    print("[5/6] Simulating SYN Flood (limited)...")
    flood_ip = '10.0.0.99'
    for i in range(30):
        packet = {
            'src_ip': flood_ip,
            'dst_ip': '192.168.1.1',
            'src_port': 40000 + i,
            'dst_port': 80,
            'protocol': 'tcp',
            'payload': '',
            'size': 64,
            'flags': {'syn': True, 'ack': False}
        }
        requests.post(f'{BASE_URL}/monitor/inject', json=packet)
    print(f"  Sent 30 SYN packets from {flood_ip}")
    
    # 6. Brute force simulation
    print("[6/6] Simulating Brute Force attack...")
    brute_ip = '10.0.0.88'
    for i in range(10):
        requests.post(
            f'{BASE_URL}/anomaly/failed-auth',
            json={'source_ip': brute_ip}
        )
    print(f"  Recorded 10 failed auth attempts from {brute_ip}")
    
    # Wait for processing
    print("\nWaiting for analysis...")
    time.sleep(3)
    
    # Get results
    print("\n" + "=" * 60)
    print("Attack Simulation Results")
    print("=" * 60)
    
    # Get alert summary
    stats_response = requests.get(f'{BASE_URL}/alerts/statistics')
    stats = stats_response.json()
    
    print(f"\nTotal Alerts Generated: {stats.get('total_alerts', 0)}")
    print(f"Alerts by Severity:")
    for level, count in stats.get('by_level', {}).items():
        print(f"  {level}: {count}")
    
    print(f"\nTop Alert Types:")
    for alert_type, count in list(stats.get('by_type', {}).items())[:5]:
        print(f"  {alert_type}: {count}")
    
    print(f"\nTop Attack Sources:")
    for source, count in list(stats.get('top_sources', {}).items())[:5]:
        print(f"  {source}: {count}")
    
    # Get recent critical/high alerts
    alerts_response = requests.get(f'{BASE_URL}/alerts', params={'level': 'CRITICAL', 'limit': 5})
    critical_alerts = alerts_response.json().get('alerts', [])
    
    if critical_alerts:
        print(f"\nRecent Critical Alerts:")
        for alert in critical_alerts:
            print(f"  [{alert['timestamp']}] {alert['alert_type']} from {alert['source_ip']}")
    
    print("\n" + "=" * 60)
    print("Attack Simulation Complete!")
    print("=" * 60)


def interactive_menu():
    """Interactive menu for testing the API"""
    while True:
        print("\n" + "=" * 50)
        print("IDS Backend API - Interactive Menu")
        print("=" * 50)
        print("1.  Health Check")
        print("2.  System Status")
        print("3.  Get All Alerts")
        print("4.  Get Alert Statistics")
        print("5.  Get Detection Rules")
        print("6.  Create Custom Rule")
        print("7.  Test Rule Pattern")
        print("8.  Get Anomaly Thresholds")
        print("9.  Inject Test Packet")
        print("10. Inject Malicious Packet")
        print("11. Simulate Port Scan")
        print("12. Simulate Brute Force")
        print("13. Get Blocklist")
        print("14. Add IP to Blocklist")
        print("15. Dashboard Summary")
        print("16. Daily Report")
        print("17. Weekly Report")
        print("18. Run Full Demo")
        print("19. Run Attack Simulation")
        print("0.  Exit")
        print("-" * 50)
        
        try:
            choice = input("Enter your choice: ").strip()
            
            if choice == '1':
                check_health()
            elif choice == '2':
                get_system_status()
            elif choice == '3':
                limit = input("Limit (default 10): ").strip() or '10'
                level = input("Level filter (LOW/MEDIUM/HIGH/CRITICAL or blank): ").strip() or None
                get_alerts(level=level, limit=int(limit))
            elif choice == '4':
                get_alert_statistics()
            elif choice == '5':
                get_rules()
            elif choice == '6':
                create_rule()
            elif choice == '7':
                test_rule_pattern()
            elif choice == '8':
                get_anomaly_thresholds()
            elif choice == '9':
                inject_test_packet()
            elif choice == '10':
                inject_malicious_packet()
            elif choice == '11':
                simulate_port_scan()
            elif choice == '12':
                simulate_brute_force()
            elif choice == '13':
                get_blocklist()
            elif choice == '14':
                ip = input("IP to block: ").strip()
                reason = input("Reason: ").strip()
                if ip:
                    add_to_blocklist(ip, reason or "Manual block")
            elif choice == '15':
                get_dashboard_summary()
            elif choice == '16':
                get_daily_report()
            elif choice == '17':
                get_weekly_report()
            elif choice == '18':
                run_full_demo()
            elif choice == '19':
                run_attack_simulation()
            elif choice == '0':
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
        
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except requests.exceptions.ConnectionError:
            print("\nError: Cannot connect to the IDS API. Is the server running?")
        except Exception as e:
            print(f"\nError: {e}")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'demo':
            run_full_demo()
        elif command == 'attack':
            run_attack_simulation()
        elif command == 'health':
            check_health()
        elif command == 'status':
            get_system_status()
        elif command == 'alerts':
            get_alerts()
        elif command == 'rules':
            get_rules()
        elif command == 'dashboard':
            get_dashboard_summary()
        elif command == 'report':
            get_daily_report()
        elif command == 'menu':
            interactive_menu()
        else:
            print(f"Unknown command: {command}")
            print("Available commands: demo, attack, health, status, alerts, rules, dashboard, report, menu")
    else:
        interactive_menu()