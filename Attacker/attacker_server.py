#!/usr/bin/env python3
"""
IDS Attacker HTTP Server - Receives attack commands from the defender (IDS panel).
Run this on the attacker VM. The defender sends signals to trigger attacks.

Usage:
    python attacker_server.py --port 9999
    TARGET_IP=10.0.1.50 python attacker_server.py   # Defender/victim IP to attack
"""

import argparse
import json
import os
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Import attack logic from attacker module
from attacker import (
    port_scan,
    connection_flood,
    brute_force_simulation,
    http_attack,
)

# Map frontend attack types to attacker modes
ATTACK_TYPE_TO_MODE = {
    "Port Scan": "portscan",
    "portscan": "portscan",
    "DDoS": "flood",
    "ddos": "flood",
    "flood": "flood",
    "Brute Force": "bruteforce",
    "bruteforce": "bruteforce",
    "SQL Injection": "http_sqli",
    "SQL injection": "http_sqli",
    "XSS": "http_xss",
    "xss": "http_xss",
    "Buffer Overflow": "flood",
    "DNS Tunneling": "portscan",
    "Malware C2": "bruteforce",
}


def run_attack(mode: str, target_ip: str, port: int = 80, duration: int = 30) -> dict:
    """Execute attack and return stats."""
    if mode == "portscan":
        count = port_scan(target_ip)
        return {"mode": mode, "count": count, "message": f"Port scan completed: {count} probes"}
    if mode == "flood":
        count = connection_flood(target_ip, port, duration, 5)
        return {"mode": mode, "count": count, "message": f"Connection flood: {count} connections"}
    if mode == "bruteforce":
        count = brute_force_simulation(target_ip, duration)
        return {"mode": mode, "count": count, "message": f"Brute force sim: {count} attempts"}
    if "http" in mode:
        count = http_attack(target_ip, port, duration)
        return {"mode": mode, "count": count, "message": f"HTTP attacks: {count} requests"}
    return {"mode": mode, "count": 0, "message": f"Unknown mode: {mode}"}


class AttackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        if self.path != "/attack/start":
            self.send_error(404)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self._send_json(400, {"success": False, "message": "Invalid JSON"})
            return

        attack_type = data.get("attackType", "")
        target_ip = data.get("targetIp", "").strip() or os.environ.get("TARGET_IP", "")
        port = int(data.get("port", 80))
        duration = int(data.get("duration", 30))

        if not target_ip:
            self._send_json(400, {
                "success": False,
                "message": "targetIp required (or set TARGET_IP env var)",
            })
            return

        mode = ATTACK_TYPE_TO_MODE.get(attack_type)
        if not mode:
            mode = ATTACK_TYPE_TO_MODE.get(attack_type.lower(), "portscan")

        # Run attack in background thread so we return immediately
        def run():
            run_attack(mode, target_ip, port, duration)

        threading.Thread(target=run, daemon=True).start()

        self._send_json(200, {
            "success": True,
            "attackType": attack_type,
            "mode": mode,
            "targetIp": target_ip,
            "message": f"Attack started: {attack_type} -> {mode}",
        })

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "service": "ids-attacker"})
            return
        self.send_error(404)

    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())


def main():
    parser = argparse.ArgumentParser(description="IDS Attacker HTTP Server")
    parser.add_argument("--port", "-p", type=int, default=int(os.environ.get("ATTACKER_PORT", "9999")))
    parser.add_argument("--bind", "-b", default="0.0.0.0")
    args = parser.parse_args()

    target = os.environ.get("TARGET_IP")
    if not target:
        print("Warning: TARGET_IP not set. Defender must send targetIp in request body.", file=sys.stderr)

    server = HTTPServer((args.bind, args.port), AttackHandler)
    print(f"Attacker server listening on {args.bind}:{args.port}")
    print(f"  TARGET_IP: {target or '(from request)'}")
    print("  Endpoints: POST /attack/start, GET /health")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
