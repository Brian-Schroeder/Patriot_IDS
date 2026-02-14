# IDS Attacker

Simulates attack traffic for IDS testing. Designed to run on **AWS EC2 t3.small** in a separate subnet from your IDS infrastructure.

## Two Modes

### 1. Attacker Server (defender-triggered)

The defender (frontend Testing page) sends attack commands to the attacker. Run the **server** on the attacker VM:

```bash
pip install -r requirements.txt
export TARGET_IP=10.0.1.50   # Defender/victim IP to attack
python attacker_server.py --port 9999
```

Then in the frontend Testing page, configure:
- **Attacker URL**: `10.0.1.100:9999` (attacker VM IP and port)
- **Target IP**: `10.0.1.50` (defender/IDS IP)

Click an attack type to signal the attacker.

### 2. Standalone CLI

Run attacks manually without the defender:

```bash
export TARGET_IP=10.0.1.50
python attacker.py --mode all
```

## Attack Modes

| Mode | Description | IDS Detection |
|------|-------------|---------------|
| `portscan` | Probes common ports (22, 80, 443, 3306, 5432, etc.) | Port scan, reconnaissance |
| `flood` | Opens many rapid TCP connections to a port | DoS, connection flood |
| `bruteforce` | Many connection attempts to SSH/MySQL/RDP | Brute force |
| `http` | HTTP requests with SQLi, XSS, path traversal payloads | Signature-based (SQL injection, XSS) |
| `all` | Runs all modes in sequence | Various |

## Options

```
--target, -t     Target IP (or set TARGET_IP env var)
--port, -p       Target port for flood/http (default: 80)
--mode, -m       Attack mode: portscan, flood, bruteforce, http, all
--duration, -d   Run duration in seconds (default: 60)
--interval       Ms between requests in flood mode (default: 10)
--loop           Number of iterations (0 = infinite)
```

## AWS EC2 Setup

1. Launch t3.small (Amazon Linux 2 or Ubuntu).
2. Security group: allow **outbound** to your VPC (or 0.0.0.0/0).
3. Ensure the attacker can reach the victim over the network (same VPC or peered VPC).
4. Copy this folder to the instance and run.

## Example: User Data for EC2 Launch

```bash
#!/bin/bash
yum install -y python3 python3-pip git
cd /home/ec2-user
git clone <your-repo-url> ids-project
cd ids-project/Attacker
pip3 install -r requirements.txt
# Set TARGET_IP in /etc/environment or run manually
```

## Security Warning

Use only in a **controlled test environment**. The traffic generated will trigger IDS alerts and may impact target services.
