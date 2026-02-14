# IDS AWS Deployment Guide

This guide explains how to deploy the IDS (Backend, Frontend, MongoDB) on AWS with **VPC Flow Logs** for network traffic analysis and an **Attacker** EC2 instance for testing.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AWS VPC                                        │
│  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────┐  │
│  │ IDS Backend     │   │ Frontend        │   │ MongoDB (DocDB or    │  │
│  │ EC2 / ECS       │   │ S3 + CloudFront │   │ EC2 + MongoDB)       │  │
│  │ Port 5000       │   │ or EC2          │   │ Port 27017           │  │
│  └────────┬────────┘   └────────┬────────┘   └──────────┬──────────┘  │
│           │                    │                       │              │
│           └────────────────────┼───────────────────────┘              │
│                                │                                       │
│  ┌─────────────────────────────┼───────────────────────────────────┐  │
│  │         VPC Flow Logs → CloudWatch Logs                          │  │
│  │                    │                                             │  │
│  │                    ▼                                             │  │
│  │              Lambda (Flow Log Subscriber)                         │  │
│  │                    │                                             │  │
│  │                    ▼ POST /api/v1/flow-logs/inject               │  │
│  │              IDS Backend                                          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │ Attacker EC2    │  ───────►  Generates attack traffic                │
│  │ t3.small        │            (port scan, flood, brute force, etc.)  │
│  └─────────────────┘                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- AWS Account
- AWS CLI configured
- VPC with at least 2 subnets (public + private recommended)
- Security groups allowing traffic between components

---

## 1. Deploy MongoDB

### Option A: Amazon DocumentDB (Managed)

```bash
# Create DocumentDB cluster (or use existing MongoDB Atlas)
aws docdb create-db-cluster \
  --db-cluster-identifier ids-db \
  --engine docdb \
  --master-username admin \
  --master-user-password YOUR_SECURE_PASSWORD
```

### Option B: EC2 + MongoDB (via Docker)

Use the existing `Database/ids_database/docker-compose.yml`:

```bash
cd Database/ids_database
docker-compose up -d
# MongoDB will be on port 27017
```

Set `MONGODB_URI` to your MongoDB connection string (e.g. `mongodb://user:pass@host:27017/ids`).

---

## 2. Deploy IDS Backend

### EC2 Deployment

1. Launch an EC2 instance (e.g. t3.medium) in your VPC.
2. Install dependencies:

```bash
sudo yum install -y python3.11 python3-pip git
git clone <your-repo> ids-project
cd ids-project/Backend/ids_backend
pip3 install -r requirements.txt
```

3. Configure environment:

```bash
export IDS_HOST=0.0.0.0
export IDS_PORT=5000
export NETWORK_INTERFACE=eth0
# Optional: MongoDB integration (if backend writes to MongoDB)
# export MONGODB_URI=mongodb://user:pass@docdb-endpoint:27017/ids
```

4. Run with gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 "app:app"
```

5. **Start the traffic monitor** (required for detection):
   - Call `POST /api/v1/monitor/start` after the API is up
   - Or configure it to auto-start in your deployment

### VPC Flow Logs Mode (No Packet Capture)

When using VPC Flow Logs, the backend does **not** need to capture packets on the interface. Traffic is ingested via the `/api/v1/flow-logs/inject` endpoint from a Lambda function. See Section 5.

---

## 3. Deploy Frontend

### Build and deploy to S3 + CloudFront

```bash
cd Frontend/ids-control-panel
npm install
npm run build

# Deploy to S3
aws s3 sync dist/ s3://your-ids-frontend-bucket/ --delete

# Invalidate CloudFront cache (if using)
aws cloudfront create-invalidation --distribution-id YOUR_DIST_ID --paths "/*"
```

Configure the frontend to point to your backend API (environment variable or config).

### Or run on EC2

```bash
npm run build
npx serve -s dist -l 3000
```

---

## 4. Deploy the Attacker (EC2 t3.small)

The attacker runs on a **separate** EC2 instance to simulate attack traffic against your IDS/victim.

### Launch EC2 t3.small

1. Launch Amazon Linux 2 or Ubuntu AMI, t3.small.
2. Ensure security group allows **outbound** to your VPC (or 0.0.0.0/0).
3. Attacker must be able to reach the **victim** (IDS or target server) over the network.

### Install and Run

```bash
# SSH into attacker EC2
ssh -i your-key.pem ec2-user@<ATTACKER_PUBLIC_IP>

# Clone or copy the attacker script
# Option 1: From repo
sudo yum install -y python3 python3-pip git
git clone <your-repo> ids-project
cd ids-project/Attacker

# Install dependencies
pip3 install -r requirements.txt

# Run attacker - replace VICTIM_PRIVATE_IP with your IDS/target EC2 private IP
export TARGET_IP=10.0.1.50   # Private IP of victim/IDS in your VPC
python3 attacker.py --mode all --duration 120
```

### Attacker Modes

| Mode        | Description                          |
|-------------|--------------------------------------|
| `portscan`  | Scans common ports (SSH, HTTP, DBs) |
| `flood`     | Connection flood to a port           |
| `bruteforce`| Many connection attempts to SSH/DB   |
| `http`      | HTTP requests with SQLi/XSS payloads |
| `all`       | Runs all modes in sequence           |

### Attacker Server (Defender-Triggered)

For **Testing page integration**, run the attacker as an HTTP server. The defender (frontend) sends attack commands to it:

```bash
export TARGET_IP=10.0.1.50   # Defender/IDS IP to attack
python3 attacker_server.py --port 9999
```

Open firewall port 9999 for inbound from the Defender/Backend IP. In the frontend **Testing** page:
- **Attacker URL**: `http://10.0.1.100:9999` (attacker VM IP)
- **Target IP**: `10.0.1.50` (defender/IDS VM)

Click an attack type to signal the attacker. The backend proxies the command to the attacker.

### CLI Examples

```bash
# Port scan only
python3 attacker.py --target 10.0.1.50 --mode portscan

# Connection flood to port 80 for 60 seconds
python3 attacker.py --target 10.0.1.50 --mode flood --port 80 --duration 60

# Brute force simulation
python3 attacker.py --target 10.0.1.50 --mode bruteforce --duration 120

# Run all attacks, loop 5 times
python3 attacker.py --target 10.0.1.50 --mode all --loop 5
```

### Security Note

The attacker generates traffic that will trigger IDS alerts. Use only in a **controlled test environment**. Restrict the attacker's security group so it can only reach your test targets.

---

## 5. VPC Flow Logs Setup

VPC Flow Logs capture network traffic metadata. The IDS analyzes these records for anomalies (port scans, connection spikes, etc.).

### Step 1: Create VPC Flow Log

```bash
# Create IAM role for Flow Logs (if not exists)
# Create log group
aws logs create-log-group --log-group-name /aws/vpc/flow-logs

# Create flow log - replace VPC_ID and SUBNET_ID with your values
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-xxxxxxxxx \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flow-logs \
  --deliver-logs-permission-arn arn:aws:iam::ACCOUNT:role/FlowLogsRole
```

### Step 2: Lambda to Forward Flow Logs to IDS

Create a Lambda function triggered by a **CloudWatch Logs subscription filter** on the flow log group.

**Lambda handler (Python):**

```python
import json
import urllib.request
import gzip
import base64

IDS_API_URL = "https://your-ids-api.example.com/api/v1/flow-logs/inject"

def lambda_handler(event, context):
    records = []
    for log_event in event.get("logEvents", []):
        try:
            data = base64.b64decode(log_event["message"])
            if data[:2] == b"\x1f\x8b":
                data = gzip.decompress(data)
            text = data.decode("utf-8")
            for line in text.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 12:
                    records.append({
                        "srcaddr": parts[3],
                        "dstaddr": parts[4],
                        "srcport": parts[5],
                        "dstport": parts[6],
                        "protocol": parts[7],
                        "packets": parts[8],
                        "bytes": parts[9],
                    })
        except Exception as e:
            print(f"Parse error: {e}")
            continue

    if not records:
        return {"statusCode": 200, "body": "No records"}

    req = urllib.request.Request(
        IDS_API_URL,
        data=json.dumps({"records": records}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read().decode())
        print(f"Injected: {result.get('injected', 0)}")
    return {"statusCode": 200, "body": json.dumps(result)}
```

### Step 3: Create Subscription Filter

```bash
# Get Lambda ARN and Flow Log stream
aws logs put-subscription-filter \
  --log-group-name /aws/vpc/flow-logs \
  --filter-name "ForwardToIDS" \
  --filter-pattern "" \
  --destination-arn arn:aws:lambda:REGION:ACCOUNT:function:FlowLogToIDS
```

The Lambda must be in the same region as the log group and have permission to be invoked by CloudWatch Logs.

---

## 6. Data Flow Summary

| Component    | Role |
|-------------|------|
| **Backend** | Runs detection (rules, anomaly). Receives packets from: (a) live capture, or (b) `/flow-logs/inject` from Lambda. Stores alerts in memory (or MongoDB if integrated). |
| **Frontend**| Dashboard. Fetches alerts from Backend API. |
| **MongoDB** | Stores alerts (used by Database/ids_database service). Backend can be extended to write alerts to MongoDB. |
| **Attacker**| Generates attack traffic → appears in VPC Flow Logs → Lambda → Backend → Alerts. |
| **Lambda**  | Reads CloudWatch Logs (VPC Flow Logs), parses, POSTs to Backend `/flow-logs/inject`. |

---

## 7. Quick Test (Without VPC Flow Logs)

To test immediately **without** VPC Flow Logs:

1. Deploy Backend and start it.
2. Start the monitor: `curl -X POST http://YOUR_BACKEND_IP:5000/api/v1/monitor/start`
3. Deploy Attacker, set `TARGET_IP` to Backend’s IP (or any target in VPC).
4. Run: `python3 attacker.py --mode all`
5. Check alerts: `curl http://YOUR_BACKEND_IP:5000/api/v1/alerts`

**Note:** Without VPC Flow Logs, the Backend must use **packet capture** (Scapy). That requires the Backend EC2 to see the traffic (same subnet or in path). With VPC Flow Logs, the Backend receives traffic via Lambda and does not need packet capture.

---

## 8. Connecting Frontend to Backend

Update the frontend API base URL to your deployed backend:

- In production: Set `VITE_API_URL` or equivalent to `https://your-ids-api.example.com`
- Ensure CORS on the backend allows your frontend origin.

---

## 9. Security Group Checklist

| Source       | Target  | Port   | Purpose            |
|-------------|---------|--------|--------------------|
| Frontend    | Backend | 5000   | API calls          |
| Lambda      | Backend | 5000   | Flow log ingestion |
| Attacker    | Victim  | 22,80,443,3306,etc | Attack traffic |
| Your IP     | Frontend| 443/80 | Dashboard access   |
| Backend     | MongoDB | 27017  | DB connection      |

---

## 10. Troubleshooting

- **No alerts from Attacker:** Confirm Attacker can reach victim IP; check Backend logs; ensure monitor is started.
- **Flow Logs not appearing:** Flow logs can take ~5–10 minutes. Check CloudWatch Logs for `/aws/vpc/flow-logs`.
- **Lambda not invoking:** Verify subscription filter and Lambda permissions (CloudWatch Logs → Lambda).
- **Backend "monitor not initialized":** The TrafficMonitor is created at startup; call `POST /monitor/start` to begin capture.
