import json
import random
import string
from datetime import datetime, timedelta, timezone

# 1) How many log lines to generate
N = 500

# 2) Output file path (relative). Change if you want.
OUT = "mvp/logs/app.jsonl"

# 3) Helper to make a short request_id like you see in real systems
def rid(n=12):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))

# 4) Helper to make IP addresses (mix of private + test/public ranges)
def fake_ip():
    pools = [
        ("10",), ("192.168",), ("172.16",),         # private ranges
        ("203.0.113",), ("198.51.100",), ("192.0.2",)  # documentation/test ranges
    ]
    p = random.choice(pools)[0]
    parts = p.split(".")
    while len(parts) < 3:
        parts.append(str(random.randint(0, 255)))
    parts.append(str(random.randint(1, 254)))
    return ".".join(parts[:4])

# 5) Pick from common ports/protocols/events
PORTS = [22, 53, 80, 443, 445, 3389, 8080, 9001]
PROTOS = ["TCP", "UDP"]
EVENTS = ["request", "ingest", "ingest_error", "rate_limit", "suspicious_user_agent"]

USER_AGENTS = [
    "Mozilla/5.0",
    "curl/8.1.2",
    "python-requests/2.31.0",
    "PostmanRuntime/7.36.0",
    "sqlmap/1.8.2"
]

ALERTS = [
    ("bruteforce_suspected", ["ssh", "bruteforce"]),
    ("scanner_detected", ["scanner", "http"]),
    ("rdp_anomaly", ["rdp", "lateral_movement"]),
    ("dns_tunnel_suspected", ["dns", "exfiltration"]),
    ("data_exfil_suspected", ["exfiltration", "egress"])
]

# 6) Start time for logs (now minus a few minutes)
t0 = datetime.now(timezone.utc) - timedelta(minutes=10)

with open(OUT, "w", encoding="utf-8") as f:
    for i in range(N):
        # 7) Increment time slightly for each line
        ts = (t0 + timedelta(seconds=i * random.randint(1, 3))).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 8) Choose an event type
        event = random.choices(EVENTS, weights=[45, 40, 5, 5, 5])[0]

        # 9) Base log fields
        log = {
            "ts": ts,
            "level": "INFO",
            "event": event,
            "request_id": rid(),
            "client_ip": fake_ip(),
            "user_agent": random.choice(USER_AGENTS),
        }

        # 10) Add fields based on event type
        if event == "request":
            path = random.choice(["/health", "/logs/latest", "/"])
            status = random.choice([200, 200, 200, 404])
            log.update({
                "method": "GET",
                "path": path,
                "status": status,
                "duration_ms": random.randint(1, 30),
            })

        elif event == "ingest":
            src = fake_ip()
            dst = fake_ip()
            dst_port = random.choice(PORTS)
            proto = random.choice(PROTOS)

            # Sometimes it's a normal accept, sometimes it's an alert
            if random.random() < 0.75:
                action = "accept"
                log.update({
                    "method": "POST",
                    "path": "/ingest",
                    "status": 200,
                    "duration_ms": random.randint(5, 60),
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": dst_port,
                    "proto": proto,
                    "bytes_in": random.randint(50, 5000),
                    "bytes_out": random.randint(50, 20000),
                    "action": action,
                    "sensor": random.choice(["zeek", "netflow", "waf", "auth"]),
                    "tags": random.sample(["http", "tls", "dns", "ssh", "rdp", "smb", "login"], k=random.randint(1, 3)),
                })
            else:
                alert_type, tags = random.choice(ALERTS)
                log["level"] = "WARN"
                log.update({
                    "method": "POST",
                    "path": "/ingest",
                    "status": 200,
                    "duration_ms": random.randint(5, 90),
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": dst_port,
                    "proto": proto,
                    "action": "alert",
                    "alert_type": alert_type,
                    "confidence": round(random.uniform(0.65, 0.98), 2),
                    "sensor": random.choice(["waf", "auth", "netflow"]),
                    "tags": tags,
                })

        elif event == "ingest_error":
            log["level"] = "ERROR"
            log.update({
                "method": "POST",
                "path": "/ingest",
                "status": 400,
                "duration_ms": random.randint(1, 20),
                "error": random.choice(["invalid_json", "missing_fields", "schema_error"]),
                "message": "Payload rejected",
            })

        elif event == "rate_limit":
            log["level"] = "WARN"
            log.update({
                "method": "POST",
                "path": "/ingest",
                "status": 429,
                "duration_ms": random.randint(1, 10),
                "limit_per_min": 120,
                "retry_after_s": random.choice([5, 10, 15, 30]),
            })

        elif event == "suspicious_user_agent":
            log["level"] = "WARN"
            log["user_agent"] = "sqlmap/1.8.2"
            log.update({
                "method": "POST",
                "path": "/ingest",
                "status": 200,
                "duration_ms": random.randint(5, 50),
                "action": "alert",
                "alert_type": "scanner_detected",
                "confidence": round(random.uniform(0.80, 0.99), 2),
                "sensor": "waf",
                "tags": ["scanner", "http"],
            })

        # 11) Write one JSON object per line
        f.write(json.dumps(log, ensure_ascii=False) + "\n")

print(f"Generated {N} fake log lines -> {OUT}")