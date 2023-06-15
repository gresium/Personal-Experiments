#!/usr/bin/env python3
"""
Functional tests for the honeypot and its honeytokens.

Starts the honeypot on loopback with a temp config, plants tokens with the CLI,
runs a local webhook receiver, then acts as an attacker and checks:
  * fake services respond and never grant access;
  * over-long input is bounded (the denial-of-service fix);
  * a credential honeytoken fires a critical alert via SSH and via HTTP basic auth;
  * a web canary URL fires and is served believable content;
  * a decoy-file URL serves the file and fires;
  * normal probes do NOT raise alerts;
  * every alert reaches the alert log AND the webhook.

Run:  python3 tests/test_honeypot.py       (no third-party dependencies)
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HONEYPOT = os.path.join(ROOT, "honeypot.py")
CLI = os.path.join(ROOT, "honeytokens.py")

SSH_PORT, HTTP_PORT, WEBHOOK_PORT = 42222, 48080, 49090
PASS = FAIL = 0
_webhook_hits = []


def check(desc, actual, expected):
    global PASS, FAIL
    if actual == expected:
        print(f"PASS  {desc}"); PASS += 1
    else:
        print(f"FAIL  {desc} (expected {expected!r}, got {actual!r})"); FAIL += 1


def check_true(desc, cond):
    check(desc, bool(cond), True)


def recv_until(sock, token, timeout=3.0):
    sock.settimeout(timeout)
    buf = b""
    end = time.time() + timeout
    while token not in buf and time.time() < end:
        try:
            b = sock.recv(4096)
        except socket.timeout:
            break
        if not b:
            break
        buf += b
    return buf


def recv_all(sock, timeout=3.0):
    sock.settimeout(timeout)
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            b = sock.recv(4096)
        except socket.timeout:
            break
        if not b:
            break
        buf += b
    return buf


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            _webhook_hits.append(json.loads(body))
        except Exception:
            _webhook_hits.append({"_raw": body.decode("utf-8", "replace")})
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def cli(cfg_path, *args):
    out = subprocess.check_output([sys.executable, CLI, "-c", cfg_path, *args], text=True)
    return out


def main():
    tmp = tempfile.mkdtemp(prefix="hp-test-")
    cfg_path = os.path.join(tmp, "config.json")
    cfg = {
        "log_dir": tmp, "state_dir": tmp,
        "webhook_url": f"http://127.0.0.1:{WEBHOOK_PORT}/hook",
        "webhook_min_interval": 0,
        "max_connections": 10, "conn_timeout": 3,
        "max_line_bytes": 64, "max_conn_bytes": 256,
        "services": [
            {"name": "ssh", "bind": "127.0.0.1", "port": SSH_PORT, "mode": "login",
             "banner": "SSH-2.0-OpenSSH_8.2p1", "user_prompt": "login: ",
             "pass_prompt": "Password: ", "deny": "\r\nDenied\r\n", "login_rounds": 1},
            {"name": "http", "bind": "127.0.0.1", "port": HTTP_PORT, "mode": "http"},
        ],
    }
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)

    # Plant tokens BEFORE starting the honeypot.
    cli(cfg_path, "new", "credential", "--label", "trap db admin",
        "--username", "dbadmin", "--password", "S3cr3tDecoy", "--planted-at", "wiki")
    web_out = cli(cfg_path, "new", "web", "--label", "budget.xlsx link",
                  "--base-url", f"http://127.0.0.1:{HTTP_PORT}")
    web_id = next(l.split()[-1] for l in web_out.splitlines() if l.strip().startswith("id"))
    file_out = cli(cfg_path, "new", "file", "--name", "aws_credentials.txt",
                   "--label", "aws keys", "--base-url", f"http://127.0.0.1:{HTTP_PORT}")
    file_id = next(l.split()[-1] for l in file_out.splitlines() if l.strip().startswith("id"))
    check_true("CLI lists the three planted tokens", cli(cfg_path, "list").count("\n") >= 5)

    webhook = HTTPServer(("127.0.0.1", WEBHOOK_PORT), WebhookHandler)
    threading.Thread(target=webhook.serve_forever, daemon=True).start()

    proc = subprocess.Popen([sys.executable, HONEYPOT, "-c", cfg_path],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        up = False
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", SSH_PORT), 0.5).close()
                socket.create_connection(("127.0.0.1", HTTP_PORT), 0.5).close()
                up = True
                break
            except OSError:
                time.sleep(0.1)
        check_true("both services accept connections", up)

        # --- normal SSH login (no token): denied, no alert ---
        s = socket.create_connection(("127.0.0.1", SSH_PORT), 3)
        recv_until(s, b"login:")
        s.sendall(b"root\r\n"); recv_until(s, b"Password:")
        s.sendall(b"hunter2\r\n")
        check_true("ssh denies access (never grants it)", b"Denied" in recv_until(s, b"Denied"))
        s.close()

        # --- over-long line is bounded ---
        s = socket.create_connection(("127.0.0.1", SSH_PORT), 3)
        recv_until(s, b"login:")
        s.sendall(b"A" * 5000)
        check_true("over-long input is bounded and still answered", b"Password:" in recv_until(s, b"Password:"))
        s.close()

        # --- credential honeytoken via SSH ---
        s = socket.create_connection(("127.0.0.1", SSH_PORT), 3)
        recv_until(s, b"login:")
        s.sendall(b"dbadmin\r\n"); recv_until(s, b"Password:")
        s.sendall(b"S3cr3tDecoy\r\n"); recv_until(s, b"Denied")
        s.close()

        # --- credential honeytoken via HTTP basic auth ---
        import base64
        cred = base64.b64encode(b"dbadmin:S3cr3tDecoy").decode()
        s = socket.create_connection(("127.0.0.1", HTTP_PORT), 3)
        s.sendall(f"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {cred}\r\n\r\n".encode())
        recv_all(s); s.close()

        # --- web canary URL ---
        s = socket.create_connection(("127.0.0.1", HTTP_PORT), 3)
        s.sendall(f"GET /t/{web_id} HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n".encode())
        resp = recv_all(s); s.close()
        check_true("canary URL returns 200 (looks successful)", b"200" in resp)

        # --- decoy file URL serves the file content ---
        s = socket.create_connection(("127.0.0.1", HTTP_PORT), 3)
        s.sendall(f"GET /t/{file_id} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        resp = recv_all(s); s.close()
        check_true("decoy-file URL serves the planted file", b"aws_access_key_id" in resp)

        # --- normal HTTP probe (no token) ---
        s = socket.create_connection(("127.0.0.1", HTTP_PORT), 3)
        s.sendall(b"GET /admin HTTP/1.1\r\nHost: x\r\nUser-Agent: sqlmap/1.7\r\n\r\n")
        check_true("normal probe gets the 401 bait", b"401" in recv_all(s)); s.close()

        time.sleep(0.8)  # let logs flush and webhooks arrive

        # --- activity log ---
        with open(os.path.join(tmp, "honeypot.log"), encoding="utf-8") as f:
            events = [json.loads(x) for x in f if x.strip()]
        logins = [e for e in events if e["event"] == "login_attempt"]
        check_true("normal creds were captured", any(e.get("username") == "root" for e in logins))
        longest = max((max(len(e.get("username", "")), len(e.get("password", ""))) for e in logins), default=0)
        check_true("over-long input truncated to the cap (<=64)", longest <= 64)

        # --- alert log: exactly the four honeytoken hits, all critical ---
        with open(os.path.join(tmp, "alerts.log"), encoding="utf-8") as f:
            al = [json.loads(x) for x in f if x.strip()]
        triggers = [a for a in al if a.get("kind") == "honeytoken_triggered"]
        vias = sorted(a.get("via") for a in triggers)
        check("exactly 4 honeytoken alerts", len(triggers), 4)
        check("all alerts are critical", all(a.get("severity") == "critical" for a in triggers), True)
        check("the four trigger paths are covered", vias,
              ["credential", "http_basic_auth", "web_url", "web_url"])
        check_true("a credential alert names where it was planted",
                   any(a.get("planted_at") == "wiki" for a in triggers if a.get("via") == "credential"))
        check_true("no alert was raised for the normal root/hunter2 login",
                   not any(a.get("password") == "hunter2" for a in triggers))

        # --- webhook delivery ---
        hook_triggers = [a for a in _webhook_hits if a.get("kind") == "honeytoken_triggered"]
        check("all 4 alerts were delivered to the webhook", len(hook_triggers), 4)
        check_true("webhook payload carries the token id",
                   all(a.get("token_id") for a in hook_triggers))

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        webhook.shutdown()

    print()
    print(f"{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
