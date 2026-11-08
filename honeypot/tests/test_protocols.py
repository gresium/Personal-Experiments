#!/usr/bin/env python3
"""
Regression tests for login parsing and the protocol dialogues in protocols.py.

Starts the honeypot on loopback and speaks each protocol over a raw socket.
Run:  python3 tests/test_protocols.py       (no third-party dependencies)
"""

import base64
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HONEYPOT = os.path.join(ROOT, "honeypot.py")
CLI = os.path.join(ROOT, "honeytokens.py")
HOST = "127.0.0.1"
BASE = 43100
MODES = ["telnet", "ssh", "http", "ftp", "smtp", "redis", "postgres", "vnc",
         "mysql", "dns", "rdp", "nfs", "es"]
PORT = {name: BASE + i for i, name in enumerate(MODES)}
TOKEN = (b"dbadmin", b"S3cr3tDecoy")
failures = 0


def check(desc, ok):
    global failures
    print(("PASS  " if ok else "FAIL  ") + desc)
    failures += 0 if ok else 1


def conn(name):
    return socket.create_connection((HOST, PORT[name]), 3)


def read(s, wait=0.3):
    s.settimeout(wait)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    return data


def service(name, mode, **extra):
    return {"name": name, "bind": HOST, "port": PORT[name], "mode": mode, **extra}


def main():
    tmp = tempfile.mkdtemp(prefix="hp-proto-")
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as f:
        json.dump({"log_dir": tmp, "state_dir": tmp, "conn_timeout": 1, "conn_lifetime": 3, "services": [
            service("telnet", "login", banner="Ubuntu"), service("ssh", "login", banner="SSH-2.0-OpenSSH_8.2p1"),
            service("http", "http"), service("ftp", "ftp"), service("smtp", "smtp"),
            service("redis", "redis"), service("postgres", "postgres"), service("vnc", "vnc"),
            service("mysql", "mysql"), service("dns", "dns"), service("rdp", "rdp"), service("nfs", "nfs"),
            service("es", "http", profile="elasticsearch"),
        ]}, f)
    subprocess.check_output([sys.executable, CLI, "-c", cfg_path, "new", "credential",
                             "--username", TOKEN[0].decode(), "--password", TOKEN[1].decode()])
    proc = subprocess.Popen([sys.executable, HONEYPOT, "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                conn("es").close()
                break
            except OSError:
                time.sleep(0.1)

        def alerts():
            time.sleep(0.2)
            try:
                with open(os.path.join(tmp, "alerts.log"), encoding="utf-8") as f:
                    return [json.loads(x) for x in f if x.strip()]
            except FileNotFoundError:
                return []

        def fires(desc, action):
            before = len(alerts())
            action()
            check(desc, len(alerts()) == before + 1)

        def telnet(raw):
            def go():
                s = conn("telnet")
                read(s)
                s.sendall(raw)
                read(s, 0.5)
                s.close()
            return go

        creds = TOKEN[0] + b"\r\n" + TOKEN[1] + b"\r\n"
        fires("pipelined username+password in one packet", telnet(creds))
        fires("bare LF line endings", telnet(TOKEN[0] + b"\n" + TOKEN[1] + b"\n"))
        fires("telnet CR NUL line endings", telnet(TOKEN[0] + b"\r\0" + TOKEN[1] + b"\r\0"))
        fires("telnet option bytes are ignored", telnet(b"\xff\xfd\x18" + creds))

        s = conn("telnet"); read(s); s.close(); time.sleep(0.2)
        s = conn("telnet"); read(s); s.sendall(b"stalled\r\n"); time.sleep(1.4); s.close(); time.sleep(0.2)
        with open(os.path.join(tmp, "honeypot.log"), encoding="utf-8") as f:
            logins = [e for e in map(json.loads, f) if e["event"] == "login_attempt"]
        check("bare connect is not a login attempt", not any(e["username"] == "" for e in logins))
        check("username kept when the client stalls", any(e["username"] == "stalled" for e in logins))

        s = conn("ssh"); read(s, 0.1); s.sendall(b"SSH-2.0-TestClient_1.0\r\n")
        reply = read(s, 0.4)
        names = b"curve25519-sha256"
        kex = b"\x14" + b"\0" * 16 + b"".join(struct.pack(">I", len(names)) + names for _ in range(10)) + b"\0" * 5
        s.sendall(struct.pack(">IB", len(kex) + 5, 4) + kex + b"\0" * 4); read(s, 0.4); s.close(); time.sleep(0.2)
        check("real SSH client gets KEXINIT, not a text prompt", b"login:" not in reply and b"curve25519" in reply)
        with open(os.path.join(tmp, "honeypot.log"), encoding="utf-8") as f:
            hello = [e for e in map(json.loads, f) if e["event"] == "ssh_client_hello"]
        check("SSH client version and HASSH are logged",
              hello and hello[-1]["client_version"] == "SSH-2.0-TestClient_1.0" and hello[-1].get("hassh"))

        s = conn("ftp"); banner = read(s); s.sendall(b"USER " + TOKEN[0] + b"\r\n"); read(s)
        before = len(alerts())
        s.sendall(b"PASS " + TOKEN[1] + b"\r\n"); reply = read(s); s.close()
        check("FTP banner and refusal", banner.startswith(b"220") and reply.startswith(b"530"))
        check("FTP honeytoken fires", len(alerts()) == before + 1)

        s = conn("smtp"); banner = read(s); s.sendall(b"EHLO x\r\n"); ehlo = read(s)
        plain = base64.b64encode(b"\0" + TOKEN[0] + b"\0" + TOKEN[1])
        before = len(alerts())
        s.sendall(b"AUTH PLAIN " + plain + b"\r\n"); auth = read(s)
        s.sendall(b"RCPT TO:<x@example.org>\r\n"); rcpt = read(s); s.close()
        check("SMTP banner, EHLO and auth refusal",
              banner.startswith(b"220") and b"AUTH PLAIN" in ehlo and auth.startswith(b"535"))
        check("SMTP honeytoken fires", len(alerts()) == before + 1)
        check("SMTP never relays", rcpt.startswith(b"554"))

        s = conn("redis"); s.sendall(b"*1\r\n$4\r\nPING\r\n"); ping = read(s)
        before = len(alerts())
        s.sendall(b"AUTH " + TOKEN[0] + b" " + TOKEN[1] + b"\r\n"); auth = read(s); s.close()
        check("Redis requires auth", ping.startswith(b"-NOAUTH") and auth.startswith(b"-WRONGPASS"))
        check("Redis honeytoken fires", len(alerts()) == before + 1)

        s = conn("redis")
        before = len(alerts())
        s.sendall(b"*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n"
                  % (len(TOKEN[0]), TOKEN[0], len(TOKEN[1]), TOKEN[1]))
        reply = read(s); s.close()
        check("Redis RESP-encoded AUTH fires", reply.startswith(b"-WRONGPASS") and len(alerts()) == before + 1)

        s = conn("postgres")
        params = b"user\0" + TOKEN[0] + b"\0database\0prod\0\0"
        s.sendall(struct.pack(">II", 8 + len(params), 196608) + params)
        auth = read(s)
        body = TOKEN[1] + b"\0"
        before = len(alerts())
        s.sendall(b"p" + struct.pack(">I", 4 + len(body)) + body); reply = read(s); s.close()
        check("PostgreSQL asks for a password and refuses", auth[:1] == b"R" and b"28P01" in reply)
        check("PostgreSQL honeytoken fires", len(alerts()) == before + 1)

        s = conn("vnc"); banner = read(s); s.sendall(b"RFB 003.008\n"); types = read(s); s.sendall(b"\x02")
        challenge = read(s); s.sendall(b"\0" * 16); result = read(s); s.close()
        check("VNC handshake and refusal", banner == b"RFB 003.008\n" and types == b"\x01\x02"
              and len(challenge) == 16 and result[:4] == b"\0\0\0\1")

        s = conn("mysql"); greeting = read(s); s.close()
        check("MySQL protocol 10 greeting", greeting[4] == 10 and b"mysql_native_password" in greeting)

        s = conn("dns")
        q = b"\x12\x34\x01\0\0\1\0\0\0\0\0\0\x07example\x03com\0\0\1\0\1"
        s.sendall(struct.pack(">H", len(q)) + q); reply = read(s); s.close()
        check("DNS answers REFUSED with the same id", reply[2:4] == b"\x12\x34" and reply[5] & 15 == 5)

        s = conn("rdp")
        cr = b"\x0e\xe0\0\0\0\0\0Cookie: mstshash=admin\r\n\x01\0\x08\0\x03\0\0\0"
        cr = bytes([len(cr) - 1]) + cr[1:]
        s.sendall(b"\x03\0" + struct.pack(">H", 4 + len(cr)) + cr); reply = read(s); s.close()
        check("RDP connection confirm picks TLS", reply[:1] == b"\x03" and reply[5] == 0xD0 and reply[11] == 2)

        s = conn("nfs")
        call = struct.pack(">IIIIII", 7, 0, 2, 100003, 3, 0) + b"\0" * 16
        s.sendall(struct.pack(">I", 0x80000000 | len(call)) + call); reply = read(s); s.close()
        check("NFS NULL call succeeds", reply[4:8] == struct.pack(">I", 7) and reply[-4:] == b"\0\0\0\0")

        s = conn("es"); s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); reply = read(s); s.close()
        check("Elasticsearch security error", b"401" in reply[:20] and b"security_exception" in reply)

        s = conn("http"); s.sendall(b"GET / HTTP/1.1\nHost: x\nUser-Agent: UA-LF\n\n"); read(s); s.close()
        time.sleep(0.2)
        with open(os.path.join(tmp, "honeypot.log"), encoding="utf-8") as f:
            reqs = [e for e in map(json.loads, f) if e["event"] == "http_request"]
        check("LF-only HTTP requests are parsed", reqs[-1]["user_agent"] == "UA-LF")

        check("honeypot survived everything", proc.poll() is None)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    print(f"\n{'all passed' if not failures else str(failures) + ' failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
