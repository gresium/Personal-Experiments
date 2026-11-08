#!/usr/bin/env python3
"""
Tests for real SSH credential capture, using paramiko as the attacking client.

Run:  python3 tests/test_ssh.py       (needs paramiko; skipped without it)
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time

try:
    import paramiko
except ImportError:
    print("SKIP  paramiko is not installed")
    raise SystemExit(0)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HONEYPOT = os.path.join(ROOT, "honeypot.py")
CLI = os.path.join(ROOT, "honeytokens.py")
HOST, PORT = "127.0.0.1", 43300
BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
failures = 0


def check(desc, ok):
    global failures
    print(("PASS  " if ok else "FAIL  ") + desc)
    failures += 0 if ok else 1


def start(cfg_path):
    proc = subprocess.Popen([sys.executable, HONEYPOT, "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):        # the first start generates host keys
        try:
            socket.create_connection((HOST, PORT), 0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    return proc


def stop(proc):
    proc.terminate()
    proc.wait(timeout=5)
    for _ in range(50):         # Windows can briefly accept on a dead process's port
        try:
            socket.create_connection((HOST, PORT), 0.2).close()
            time.sleep(0.1)
        except OSError:
            return


def attempt(user, password=None, key=None):
    """Returns (authenticated, remote version, host key fingerprint)."""
    t = paramiko.Transport((HOST, PORT))
    try:
        t.start_client(timeout=10)
        host_key = t.get_remote_server_key().asbytes()
        try:
            if key:
                t.auth_publickey(user, key)
            else:
                t.auth_password(user, password, fallback=False)
        except paramiko.AuthenticationException:
            pass
        return t.is_authenticated(), t.remote_version, host_key
    finally:
        t.close()


def read(tmp, name):
    time.sleep(0.3)
    try:
        with open(os.path.join(tmp, name), encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]
    except FileNotFoundError:
        return []


def main():
    tmp = tempfile.mkdtemp(prefix="hp-ssh-")
    cfg_path = os.path.join(tmp, "config.json")
    with open(cfg_path, "w") as f:
        json.dump({"log_dir": tmp, "state_dir": tmp, "conn_timeout": 5, "services": [
            {"name": "ssh", "bind": HOST, "port": PORT, "mode": "login", "banner": BANNER, "max_auth_tries": 3}]}, f)
    subprocess.check_output([sys.executable, CLI, "-c", cfg_path, "new", "credential",
                             "--username", "dbadmin", "--password", "S3cr3tDecoy"])
    proc = start(cfg_path)
    try:
        authed, version, key_one = attempt("root", "hunter2")
        check("wrong password is refused", not authed)
        check("client sees the configured banner", version == BANNER)
        logins = [e for e in read(tmp, "honeypot.log") if e["event"] == "login_attempt"]
        check("username and password captured",
              any(e["username"] == "root" and e["password"] == "hunter2" and e["src_ip"] == HOST for e in logins))
        check("no alert for an ordinary password", read(tmp, "alerts.log") == [])

        authed, _, _ = attempt("dbadmin", "S3cr3tDecoy")
        alerts = read(tmp, "alerts.log")
        check("honeytoken password is still refused", not authed)
        check("honeytoken fires a critical alert", len(alerts) == 1 and alerts[0]["severity"] == "critical")

        authed, _, _ = attempt("deploy", key=paramiko.ECDSAKey.generate())
        logins = [e for e in read(tmp, "honeypot.log") if e["event"] == "login_attempt"]
        check("public key refused and fingerprinted",
              not authed and any(e["username"] == "deploy" and e.get("key_fingerprint") for e in logins))

        hellos = [e for e in read(tmp, "honeypot.log") if e["event"] == "ssh_client_hello"]
        check("client fingerprint logged", hellos and hellos[0].get("hassh") and "paramiko" in hellos[0]["client_version"].lower())

        s = socket.create_connection((HOST, PORT), 5)
        s.settimeout(3)
        s.recv(200)
        s.sendall(b"SSH-2.0-OpenSSH_8.2p1\r\n")
        time.sleep(0.4)
        offer = s.recv(4096)
        s.close()
        check("offer matches OpenSSH 8.2's era",
              b"curve25519-sha256,curve25519-sha256@libssh.org" in offer
              and b"mlkem" not in offer and b"kex-strict" not in offer)

        t = paramiko.Transport((HOST, PORT))
        t.start_client(timeout=10)
        for _ in range(3):
            try:
                t.auth_password("root", "guess", fallback=False)
            except (paramiko.AuthenticationException, paramiko.SSHException, EOFError):
                pass
        time.sleep(0.6)
        check("connection dropped after max_auth_tries", not t.is_active())
        t.close()

        s = socket.create_connection((HOST, PORT), 5)
        s.settimeout(3)
        data = b""
        while b"login:" not in data:
            data += s.recv(1024)
        check("raw connection gets the banner, then the line login", data.startswith(BANNER.encode()))
        s.sendall(b"rawuser\nrawpass\n")
        time.sleep(0.3)
        s.close()
        logins = [e for e in read(tmp, "honeypot.log") if e["event"] == "login_attempt"]
        check("raw line login still captured", any(e["username"] == "rawuser" for e in logins))
    finally:
        stop(proc)

    proc = start(cfg_path)
    try:
        _, _, key_two = attempt("root", "x")
        check("host key is the same after a restart", key_one == key_two)
    finally:
        stop(proc)

    print(f"\n{'all passed' if not failures else str(failures) + ' failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
