#!/usr/bin/env python3
"""
Advanced low-interaction honeypot with honeytoken detection.

Listens on one or more TCP ports, pretends to be common services (SSH, Telnet,
HTTP), and writes a structured JSON log of every connection and login attempt.
It NEVER grants access and NEVER runs anything the client sends.

On top of that it watches for *honeytokens* (see tokens.py and honeytokens.py):
decoy credentials and unique canary URLs you plant around your environment.
Because nothing legitimate ever uses them, any hit is a high-confidence
intrusion signal and raises a critical alert (alert log + optional webhook).

Runs on Linux and Windows with only the Python standard library (3.8+).

Safe-use notes:
  * Run it only on systems you own or are authorised to test.
  * Everything a client sends is attacker-controlled. It is stored as JSON
    (which escapes it) and printed with control characters stripped.
  * Captured credentials are evidence, not a credential store. Don't reuse them.
  * Expose only the honeypot's own ports. Never put a real service behind it.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import platform
import signal
import socket
import socketserver
import sys
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

import alerts
from tokens import TokenStore

# --------------------------------------------------------------------------- #
# Defaults (override with a config file; see config.example.json)
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG = {
    "log_dir": None,
    "log_basename": "honeypot.log",
    "alert_basename": "alerts.log",
    "log_max_bytes": 5 * 1024 * 1024,
    "log_backups": 5,
    "state_dir": None,              # holds tokens.json and the decoys/ folder
    "token_store": None,            # explicit path; overrides state_dir default
    "decoy_dir": None,
    "webhook_url": None,            # POST alerts here (Slack/Teams/SIEM/anything)
    "webhook_min_interval": 5,
    "max_connections": 200,
    "conn_timeout": 20,
    "max_line_bytes": 4096,
    "max_conn_bytes": 16384,
    "drop_privileges_to": None,
    "services": [
        {"name": "ssh", "bind": "0.0.0.0", "port": 2222, "mode": "login",
         "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
         "user_prompt": "login: ", "pass_prompt": "Password: ",
         "deny": "\r\nPermission denied, please try again.\r\n", "login_rounds": 3},
        {"name": "telnet", "bind": "0.0.0.0", "port": 2323, "mode": "login",
         "banner": "\r\nUbuntu 22.04.3 LTS\r\n",
         "user_prompt": "login: ", "pass_prompt": "Password: ",
         "deny": "\r\nLogin incorrect\r\n", "login_rounds": 3},
        {"name": "http", "bind": "0.0.0.0", "port": 8080, "mode": "http"},
    ],
}

# A 1x1 transparent GIF, returned for canary-URL hits so image/web-bug embeds work.
PIXEL_GIF = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")

log = logging.getLogger("honeypot")
STORE: TokenStore | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_log_dir() -> str:
    if platform.system() == "Windows":
        base = os.environ.get("PROGRAMDATA", os.path.expanduser("~"))
        return os.path.join(base, "Honeypot", "logs")
    for candidate in ("/var/log/honeypot", os.path.expanduser("~/honeypot-logs")):
        try:
            os.makedirs(candidate, exist_ok=True)
            t = os.path.join(candidate, ".write-test")
            open(t, "w").close()
            os.remove(t)
            return candidate
        except OSError:
            continue
    return os.path.expanduser("~")


def default_state_dir() -> str:
    if platform.system() == "Windows":
        base = os.environ.get("PROGRAMDATA", os.path.expanduser("~"))
        return os.path.join(base, "Honeypot", "state")
    for candidate in ("/var/lib/honeypot", os.path.expanduser("~/honeypot-state")):
        try:
            os.makedirs(candidate, exist_ok=True)
            t = os.path.join(candidate, ".write-test")
            open(t, "w").close()
            os.remove(t)
            return candidate
        except OSError:
            continue
    return os.path.expanduser("~")


def printable(text: str, limit: int = 200) -> str:
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)[:limit]


def record(service: str, event: str, client, **fields) -> None:
    ip, port = client
    entry = {"ts": now_iso(), "service": service, "event": event,
             "src_ip": ip, "src_port": port, **fields}
    log.info(json.dumps(entry, ensure_ascii=False, default=str))
    summary = f"[{service}] {event} from {ip}:{port}"
    if "username" in fields or "password" in fields:
        summary += f"  user={printable(str(fields.get('username','')))!r}" \
                   f" pass={printable(str(fields.get('password','')))!r}"
    elif "request_line" in fields:
        summary += f"  {printable(str(fields['request_line']))!r}"
    if fields.get("honeytoken"):
        summary += "  <<< HONEYTOKEN"
    print(summary, flush=True)


_conn_slots: threading.Semaphore | None = None


# --------------------------------------------------------------------------- #
# Connection handler
# --------------------------------------------------------------------------- #

class HoneypotHandler(socketserver.BaseRequestHandler):
    service: dict = {}
    limits: dict = {}

    def handle(self) -> None:
        assert _conn_slots is not None
        name = self.service.get("name", "service")
        if not _conn_slots.acquire(blocking=False):
            record(name, "rejected_capacity", self.client_address)
            return
        try:
            self.request.settimeout(self.limits["conn_timeout"])
            self._bytes_left = self.limits["max_conn_bytes"]
            record(name, "connect", self.client_address)
            mode = self.service.get("mode", "banner")
            if mode == "login":
                self._do_login(self.service)
            elif mode == "http":
                self._do_http(self.service)
            else:
                self._do_banner(self.service)
        except (socket.timeout, OSError):
            pass
        except Exception as exc:
            record(name, "error", self.client_address, detail=printable(repr(exc)))
        finally:
            record(name, "disconnect", self.client_address)
            _conn_slots.release()

    # -- honeytoken alerting ---------------------------------------------- #

    def _fire(self, token: dict, token_kind: str, **extra) -> None:
        ip, port = self.client_address
        alerts.dispatch({
            "severity": "critical",
            "kind": "honeytoken_triggered",
            "token_id": token.get("id"),
            "token_type": token.get("type"),
            "label": token.get("label"),
            "planted_at": token.get("planted_at"),
            "service": self.service.get("name"),
            "via": token_kind,
            "src_ip": ip, "src_port": port,
            **extra,
        })

    # -- modes ------------------------------------------------------------- #

    def _do_banner(self, svc: dict) -> None:
        self._send(svc.get("banner", ""))
        line = self._recv_line()
        if line:
            record(svc["name"], "data", self.client_address, data=line)

    def _do_login(self, svc: dict) -> None:
        if svc.get("banner"):
            b = svc["banner"]
            self._send(b if b.endswith(("\r\n", "\n")) else b + "\r\n")
        for _ in range(max(1, int(svc.get("login_rounds", 3)))):
            self._send(svc.get("user_prompt", "login: "))
            user = self._recv_line()
            self._send(svc.get("pass_prompt", "Password: "))
            pw = self._recv_line()
            token = STORE.find_credential(user, pw) if STORE else None
            record(svc["name"], "login_attempt", self.client_address,
                   username=user, password=pw,
                   honeytoken=token["id"] if token else None)
            if token:
                self._fire(token, "credential", username=user, password=pw)
            self._send(svc.get("deny", "\r\nAccess denied\r\n"))
            if user == "" and pw == "":
                break

    def _do_http(self, svc: dict) -> None:
        raw = self._recv_until_blank_line()
        if not raw:
            return
        lines = raw.split("\r\n")
        request_line = lines[0] if lines else ""
        parts = request_line.split()
        path = parts[1] if len(parts) >= 2 else ""
        headers = {}
        for h in lines[1:]:
            if ":" in h:
                k, _, v = h.partition(":")
                headers[k.strip().lower()] = v.strip()

        web_token = STORE.find_web(path) if STORE else None

        # Basic-auth credentials can also be honeytokens.
        cred_token = None
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic ") and STORE:
            try:
                decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
                u, _, p = decoded.partition(":")
                cred_token = STORE.find_credential(u, p)
            except Exception:
                pass

        token = web_token or cred_token
        record(svc["name"], "http_request", self.client_address,
               request_line=request_line, path=path,
               user_agent=headers.get("user-agent", ""),
               host=headers.get("host", ""),
               authorization=auth,
               honeytoken=token["id"] if token else None)

        if web_token:
            self._fire(web_token, "web_url", path=path,
                       user_agent=headers.get("user-agent", ""))
            self._serve_token(web_token)
            return
        if cred_token:
            self._fire(cred_token, "http_basic_auth")

        body = "<!doctype html><title>401</title><h1>401 Unauthorized</h1>"
        self._send(
            "HTTP/1.1 401 Unauthorized\r\n"
            'WWW-Authenticate: Basic realm="Restricted"\r\n'
            "Server: Apache/2.4.52 (Ubuntu)\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n" + body)

    def _serve_token(self, token: dict) -> None:
        """Return believable content for a canary URL so the hit looks successful."""
        data = PIXEL_GIF
        ctype = "image/gif"
        decoy = token.get("file")
        if decoy and os.path.isfile(decoy):
            try:
                with open(decoy, "rb") as f:
                    data = f.read(self.limits["max_conn_bytes"])
                ctype = "text/plain; charset=utf-8"
            except OSError:
                pass
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache/2.4.52 (Ubuntu)\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n"
        ).encode("utf-8")
        try:
            self.request.sendall(header + data)
        except OSError:
            pass

    # -- bounded I/O ------------------------------------------------------- #

    def _send(self, text: str) -> None:
        try:
            self.request.sendall(text.encode("utf-8", "replace"))
        except OSError:
            pass

    def _recv_line(self) -> str:
        cap = min(self.limits["max_line_bytes"], max(0, self._bytes_left))
        data = bytearray()
        while len(data) < cap:
            chunk = self.request.recv(min(1024, cap - len(data)))
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk or b"\r" in chunk:
                break
        self._bytes_left -= len(data)
        return data.decode("utf-8", "replace").strip("\r\n")

    def _recv_until_blank_line(self) -> str:
        data = bytearray()
        cap = min(self.limits["max_conn_bytes"], max(0, self._bytes_left))
        while len(data) < cap:
            chunk = self.request.recv(min(1024, cap - len(data)))
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data or b"\n\n" in data:
                break
        self._bytes_left -= len(data)
        return data.decode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# Server wiring
# --------------------------------------------------------------------------- #

class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(svc: dict, limits: dict) -> ThreadingTCPServer:
    handler = type(f"Handler_{svc['name']}", (HoneypotHandler,),
                   {"service": svc, "limits": limits})
    return ThreadingTCPServer((svc.get("bind", "0.0.0.0"), int(svc["port"])), handler)


def load_config(path: str | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
        cfg.update({k: v for k, v in user.items() if k != "services"})
        if "services" in user:
            cfg["services"] = user["services"]
    return cfg


def setup_logging(cfg: dict) -> tuple[str, str]:
    log_dir = cfg["log_dir"] or default_log_dir()
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, cfg["log_basename"])
    h = RotatingFileHandler(log_path, maxBytes=int(cfg["log_max_bytes"]),
                            backupCount=int(cfg["log_backups"]), encoding="utf-8")
    h.setFormatter(logging.Formatter("%(message)s"))
    log.setLevel(logging.INFO)
    log.addHandler(h)
    log.propagate = False

    alert_path = os.path.join(log_dir, cfg["alert_basename"])
    alerts.setup(alert_path, cfg.get("webhook_url"),
                 cfg.get("webhook_min_interval", 5),
                 cfg["log_max_bytes"], cfg["log_backups"])
    return log_path, alert_path


def resolve_token_store(cfg: dict) -> str:
    if cfg.get("token_store"):
        return cfg["token_store"]
    return os.path.join(cfg.get("state_dir") or default_state_dir(), "tokens.json")


def maybe_drop_privileges(cfg: dict) -> None:
    user = cfg.get("drop_privileges_to")
    if not user or platform.system() == "Windows" or not hasattr(os, "setuid"):
        return
    if os.getuid() != 0:
        return
    import grp
    import pwd
    pw = pwd.getpwnam(user)
    os.setgroups([g.gr_gid for g in grp.getgrall() if user in g.gr_mem])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    os.umask(0o077)
    print(f"Dropped privileges to {user} (uid={pw.pw_uid})", flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Advanced honeypot with honeytokens.")
    parser.add_argument("-c", "--config", help="path to a JSON config file")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    log_path, alert_path = setup_logging(cfg)

    global _conn_slots, STORE
    _conn_slots = threading.Semaphore(int(cfg["max_connections"]))
    STORE = TokenStore(resolve_token_store(cfg))
    limits = {k: cfg[k] for k in ("conn_timeout", "max_line_bytes", "max_conn_bytes")}

    servers: list[ThreadingTCPServer] = []
    for svc in cfg["services"]:
        try:
            server = make_server(svc, limits)
        except OSError as exc:
            print(f"ERROR: cannot bind {svc.get('name')} on "
                  f"{svc.get('bind','0.0.0.0')}:{svc.get('port')}: {exc}", file=sys.stderr)
            continue
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"Listening: {svc['name']} on {svc.get('bind','0.0.0.0')}:{svc['port']} "
              f"(mode={svc.get('mode','banner')})", flush=True)

    if not servers:
        print("No services could be started. Check the ports and config.", file=sys.stderr)
        return 1

    maybe_drop_privileges(cfg)
    print(f"Honeypot running.\n  activity : {log_path}\n  alerts   : {alert_path}\n"
          f"  tokens   : {STORE.path} ({len(STORE.all())} loaded)", flush=True)
    record("honeypot", "startup", ("-", 0),
           services=[s.get("name") for s in cfg["services"]],
           tokens_loaded=len(STORE.all()))

    stop = threading.Event()
    for sig in ("SIGINT", "SIGTERM"):
        if hasattr(signal, sig):
            try:
                signal.signal(getattr(signal, sig), lambda *_: stop.set())
            except (ValueError, OSError):
                pass
    try:
        while not stop.is_set():
            stop.wait(1)
    except KeyboardInterrupt:
        pass

    print("\nShutting down...", flush=True)
    record("honeypot", "shutdown", ("-", 0))
    for server in servers:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
