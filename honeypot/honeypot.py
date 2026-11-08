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
import re
import signal
import socket
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone
from email.utils import formatdate
from logging.handlers import RotatingFileHandler
from urllib.parse import unquote

import alerts
import protocols
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
    "conn_lifetime": 120,           # hard limit, so slow-drip clients can't hold a slot
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

_EOL = re.compile(rb"[\r\n]")
# Telnet option negotiation that clients mix into the login stream.
_TELNET_IAC = re.compile(rb"\xff(?:[\xfb-\xfe].|\xfa.*?\xff\xf0|[\xf0-\xf9])", re.DOTALL)


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
    ip, port = client[:2]   # IPv6 addresses are 4-tuples
    entry = {"ts": now_iso(), "service": service, "event": event,
             "src_ip": ip, "src_port": port, **fields}
    # ensure_ascii also escapes C1 control characters that can drive a terminal.
    log.info(json.dumps(entry, ensure_ascii=True, default=str))
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
            self._deadline = time.monotonic() + self.limits["conn_lifetime"]
            self._buf = bytearray()
            self._skip_lf = False
            self.eof = False
            record(name, "connect", self.client_address)
            mode = self.service.get("mode", "banner")
            if mode == "login":
                self._do_login(self.service)
            elif mode == "http":
                self._do_http(self.service)
            elif mode in protocols.HANDLERS:
                protocols.HANDLERS[mode](self, self.service)
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

    def event(self, event: str, **fields) -> None:
        record(self.service.get("name", "service"), event, self.client_address, **fields)

    def login(self, user: str, password: str, **extra) -> dict | None:
        """Record a login attempt and alert if it used a honeytoken."""
        token = STORE.find_credential(user, password) if STORE else None
        self.event("login_attempt", username=user, password=password,
                   honeytoken=token["id"] if token else None, **extra)
        if token:
            self._fire(token, "credential", username=user, password=password)
        return token

    def _fire(self, token: dict, token_kind: str, **extra) -> None:
        ip, port = self.client_address[:2]
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
        self.send(svc.get("banner", ""))
        line = self.recv_line()
        if line:
            self.event("data", data=line)

    def _login_line(self) -> str:
        return _TELNET_IAC.sub(b"", self._recv_line_bytes()).decode("utf-8", "replace")

    def _do_login(self, svc: dict) -> None:
        banner = svc.get("banner", "")
        if banner:
            self.send(banner if banner.endswith(("\r\n", "\n")) else banner + "\r\n")
        if banner.startswith("SSH-"):
            # Real SSH clients announce themselves straight away, and would choke
            # on a text prompt. Anything else falls through to the line login.
            self._fill(timeout=float(svc.get("ssh_hello_wait", 1.0)))
            if self._buf.startswith(b"SSH-"):
                protocols.ssh_client(self, svc, self.recv_line())
                return
        for _ in range(max(1, int(svc.get("login_rounds", 3)))):
            self.send(svc.get("user_prompt", "login: "))
            user = self._login_line()
            if not user and self.eof:
                break       # a bare connect is not a login attempt
            self.send(svc.get("pass_prompt", "Password: "))
            pw = self._login_line()
            self.login(user, pw)
            self.send(svc.get("deny", "\r\nAccess denied\r\n"))
            if self.eof or (user == "" and pw == ""):
                break

    def _do_http(self, svc: dict) -> None:
        raw = self._recv_until_blank_line()
        if not raw:
            return
        lines = re.split(r"\r?\n", re.split(r"\r?\n\r?\n", raw, maxsplit=1)[0])
        request_line = lines[0] if lines else ""
        parts = request_line.split()
        path = parts[1] if len(parts) >= 2 else ""
        headers = {}
        for h in lines[1:]:
            if ":" in h:
                k, _, v = h.partition(":")
                headers[k.strip().lower()] = v.strip()

        web_token = None
        if STORE:
            web_token = STORE.find_web(path) or STORE.find_web(unquote(path))

        # Basic-auth credentials can also be honeytokens.
        cred_token = None
        creds = {}
        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "replace")
                u, _, p = decoded.partition(":")
                creds = {"username": u, "password": p}
                cred_token = STORE.find_credential(u, p) if STORE else None
            except Exception:
                pass

        token = web_token or cred_token
        self.event("http_request",
                   request_line=request_line, path=path,
                   user_agent=headers.get("user-agent", ""),
                   host=headers.get("host", ""),
                   authorization=auth, **creds,
                   honeytoken=token["id"] if token else None)

        if web_token:
            self._fire(web_token, "web_url", path=path,
                       user_agent=headers.get("user-agent", ""))
            self._serve_token(web_token, svc)
            return
        if cred_token:
            self._fire(cred_token, "http_basic_auth", **creds)

        self.send(protocols.http_401(svc, path, headers.get("host", "localhost")))

    def _serve_token(self, token: dict, svc: dict) -> None:
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
            f"Date: {formatdate(usegmt=True)}\r\n"
            f"Server: {svc.get('server', 'Apache/2.4.52 (Ubuntu)')}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n"
        ).encode("utf-8")
        try:
            self.request.sendall(header + data)
        except OSError:
            pass

    # -- bounded I/O ------------------------------------------------------- #

    def send(self, text: str) -> None:
        self.send_bytes(text.encode("utf-8", "replace"))

    def send_bytes(self, data: bytes) -> None:
        try:
            self.request.sendall(data)
        except OSError:
            pass

    def _fill(self, want: int = 1024, timeout: float | None = None) -> bool:
        """Read more into the buffer. False once the connection is finished.

        A timeout ends the connection but keeps what already arrived, so a
        client that stalls part-way is still logged. Passing `timeout` makes a
        short, non-final wait instead.
        """
        if self.eof:
            return False
        room = min(want, self._bytes_left)
        left = self._deadline - time.monotonic()
        if room <= 0 or left <= 0:
            self.eof = True
            return False
        try:
            self.request.settimeout(min(timeout or self.limits["conn_timeout"], left))
            chunk = self.request.recv(room)
        except socket.timeout:
            if timeout is not None:
                return False
            chunk = b""
        except OSError:
            chunk = b""
        if not chunk:
            self.eof = True
            return False
        self._bytes_left -= len(chunk)
        self._buf += chunk
        return True

    def _drop_line_end(self) -> None:
        """Consume the second half of a CRLF or CR NUL that followed a line."""
        if self._skip_lf and self._buf:
            if self._buf[0] in (0, 10):
                del self._buf[0]
            self._skip_lf = False

    def _recv_line_bytes(self) -> bytes:
        cap = self.limits["max_line_bytes"]
        while True:
            self._drop_line_end()
            found = _EOL.search(self._buf, 0, cap)
            if found:
                end = found.start()
                line = bytes(self._buf[:end])
                was_cr = self._buf[end] == 13
                del self._buf[:end + 1]
                self._skip_lf = was_cr
                return line
            if len(self._buf) >= cap or not self._fill():
                line = bytes(self._buf[:cap])
                del self._buf[:cap]
                return line

    def recv_line(self) -> str:
        return self._recv_line_bytes().decode("utf-8", "replace")

    def recv_exact(self, count: int) -> bytes:
        """Up to `count` bytes; fewer only if the connection has ended."""
        self._drop_line_end()
        while len(self._buf) < count + self._skip_lf:
            if not self._fill(count + self._skip_lf - len(self._buf)):
                break
            self._drop_line_end()
        data = bytes(self._buf[:count])
        del self._buf[:count]
        return data

    def _recv_until_blank_line(self) -> str:
        while b"\r\n\r\n" not in self._buf and b"\n\n" not in self._buf:
            if not self._fill():
                break
        data = self._buf.decode("utf-8", "replace")
        self._buf.clear()
        return data


# --------------------------------------------------------------------------- #
# Server wiring
# --------------------------------------------------------------------------- #

class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    # On Windows SO_REUSEADDR lets a second process share a port that is in use.
    allow_reuse_address = os.name != "nt"
    daemon_threads = True

    def server_bind(self) -> None:
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class ThreadingTCPServer6(ThreadingTCPServer):
    address_family = socket.AF_INET6


def make_server(svc: dict, limits: dict) -> ThreadingTCPServer:
    handler = type(f"Handler_{svc['name']}", (HoneypotHandler,),
                   {"service": svc, "limits": limits})
    bind = svc.get("bind", "0.0.0.0")
    cls = ThreadingTCPServer6 if ":" in bind else ThreadingTCPServer
    return cls((bind, int(svc["port"])), handler)


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

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read config {args.config}: {exc}", file=sys.stderr)
        return 1
    if os.name == "posix":
        os.umask(0o027)     # logs hold captured credentials; keep them off world-read
    log_path, alert_path = setup_logging(cfg)

    global _conn_slots, STORE
    _conn_slots = threading.Semaphore(int(cfg["max_connections"]))
    STORE = TokenStore(resolve_token_store(cfg))
    limits = {k: cfg[k] for k in ("conn_timeout", "conn_lifetime",
                                  "max_line_bytes", "max_conn_bytes")}

    servers: list[ThreadingTCPServer] = []
    started: list[str] = []
    for svc in cfg["services"]:
        try:
            server = make_server(svc, limits)
        except (OSError, KeyError, ValueError, TypeError) as exc:
            print(f"ERROR: cannot start {svc.get('name')} on "
                  f"{svc.get('bind','0.0.0.0')}:{svc.get('port')}: {exc!r}", file=sys.stderr)
            continue
        servers.append(server)
        started.append(svc["name"])
        print(f"Listening: {svc['name']} on {svc.get('bind','0.0.0.0')}:{svc['port']} "
              f"(mode={svc.get('mode','banner')})", flush=True)

    if not servers:
        print("No services could be started. Check the ports and config.", file=sys.stderr)
        return 1

    # Drop root before accepting anything from the network.
    maybe_drop_privileges(cfg)
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"Honeypot running.\n  activity : {log_path}\n  alerts   : {alert_path}\n"
          f"  tokens   : {STORE.path} ({len(STORE.all())} loaded)", flush=True)
    record("honeypot", "startup", ("-", 0),
           services=started, tokens_loaded=len(STORE.all()))

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
