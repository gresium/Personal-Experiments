#!/usr/bin/env python3
"""
Fake service dialogues for the honeypot.

Each function speaks enough of one real protocol for a client or scanner to
believe it, records what the client offered, then refuses. None of them grants
access, relays anything, stores data or runs anything a client sends.

Each takes the connection handler `h` (see honeypot.HoneypotHandler) and the
service's config dict. All reads go through the handler's bounded I/O, so the
line, connection-byte and lifetime caps apply. Malformed binary input raises
IndexError/struct.error, which the handler records as an "error" event.

Where a protocol reveals the password (SSH, FTP, SMTP, MySQL, Redis, PostgreSQL
and LDAP) a credential honeytoken can fire. MongoDB, SMB and VNC only send a
challenge response, and RDP encrypts it, so those log what they can.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import os
import re
import ssl
import struct
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from email.utils import formatdate

try:
    import paramiko
    # Hostile clients trigger constant paramiko errors; those aren't log material.
    logging.getLogger("paramiko").addHandler(logging.NullHandler())
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
except Exception:   # a missing or broken install must not stop the other services
    paramiko = None

MAX_COMMANDS = 32
SSH_MAX_BYTES = 256 * 1024
_ssh_keys: list = []
# Key exchange is CPU-heavy and each session adds a thread, so cap them.
_ssh_slots = threading.BoundedSemaphore(64)
_tls_context = None
_rsa_key = None


def _limit(h) -> int:
    return h.limits["max_conn_bytes"]


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #

def load_tls(directory: str, hostname: str) -> None:
    """Load or create a self-signed certificate, like a distro's snakeoil cert."""
    global _tls_context, _rsa_key
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except Exception:
        return
    cert_path, key_path = os.path.join(directory, "tls_cert.pem"), os.path.join(directory, "tls_key.pem")
    try:
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=412)).not_valid_after(now + timedelta(days=3238))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                    .sign(key, hashes.SHA256()))
            os.makedirs(directory, exist_ok=True)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "rb") as f:
            _rsa_key = serialization.load_pem_private_key(f.read(), password=None)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        _tls_context = context
    except (OSError, ValueError, ssl.SSLError) as exc:
        print(f"WARNING: TLS certificate in {directory}: {exc}", file=sys.stderr, flush=True)


def _context_for(svc: dict):
    if svc.get("tls_cert"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(svc["tls_cert"], svc.get("tls_key"))
        return context
    return _tls_context


def _start_tls(h, svc: dict) -> bool:
    context = _context_for(svc)
    if context is None:
        return False
    try:
        h.request = context.wrap_socket(h.request, server_side=True)
    except OSError as exc:
        h.event("tls_error", detail=repr(exc)[:200])
        h.eof = True
        return False
    h.tls = True
    h._buf.clear()
    return True


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #

# Default server proposal of OpenSSH 8.2p1, in its order.
_SSH_ALGOS = [
    "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
    "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
    "diffie-hellman-group14-sha256",
    "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519",
    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
    "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    "none,zlib@openssh.com", "none,zlib@openssh.com", "", "",
]


def _kexinit_fields(body: bytes) -> dict:
    if body[:1] != b"\x14":
        return {}
    off, lists = 17, []
    for _ in range(10):
        n = struct.unpack(">I", body[off:off + 4])[0]
        lists.append(body[off + 4:off + 4 + n].decode("ascii", "replace"))
        off += 4 + n
    # HASSH: a stable fingerprint of the client's SSH implementation.
    return {"kex_algorithms": lists[0],
            "hassh": hashlib.md5(";".join((lists[0], lists[2], lists[4], lists[6])).encode()).hexdigest()}


def _write_ed25519(path: str) -> None:
    # paramiko can load Ed25519 keys but not write them.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(pem)


def load_ssh_host_keys(directory: str) -> None:
    """Load the host keys, creating them once so they stay the same across restarts."""
    paramiko.Transport.load_server_moduli()
    for filename, cls, write in (
            ("ssh_host_rsa_key", paramiko.RSAKey, lambda p: paramiko.RSAKey.generate(3072).write_private_key_file(p)),
            ("ssh_host_ecdsa_key", paramiko.ECDSAKey, lambda p: paramiko.ECDSAKey.generate().write_private_key_file(p)),
            ("ssh_host_ed25519_key", paramiko.Ed25519Key, _write_ed25519)):
        path = os.path.join(directory, filename)
        try:
            if not os.path.exists(path):
                os.makedirs(directory, exist_ok=True)
                write(path)
            _ssh_keys.append(cls.from_private_key_file(path))
        except Exception as exc:    # one bad key must not take the whole honeypot down
            print(f"WARNING: SSH host key {path}: {exc}", file=sys.stderr, flush=True)


class _ReplaySocket:
    """Hands paramiko a socket whose banner exchange has already started.

    The honeypot sends its banner at once, as sshd does, then reads the client's
    bytes to tell a real client from a raw connection. Those bytes are replayed
    here, and paramiko's own banner is skipped because it has already gone out.
    """

    def __init__(self, sock, replay: bytes):
        self._sock = sock
        self._replay = bytearray(replay)
        self._banner_skipped = False
        self._budget = SSH_MAX_BYTES - len(replay)
        self.inbound = bytes(replay[:8192])

    def recv(self, count: int) -> bytes:
        if self._replay:
            data = bytes(self._replay[:count])
            del self._replay[:count]
            return data
        if self._budget <= 0:
            return b""
        data = self._sock.recv(count)
        self._budget -= len(data)
        if len(self.inbound) < 8192:
            self.inbound += data[:8192 - len(self.inbound)]
        return data

    def send(self, data) -> int:
        if not self._banner_skipped and bytes(data[:4]) == b"SSH-":
            self._banner_skipped = True
            return len(data)
        return self._sock.send(data)

    def __getattr__(self, name):
        return getattr(self._sock, name)


class _SSHAuth(paramiko.ServerInterface if paramiko else object):
    """Records every authentication attempt and refuses all of them."""

    def __init__(self, h, svc: dict, transport):
        self.h, self.transport = h, transport
        self.delay = float(svc.get("ssh_auth_delay", 0))
        self.tries_left = int(svc.get("max_auth_tries", 6))
        self.exhausted = False

    def _refuse(self) -> int:
        self.tries_left -= 1
        self.exhausted = self.tries_left <= 0
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "publickey,password"

    def check_auth_none(self, username: str) -> int:
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        self.h.login(username, password, client_version=self.transport.remote_version)
        self.h.pause(self.delay)    # sshd pauses after a wrong password; so do we
        return self._refuse()

    def check_auth_publickey(self, username: str, key) -> int:
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        self.h.event("login_attempt", username=username, key_type=key.get_name(),
                     key_fingerprint=f"SHA256:{digest}", client_version=self.transport.remote_version)
        return self._refuse()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


def _match_openssh(transport) -> None:
    """Offer OpenSSH 8.2's algorithms, in its order, limited to what paramiko can do."""
    def pick(wanted: str, known) -> tuple:
        return tuple(name for name in wanted.split(",") if name in known)

    # paramiko implements this exchange but only under its older name.
    transport._kex_info = {**transport._kex_info,
                           "curve25519-sha256": transport._kex_info["curve25519-sha256@libssh.org"]}
    kex = pick(_SSH_ALGOS[0], transport._kex_info)
    if transport._modulus_pack is None:     # group exchange needs /etc/ssh/moduli
        kex = tuple(name for name in kex if "group-exchange" not in name)
    transport._preferred_kex = kex
    transport._preferred_keys = pick(_SSH_ALGOS[1], transport._key_info)
    transport._preferred_ciphers = pick(_SSH_ALGOS[2], transport._cipher_info)
    transport._preferred_macs = pick(_SSH_ALGOS[4], transport._mac_info)
    transport._preferred_compression = pick(_SSH_ALGOS[6], transport._compression_info)


def ssh_server(h, svc: dict, banner: str) -> bool:
    """Run real SSH key exchange and capture credentials. False if unavailable."""
    if paramiko is None or not _ssh_keys or not _ssh_slots.acquire(blocking=False):
        return False
    sock = _ReplaySocket(h.request, bytes(h._buf))
    h._buf.clear()
    transport = None
    try:
        transport = paramiko.Transport(sock, strict_kex=False)  # 8.2 predates strict KEX
        transport.local_version = banner.strip()
        transport.banner_timeout = transport.handshake_timeout = h.limits["conn_timeout"]
        _match_openssh(transport)
        for key in _ssh_keys:
            transport.add_server_key(key)
        auth = _SSHAuth(h, svc, transport)
        transport.start_server(event=threading.Event(), server=auth)
        while transport.is_active() and not auth.exhausted and time.monotonic() < h._deadline:
            time.sleep(0.1)
        if auth.exhausted and transport.is_active():
            goodbye = paramiko.Message()
            goodbye.add_byte(b"\x01")       # SSH_MSG_DISCONNECT, protocol error
            goodbye.add_int(2)
            goodbye.add_string("Too many authentication failures")
            goodbye.add_string("")
            transport._send_message(goodbye)
            time.sleep(0.1)
    except (paramiko.SSHException, OSError, EOFError):
        pass
    finally:
        if transport:
            transport.close()
        _ssh_slots.release()
    line, _, rest = sock.inbound.partition(b"\n")
    fields = {"client_version": line.strip().decode("ascii", "replace")[:255]}
    try:
        size = struct.unpack(">I", rest[:4])[0]
        fields.update(_kexinit_fields(rest[5:4 + size]))
    except (struct.error, IndexError):
        pass
    h.event("ssh_client_hello", **fields)
    return True


def ssh_client(h, svc: dict, client_version: str) -> None:
    """Fallback without paramiko: swap KEXINITs, log a fingerprint, then hang up.

    Passwords are only sent after key exchange, so this path can't capture them.
    """
    payload = b"\x14" + os.urandom(16)
    for names in _SSH_ALGOS:
        raw = names.encode()
        payload += struct.pack(">I", len(raw)) + raw
    payload += b"\0" + b"\0\0\0\0"
    pad = 8 - ((5 + len(payload)) % 8)
    pad += 8 if pad < 4 else 0
    h.send_bytes(struct.pack(">IB", len(payload) + pad + 1, pad) + payload + os.urandom(pad))

    fields = {"client_version": client_version}
    head = h.recv_exact(5)
    if len(head) == 5:
        size, pad = struct.unpack(">IB", head)
        if 0 < size <= _limit(h):
            fields.update(_kexinit_fields(h.recv_exact(size - 1)))
    h.event("ssh_client_hello", **fields)


# --------------------------------------------------------------------------- #
# Text protocols
# --------------------------------------------------------------------------- #

def ftp(h, svc: dict) -> None:
    """vsftpd before login, with anonymous access off and no TLS."""
    h.send(svc.get("banner", "220 (vsFTPd 3.0.3)\r\n"))
    user = None
    fails_left = int(svc.get("max_login_fails", 3))
    for _ in range(MAX_COMMANDS):
        line = h.recv_line()
        if not line and h.eof:
            return
        verb, _, arg = line.partition(" ")
        verb = verb.upper()
        if verb == "USER":
            user = arg
            h.send("331 Please specify the password.\r\n")
        elif verb == "PASS":
            if user is None:
                h.send("503 Login with USER first.\r\n")
                continue
            h.login(user, arg)
            user = None
            fails_left -= 1
            h.pause_auth()
            h.send("530 Login incorrect.\r\n")
            if fails_left <= 0:
                return
        elif verb == "QUIT":
            h.send("221 Goodbye.\r\n")
            return
        else:
            h.event("command", command=line)
            if verb == "FEAT":
                h.send("211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n"
                       " REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
            elif verb == "OPTS" and arg.upper().startswith("UTF8"):
                h.send("200 Always in UTF8 mode.\r\n")
            else:
                h.send("530 Please login with USER and PASS.\r\n")


def smtp(h, svc: dict) -> None:
    """Postfix: never accepts a recipient, so it can never relay."""
    host = svc.get("hostname", "mail.example.com")
    h.send(svc.get("banner", f"220 {host} ESMTP Postfix (Ubuntu)\r\n"))
    fail = "535 5.7.8 Error: authentication failed: authentication failure\r\n"
    helo = sender = tls_done = False
    rejected = False

    def decode(text: str) -> str:
        return base64.b64decode(text).decode("utf-8", "replace")

    for _ in range(MAX_COMMANDS):
        line = h.recv_line()
        if not line and h.eof:
            return
        verb, _, arg = line.partition(" ")
        verb = verb.upper()
        if verb == "EHLO":
            h.event("command", command=line)
            if not arg:
                h.send("501 Syntax: EHLO hostname\r\n")
                continue
            helo = True
            starttls = "250-STARTTLS\r\n" if _context_for(svc) and not tls_done else ""
            h.send(f"250-{host}\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n{starttls}"
                   "250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n"
                   "250-SMTPUTF8\r\n250 CHUNKING\r\n")
        elif verb == "HELO":
            h.event("command", command=line)
            if not arg:
                h.send("501 Syntax: HELO hostname\r\n")
                continue
            helo = True
            h.send(f"250 {host}\r\n")
        elif verb == "STARTTLS" and _context_for(svc) and not tls_done:
            h.send("220 2.0.0 Ready to start TLS\r\n")
            if not _start_tls(h, svc):
                return
            tls_done, helo, sender = True, False, False
        elif verb == "AUTH":
            mech, _, initial = arg.partition(" ")
            mech = mech.upper()
            if not helo:
                h.send("503 5.5.1 Error: send HELO/EHLO first\r\n")
            elif mech == "PLAIN":
                if not initial:
                    h.send("334 \r\n")
                    initial = h.recv_line()
                try:
                    parts = decode(initial).split("\0")
                    h.login(parts[1], parts[2])
                except (ValueError, IndexError):
                    h.send("501 5.5.2 Cannot decode response\r\n")
                    continue
                h.pause_auth()
                h.send(fail)
            elif mech == "LOGIN":
                try:
                    if initial:
                        user = decode(initial)
                    else:
                        h.send("334 VXNlcm5hbWU6\r\n")
                        user = decode(h.recv_line())
                    h.send("334 UGFzc3dvcmQ6\r\n")
                    password = decode(h.recv_line())
                except ValueError:
                    h.send("501 5.5.2 Cannot decode response\r\n")
                    continue
                h.login(user, password)
                h.pause_auth()
                h.send(fail)
            else:
                h.send("535 5.7.8 Error: authentication failed: Invalid authentication mechanism\r\n")
        elif verb == "MAIL":
            h.event("command", command=line)
            if not helo:
                h.send("503 5.5.1 Error: send HELO/EHLO first\r\n")
            else:
                sender, rejected = True, False
                h.send("250 2.1.0 Ok\r\n")
        elif verb == "RCPT":
            h.event("command", command=line)
            if not sender:
                h.send("503 5.5.1 Error: need MAIL command\r\n")
                continue
            found = re.search(r"<([^>]*)>", arg)
            address = found.group(1) if found else arg.partition(":")[2].strip()
            rejected = True
            h.send(f"554 5.7.1 <{address[:256]}>: Relay access denied\r\n")
        elif verb == "DATA":
            h.event("command", command=line)
            if not sender:
                h.send("503 5.5.1 Error: need RCPT command\r\n")
            elif rejected:
                h.send("554 5.5.1 Error: no valid recipients\r\n")
            else:
                h.send("503 5.5.1 Error: need RCPT command\r\n")
        elif verb == "RSET":
            sender = rejected = False
            h.send("250 2.0.0 Ok\r\n")
        elif verb == "NOOP":
            h.send("250 2.0.0 Ok\r\n")
        elif verb == "VRFY":
            h.event("command", command=line)
            h.send(f"252 2.0.0 {arg[:256]}\r\n")
        elif verb == "QUIT":
            h.send("221 2.0.0 Bye\r\n")
            return
        else:
            h.event("command", command=line)
            h.send("502 5.5.2 Error: command not recognized\r\n")


_REDIS_COMMANDS = frozenset("""
acl append asking auth bgrewriteaof bgsave bitcount bitfield bitfield_ro bitop bitpos blmove blmpop blpop brpop
brpoplpush bzmpop bzpopmax bzpopmin client cluster command config copy dbsize debug decr decrby del discard dump echo
eval eval_ro evalsha evalsha_ro exec exists expire expireat expiretime failover fcall fcall_ro flushall flushdb
function geoadd geodecode geodist geoencode geohash geopos georadius georadius_ro georadiusbymember
georadiusbymember_ro geosearch geosearchstore get getbit getdel getex getrange getset hdel hello hexists hget hgetall
hincrby hincrbyfloat hkeys hlen hmget hmset hrandfield hscan hset hsetnx hstrlen hvals incr incrby incrbyfloat info
keys lastsave latency lcs lindex linsert llen lmove lmpop lolwut lpop lpos lpush lpushx lrange lrem lset ltrim memory
mget migrate module monitor move mset msetnx multi object persist pexpire pexpireat pexpiretime pfadd pfcount
pfdebug pfmerge pfselftest ping psetex psubscribe psync pttl publish pubsub punsubscribe quit randomkey readonly
readwrite rename renamenx replconf replicaof reset restore restore-asking role rpop rpoplpush rpush rpushx sadd save
scan scard script sdiff sdiffstore select set setbit setex setnx setrange shutdown sinter sintercard sinterstore
sismember slaveof slowlog smembers smismember smove sort sort_ro spop spublish srandmember srem sscan ssubscribe
strlen subscribe substr sunion sunionstore sunsubscribe swapdb sync time touch ttl type unlink unsubscribe unwatch
wait watch xack xadd xautoclaim xclaim xdel xgroup xinfo xlen xpending xrange xread xreadgroup xrevrange xsetid xtrim
zadd zcard zcount zdiff zdiffstore zincrby zinter zintercard zinterstore zlexcount zmpop zmscore zpopmax zpopmin
zrandmember zrange zrangebylex zrangebyscore zrangestore zrank zrem zremrangebylex zremrangebyrank
zremrangebyscore zrevrange zrevrangebylex zrevrangebyscore zrevrank zscan zscore zunion zunionstore
""".split())


def _redis_command(h) -> list[str]:
    line = h.recv_line()
    if not line.startswith("*"):
        return line.split()
    args = []
    try:
        count = int(line[1:])
    except ValueError:
        return []
    for _ in range(min(count, 32)):
        head = h.recv_line()
        if not head.startswith("$"):
            break
        try:
            size = int(head[1:])
        except ValueError:
            break
        if not 0 <= size <= _limit(h):
            break
        args.append(h.recv_exact(size).decode("utf-8", "replace"))
        h.recv_exact(2)
    return args


def redis(h, svc: dict) -> None:
    """Redis 7.0 with requirepass set."""
    wrong = "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
    for _ in range(MAX_COMMANDS):
        args = _redis_command(h)
        if not args:
            if h.eof:
                return
            continue
        verb = args[0].upper()
        if verb in ("POST", "HOST:"):           # Redis drops anything that looks like HTTP
            h.event("command", command=" ".join(args))
            return
        if verb == "AUTH":
            if len(args) == 2:
                h.login("default", args[1])
                h.pause_auth()
                h.send(wrong)
            elif len(args) == 3:
                h.login(args[1], args[2])
                h.pause_auth()
                h.send(wrong)
            elif len(args) == 1:
                h.send("-ERR wrong number of arguments for 'auth' command\r\n")
            else:
                h.send("-ERR syntax error\r\n")
        elif verb == "HELLO":
            upper = [a.upper() for a in args]
            if "AUTH" in upper and len(args) > upper.index("AUTH") + 2:
                at = upper.index("AUTH")
                h.login(args[at + 1], args[at + 2])
                h.pause_auth()
                h.send(wrong)
            elif len(args) == 1:
                h.send("-NOAUTH Authentication required.\r\n")
            else:
                h.event("command", command=" ".join(args))
                h.send("-NOAUTH HELLO must be called with the client already authenticated, otherwise the "
                       "HELLO <proto> AUTH <user> <pass> option can be used to authenticate the client and "
                       "select the RESP protocol version at the same time\r\n")
        elif verb == "QUIT":
            h.send("+OK\r\n")
            return
        elif verb.lower() not in _REDIS_COMMANDS:
            h.event("command", command=" ".join(args))
            shown = ""
            for arg in args[1:]:
                if len(shown) >= 128:
                    break
                shown += "'" + arg[:128 - len(shown)] + "' "
            text = f"-ERR unknown command '{args[0][:128]}', with args beginning with: {shown}"
            h.send(text.replace("\r", " ").replace("\n", " ") + "\r\n")
        else:
            h.event("command", command=" ".join(args))
            h.send("-NOAUTH Authentication required.\r\n")


# --------------------------------------------------------------------------- #
# HTTP(S) responses
# --------------------------------------------------------------------------- #

_REASONS = {400: "Bad Request", 401: "Unauthorized"}
_APACHE_BODY = {
    400: ("<p>Your browser sent a request that this server could not understand.<br />\n</p>\n"),
    401: ("<p>This server could not verify that you\nare authorized to access the document\nrequested.  "
          "Either you supplied the wrong\ncredentials (e.g., bad password), or your\nbrowser doesn't "
          "understand how to supply\nthe credentials required.</p>\n"),
}


def http_error(svc: dict, status: int, method: str, path: str, host: str, user: str = "") -> bytes:
    reason = _REASONS[status]
    server = svc.get("server", "Apache/2.4.41 (Ubuntu)")
    if svc.get("profile") == "elasticsearch":
        if status == 400:
            return b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n"
        schemes = ['Basic realm="security" charset="UTF-8"', "ApiKey"]
        text = (f"unable to authenticate user [{user[:128]}] for REST request [{path[:200]}]" if user
                else f"missing authentication credentials for REST request [{path[:200]}]")
        error = {"type": "security_exception", "reason": text, "header": {"WWW-Authenticate": schemes}}
        body = json.dumps({"error": {"root_cause": [error], **error}, "status": 401}, separators=(",", ":")).encode()
        head = ("HTTP/1.1 401 Unauthorized\r\n"
                f"WWW-Authenticate: {schemes[0]}\r\nWWW-Authenticate: {schemes[1]}\r\n"
                f"content-type: application/json\r\ncontent-length: {len(body)}\r\n\r\n")
    elif server.startswith("nginx"):
        title = "401 Authorization Required" if status == 401 else f"{status} {reason}"
        body = (f"<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n<center><h1>{title}</h1></center>\r\n"
                f"<hr><center>{server}</center>\r\n</body>\r\n</html>\r\n").encode()
        auth = 'WWW-Authenticate: Basic realm="Restricted"\r\n' if status == 401 else ""
        head = (f"HTTP/1.1 {status} {reason}\r\nServer: {server}\r\nDate: {formatdate(usegmt=True)}\r\n"
                f"Content-Type: text/html\r\nContent-Length: {len(body)}\r\nConnection: close\r\n{auth}\r\n")
    else:
        name = html.escape(host.split(":")[0][:100]) or "localhost"
        body = (f'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>{status} {reason}</title>\n'
                f"</head><body>\n<h1>{reason}</h1>\n{_APACHE_BODY[status]}<hr>\n"
                f"<address>{server} Server at {name} Port {svc.get('port', 80)}</address>\n"
                "</body></html>\n").encode("latin-1", "replace")
        auth = 'WWW-Authenticate: Basic realm="Restricted"\r\n' if status == 401 else ""
        head = (f"HTTP/1.1 {status} {reason}\r\nDate: {formatdate(usegmt=True)}\r\nServer: {server}\r\n{auth}"
                f"Content-Length: {len(body)}\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n")
    return head.encode("latin-1", "replace") + (b"" if method == "HEAD" else body)


def http_ok_headers(svc: dict, ctype: str, length: int, modified: float) -> bytes:
    server = svc.get("server", "Apache/2.4.41 (Ubuntu)")
    stamp = formatdate(modified, usegmt=True)
    if server.startswith("nginx"):
        etag = f'"{int(modified):x}-{length:x}"'
        head = (f"HTTP/1.1 200 OK\r\nServer: {server}\r\nDate: {formatdate(usegmt=True)}\r\nContent-Type: {ctype}\r\n"
                f"Content-Length: {length}\r\nLast-Modified: {stamp}\r\nConnection: close\r\n"
                f"ETag: {etag}\r\nAccept-Ranges: bytes\r\n\r\n")
    else:
        etag = f'"{length:x}-{int(modified * 1000000):x}"'
        head = (f"HTTP/1.1 200 OK\r\nDate: {formatdate(usegmt=True)}\r\nServer: {server}\r\nLast-Modified: {stamp}\r\n"
                f'ETag: {etag}\r\nAccept-Ranges: bytes\r\nContent-Length: {length}\r\nConnection: close\r\n'
                f"Content-Type: {ctype}\r\n\r\n")
    return head.encode("latin-1", "replace")


def _client_hello_sni(body: bytes) -> str:
    off = 4 + 2 + 32                # handshake header, version, random
    off += 1 + body[off]            # session id
    off += 2 + struct.unpack(">H", body[off:off + 2])[0]    # cipher suites
    off += 1 + body[off]            # compression
    end = off + 2 + struct.unpack(">H", body[off:off + 2])[0]
    off += 2
    while off + 4 <= end:
        kind, size = struct.unpack(">HH", body[off:off + 4])
        if kind == 0:
            n = struct.unpack(">H", body[off + 7:off + 9])[0]
            return body[off + 9:off + 9 + n].decode("ascii", "replace")
        off += 4 + size
    return ""


def https(h, svc: dict) -> None:
    """Real TLS when a certificate exists, otherwise log the hello and refuse."""
    if _context_for(svc):
        if _start_tls(h, svc):
            h._do_http(svc)
        return
    head = h.recv_exact(5)
    if len(head) < 5 or head[0] != 22:
        return
    size = struct.unpack(">H", head[3:5])[0]
    body = h.recv_exact(min(size, _limit(h)))
    h.event("tls_client_hello", sni=_client_hello_sni(body))
    h.send_bytes(b"\x15\x03\x03\x00\x02\x02\x28")   # fatal handshake_failure alert


# --------------------------------------------------------------------------- #
# DNS over TCP (deliberately no UDP: a UDP responder can be used for reflection)
# --------------------------------------------------------------------------- #

def dns(h, svc: dict) -> None:
    version = svc.get("version", "9.16.1-Ubuntu").encode()
    for _ in range(MAX_COMMANDS):
        head = h.recv_exact(2)
        if len(head) < 2:
            return
        size = struct.unpack(">H", head)[0]
        msg = h.recv_exact(size)
        if size < 12 or len(msg) < size or size > _limit(h):
            return
        off, labels = 12, []
        while msg[off]:
            n = msg[off]
            labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
            off += 1 + n
        qtype, qclass = struct.unpack(">HH", msg[off + 1:off + 5])
        question = msg[12:off + 5]
        name = ".".join(labels)
        h.event("dns_query", qname=name, qtype=qtype, qclass=qclass)
        rd = msg[2] & 1
        if name.lower() == "version.bind" and qclass == 3 and qtype == 16:
            flags, answers = 0x8400 | (rd << 8), 1
            rdata = bytes([len(version)]) + version
            answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 0, len(rdata)) + rdata
        else:
            flags, answers, answer = 0x8085 | (rd << 8), 0, b""     # REFUSED
        reply = msg[:2] + struct.pack(">HHHHH", flags, 1, answers, 0, 0) + question + answer
        h.send_bytes(struct.pack(">H", len(reply)) + reply)


# --------------------------------------------------------------------------- #
# Databases
# --------------------------------------------------------------------------- #

def _mysql_send(h, seq: int, payload: bytes) -> None:
    h.send_bytes(struct.pack("<I", len(payload))[:3] + bytes([seq & 255]) + payload)


def _mysql_read(h):
    head = h.recv_exact(4)
    if len(head) < 4:
        return None, b""
    size = int.from_bytes(head[:3], "little")
    return head[3], h.recv_exact(min(size, _limit(h)))


def mysql(h, svc: dict) -> None:
    """MySQL 8.0 with its default caching_sha2_password plugin.

    A password this server hasn't cached forces "full authentication", where the
    client sends it over TLS or RSA-encrypted, so the real password is captured.
    """
    version = svc.get("version", "8.0.39-0ubuntu0.20.04.1")
    plugin = b"caching_sha2_password"
    scramble = bytes(b % 94 + 33 for b in os.urandom(20))
    tls_available = _context_for(svc) is not None
    caps = 0xDFFFFFFF if tls_available else 0xDFFFF7FF
    greeting = (b"\x0a" + version.encode() + b"\0"
                + struct.pack("<I", int.from_bytes(os.urandom(2), "little") + 8)
                + scramble[:8] + b"\0" + struct.pack("<HBHHB", caps & 0xFFFF, 255, 2, caps >> 16, 21)
                + b"\0" * 10 + scramble[8:] + b"\0" + plugin + b"\0")
    _mysql_send(h, 0, greeting)

    seq, body = _mysql_read(h)
    if seq is None or len(body) < 32:
        return
    client_caps = struct.unpack("<I", body[:4])[0]
    if len(body) == 32 and client_caps & 0x800:         # SSLRequest
        if not _start_tls(h, svc):
            return
        seq, body = _mysql_read(h)
        if seq is None or len(body) < 33:
            return
        client_caps = struct.unpack("<I", body[:4])[0]
    end = body.index(0, 32)
    user = body[32:end].decode("utf-8", "replace")
    off = end + 1
    if client_caps & 0x200000 or client_caps & 0x8000:
        n = body[off]
        response = body[off + 1:off + 1 + n]
        off += 1 + n
    else:
        stop = body.index(0, off)
        response, off = body[off:stop], stop + 1
    database = client_plugin = ""
    if client_caps & 0x8 and off < len(body):
        stop = body.index(0, off)
        database, off = body[off:stop].decode("utf-8", "replace"), stop + 1
    if client_caps & 0x80000 and off < len(body):
        client_plugin = body[off:body.index(0, off)].decode("utf-8", "replace")

    def deny(sequence: int, using: str) -> None:
        text = f"Access denied for user '{user[:64]}'@'{h.client_address[0]}' (using password: {using})"
        h.pause_auth()
        _mysql_send(h, sequence, b"\xff" + struct.pack("<H", 1045) + b"#28000" + text.encode("utf-8", "replace"))

    if client_plugin and client_plugin != plugin.decode():
        seq += 1
        _mysql_send(h, seq, b"\xfe" + plugin + b"\0" + scramble + b"\0")
        seq, response = _mysql_read(h)
        if seq is None:
            return
    if not response:
        h.event("login_attempt", username=user, password="", database=database)
        deny(seq + 1, "NO")
        return

    seq += 1
    _mysql_send(h, seq, b"\x01\x04")                    # perform_full_authentication
    seq, reply = _mysql_read(h)
    if seq is None:
        return
    password = None
    if h.tls:
        password = reply.rstrip(b"\0")
    elif reply == b"\x02" and _rsa_key is not None:     # client asks for our public key
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        pem = _rsa_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        seq += 1
        _mysql_send(h, seq, b"\x01" + pem)
        seq, encrypted = _mysql_read(h)
        if seq is None:
            return
        try:
            mixed = _rsa_key.decrypt(encrypted, padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None))
            password = bytes(b ^ scramble[i % 20] for i, b in enumerate(mixed)).rstrip(b"\0")
        except ValueError:
            pass
    if password is None:
        h.event("login_attempt", username=user, database=database, password_hash=response.hex())
    else:
        h.login(user, password.decode("utf-8", "replace"), database=database)
    deny(seq + 1, "YES")


def postgres(h, svc: dict) -> None:
    """PostgreSQL 15 configured with the `password` auth method, to capture passwords."""
    params: dict[str, str] = {}
    for _ in range(4):
        head = h.recv_exact(4)
        if len(head) < 4:
            return
        size = struct.unpack(">I", head)[0]
        if not 8 <= size <= _limit(h):
            return
        body = h.recv_exact(size - 4)
        code = struct.unpack(">I", body[:4])[0]
        if code == 80877103:                    # SSLRequest
            if _context_for(svc):
                h.send_bytes(b"S")
                if not _start_tls(h, svc):
                    return
            else:
                h.send_bytes(b"N")
            continue
        if code == 80877104:                    # GSSENCRequest
            h.send_bytes(b"N")
            continue
        if code != 196608:                      # protocol 3.0 startup
            return
        items = body[4:].split(b"\0")
        params = {items[i].decode("utf-8", "replace"): items[i + 1].decode("utf-8", "replace")
                  for i in range(0, len(items) - 1, 2) if items[i]}
        break
    else:
        return
    user = params.get("user", "")
    h.send_bytes(b"R" + struct.pack(">II", 8, 3))   # AuthenticationCleartextPassword
    head = h.recv_exact(5)
    password = ""
    if len(head) == 5 and head[:1] == b"p":
        size = struct.unpack(">I", head[1:])[0]
        if 4 <= size <= _limit(h):
            password = h.recv_exact(size - 4).rstrip(b"\0").decode("utf-8", "replace")
    elif len(head) < 5:
        return                                  # client hung up at the password prompt
    h.login(user, password, database=params.get("database", user),
            application=params.get("application_name", ""))
    h.pause_auth()
    fields = (b"SFATAL\0VFATAL\0C28P01\0Mpassword authentication failed for user \""
              + user[:64].encode("utf-8", "replace") + b"\"\0Fauth.c\0L335\0Rauth_failed\0\0")
    h.send_bytes(b"E" + struct.pack(">I", 4 + len(fields)) + fields)


_MONGO_PROCESS = os.urandom(12)
_mongo_connections = [1]


def _bson(doc: dict) -> bytes:
    out = b""
    for key, value in doc.items():
        name = key.encode() + b"\0"
        if isinstance(value, bool):
            out += b"\x08" + name + bytes([value])
        elif isinstance(value, float):
            out += b"\x01" + name + struct.pack("<d", value)
        elif isinstance(value, int):
            out += b"\x10" + name + struct.pack("<i", value)
        elif isinstance(value, str):
            raw = value.encode() + b"\0"
            out += b"\x02" + name + struct.pack("<i", len(raw)) + raw
        elif isinstance(value, bytes):
            out += b"\x05" + name + struct.pack("<i", len(value)) + b"\0" + value
        elif isinstance(value, dict):
            out += b"\x03" + name + _bson(value)
        elif isinstance(value, list):
            out += b"\x04" + name + _bson({str(i): v for i, v in enumerate(value)})
        elif isinstance(value, tuple) and value[0] == "date":
            out += b"\x09" + name + struct.pack("<q", value[1])
        elif isinstance(value, tuple) and value[0] == "oid":
            out += b"\x07" + name + value[1]
        elif isinstance(value, tuple) and value[0] == "long":
            out += b"\x12" + name + struct.pack("<q", value[1])
    return struct.pack("<i", len(out) + 5) + out + b"\0"


def mongodb(h, svc: dict) -> None:
    """MongoDB 6.0 with authorization enabled."""
    version = svc.get("version", "6.0.18")
    _mongo_connections[0] += 1
    connection = _mongo_connections[0]
    server_nonce = base64.b64encode(os.urandom(18)).decode()
    for _ in range(MAX_COMMANDS):
        head = h.recv_exact(16)
        if len(head) < 16:
            return
        length, request_id, _, opcode = struct.unpack("<iiii", head)
        if not 16 < length <= _limit(h):
            return
        body = h.recv_exact(length - 16)
        if opcode == 2004:                      # OP_QUERY (legacy hello)
            doc = body[body.index(0, 4) + 9:]
        elif opcode == 2013:                    # OP_MSG
            doc = body[5:]
        else:
            return
        command = doc[5:doc.index(0, 5)].decode("utf-8", "replace")
        low = command.lower()
        denied = {"ok": 0.0, "errmsg": "Authentication failed.", "code": 18, "codeName": "AuthenticationFailed"}
        if low in ("hello", "ismaster"):
            reply: dict = {}
            if b"helloOk" in doc:
                reply["helloOk"] = True
            reply["isWritablePrimary" if low == "hello" else "ismaster"] = True
            reply.update({"topologyVersion": {"processId": ("oid", _MONGO_PROCESS), "counter": ("long", 0)},
                          "maxBsonObjectSize": 16777216, "maxMessageSizeBytes": 48000000,
                          "maxWriteBatchSize": 100000, "localTime": ("date", int(time.time() * 1000)),
                          "logicalSessionTimeoutMinutes": 30, "connectionId": connection,
                          "minWireVersion": 0, "maxWireVersion": 17, "readOnly": False})
            if b"saslSupportedMechs" in doc:
                reply["saslSupportedMechs"] = ["SCRAM-SHA-1", "SCRAM-SHA-256"]
            reply["ok"] = 1.0
            h.event("mongo_hello", command=command)
        elif low == "buildinfo":
            parts = [int(p) for p in version.split(".")] + [0]
            reply = {"version": version, "gitVersion": hashlib.sha1(version.encode()).hexdigest(), "modules": [],
                     "allocator": "tcmalloc", "javascriptEngine": "mozjs", "sysInfo": "deprecated",
                     "versionArray": parts, "openssl": {"running": "OpenSSL 1.1.1f  31 Mar 2020",
                                                        "compiled": "OpenSSL 1.1.1f  31 Mar 2020"},
                     "buildEnvironment": {"distmod": "ubuntu2004", "distarch": "x86_64",
                                          "target_arch": "x86_64", "target_os": "linux"},
                     "bits": 64, "debug": False, "maxBsonObjectSize": 16777216,
                     "storageEngines": ["devnull", "ephemeralForTest", "wiredTiger"], "ok": 1.0}
            h.event("command", command=command)
        elif low == "ping":
            reply = {"ok": 1.0}
        elif low == "whatsmyuri":
            reply = {"you": f"{h.client_address[0]}:{h.client_address[1]}", "ok": 1.0}
        elif low == "saslstart":
            found = re.search(rb"n=([^,\0]{1,128}),r=([^,\0]{1,128})", doc)
            user = found.group(1).decode("utf-8", "replace") if found else ""
            sha1 = b"SCRAM-SHA-1\0" in doc
            h.event("login_attempt", username=user, mechanism="SCRAM-SHA-1" if sha1 else "SCRAM-SHA-256")
            if not found:
                reply = denied
            else:
                # Real servers derive a stable fake salt, so unknown users look like known ones.
                salt = hashlib.sha256(found.group(1)).digest()[:16 if sha1 else 28]
                payload = (f"r={found.group(2).decode('ascii', 'replace')}{server_nonce},"
                           f"s={base64.b64encode(salt).decode()},i={10000 if sha1 else 15000}")
                reply = {"conversationId": 1, "done": False, "payload": payload.encode(), "ok": 1.0}
        elif low == "saslcontinue":
            reply = denied
        else:
            h.event("command", command=command)
            reply = {"ok": 0.0, "errmsg": f"command {command[:64]} requires authentication",
                     "code": 13, "codeName": "Unauthorized"}
        encoded = _bson(reply)
        if opcode == 2004:
            payload_out, code = struct.pack("<iqii", 8, 0, 0, 1) + encoded, 1
        else:
            payload_out, code = struct.pack("<iB", 0, 0) + encoded, 2013
        if reply is denied:
            h.pause_auth()
        h.send_bytes(struct.pack("<iiii", 16 + len(payload_out), 1, request_id, code) + payload_out)


# --------------------------------------------------------------------------- #
# BER helpers (LDAP and SPNEGO)
# --------------------------------------------------------------------------- #

def _ber(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 128:
        return bytes([tag, n]) + value
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + value


def _ber_read(buf: bytes, off: int) -> tuple[int, bytes, int]:
    tag, n = buf[off], buf[off + 1]
    off += 2
    if n & 0x80:
        count = n & 0x7F
        n = int.from_bytes(buf[off:off + count], "big")
        off += count
    return tag, buf[off:off + n], off + n


_AD_CONTROLS = """1.2.840.113556.1.4.319 1.2.840.113556.1.4.801 1.2.840.113556.1.4.473 1.2.840.113556.1.4.528
1.2.840.113556.1.4.417 1.2.840.113556.1.4.619 1.2.840.113556.1.4.841 1.2.840.113556.1.4.529 1.2.840.113556.1.4.805
1.2.840.113556.1.4.521 1.2.840.113556.1.4.970 1.2.840.113556.1.4.1338 1.2.840.113556.1.4.474 1.2.840.113556.1.4.1339
1.2.840.113556.1.4.1340 1.2.840.113556.1.4.1413 2.16.840.1.113730.3.4.9 2.16.840.1.113730.3.4.10
1.2.840.113556.1.4.1504 1.2.840.113556.1.4.1852 1.2.840.113556.1.4.802 1.2.840.113556.1.4.1907
1.2.840.113556.1.4.1948 1.2.840.113556.1.4.1974 1.2.840.113556.1.4.1341 1.2.840.113556.1.4.2026
1.2.840.113556.1.4.2064 1.2.840.113556.1.4.2065 1.2.840.113556.1.4.2066 1.2.840.113556.1.4.2090
1.2.840.113556.1.4.2205 1.2.840.113556.1.4.2204 1.2.840.113556.1.4.2206 1.2.840.113556.1.4.2211
1.2.840.113556.1.4.2239 1.2.840.113556.1.4.2255 1.2.840.113556.1.4.2256 1.2.840.113556.1.4.2309
1.2.840.113556.1.4.2330 1.2.840.113556.1.4.2354""".split()


def _ad_root_dse(svc: dict) -> dict:
    base = svc.get("naming_context", "DC=corp,DC=local")
    computer = svc.get("computer", "DC01")
    dns_name = ".".join(part.split("=", 1)[1] for part in base.split(","))
    config = f"CN=Configuration,{base}"
    server = f"CN={computer},CN=Servers,CN=Default-First-Site-Name,CN=Sites,{config}"
    return {
        "currentTime": [time.strftime("%Y%m%d%H%M%S.0Z", time.gmtime())],
        "subschemaSubentry": [f"CN=Aggregate,CN=Schema,{config}"],
        "dsServiceName": [f"CN=NTDS Settings,{server}"],
        "namingContexts": [base, config, f"CN=Schema,{config}", f"DC=DomainDnsZones,{base}", f"DC=ForestDnsZones,{base}"],
        "defaultNamingContext": [base],
        "schemaNamingContext": [f"CN=Schema,{config}"],
        "configurationNamingContext": [config],
        "rootDomainNamingContext": [base],
        "supportedControl": _AD_CONTROLS,
        "supportedLDAPVersion": ["3", "2"],
        "supportedLDAPPolicies": ["MaxPoolThreads", "MaxPercentDirSyncRequests", "MaxDatagramRecv", "MaxReceiveBuffer",
                                  "InitRecvTimeout", "MaxConnections", "MaxConnIdleTime", "MaxPageSize",
                                  "MaxBatchReturnMessages", "MaxQueryDuration", "MaxDirSyncDuration", "MaxTempTableSize",
                                  "MaxResultSetSize", "MinResultSets", "MaxResultSetsPerConn", "MaxNotificationPerConn",
                                  "MaxValRange", "MaxValRangeTransitive", "ThreadMemoryLimit", "SystemMemoryLimitPercent"],
        "highestCommittedUSN": [str(int(hashlib.sha1(server.encode()).hexdigest()[:5], 16) + 12000)],
        "supportedSASLMechanisms": ["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
        "dnsHostName": [f"{computer.lower()}.{dns_name}"],
        "ldapServiceName": [f"{dns_name}:{computer.lower()}$@{dns_name.upper()}"],
        "serverName": [server],
        "supportedCapabilities": ["1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791",
                                  "1.2.840.113556.1.4.1935", "1.2.840.113556.1.4.2080", "1.2.840.113556.1.4.2237"],
        "isSynchronized": ["TRUE"],
        "isGlobalCatalogReady": ["TRUE"],
        "domainFunctionality": ["7"],
        "forestFunctionality": ["7"],
        "domainControllerFunctionality": ["7"],
    }


def ldap(h, svc: dict) -> None:
    """A Windows Server 2019 domain controller."""
    bad_login = b"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e, v4563\0"
    need_bind = (b"000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful "
                 b"bind must be completed on the connection., data 0, v4563\0")

    def result(tag: int, msg_id: bytes, code: int, text: bytes = b"") -> None:
        body = _ber(0x0A, bytes([code])) + _ber(4, b"") + _ber(4, text)
        h.send_bytes(_ber(0x30, _ber(2, msg_id) + _ber(tag, body)))

    for _ in range(MAX_COMMANDS):
        head = h.recv_exact(2)
        if len(head) < 2 or head[0] != 0x30:
            return
        size = head[1]
        if size & 0x80:
            count = size & 0x7F
            if count > 4:
                return
            size = int.from_bytes(h.recv_exact(count), "big")
        if size > _limit(h):
            return
        msg = h.recv_exact(size)
        _, msg_id, off = _ber_read(msg, 0)
        op, value, _ = _ber_read(msg, off)
        if op == 0x60:                          # BindRequest
            _, _, i = _ber_read(value, 0)
            _, dn_raw, i = _ber_read(value, i)
            auth, secret, _ = _ber_read(value, i)
            dn = dn_raw.decode("utf-8", "replace")
            if auth == 0x80:
                if not secret:
                    h.event("ldap_anonymous_bind", username=dn)
                    result(0x61, msg_id, 0)
                    continue
                h.login(dn, secret.decode("utf-8", "replace"))
            else:
                h.event("login_attempt", username=dn, auth="sasl")
            h.pause_auth()
            result(0x61, msg_id, 49, bad_login)
        elif op == 0x63:                        # SearchRequest
            _, base, i = _ber_read(value, 0)
            h.event("ldap_search", base=base.decode("utf-8", "replace"))
            if base:
                result(0x65, msg_id, 1, need_bind)
                continue
            for _ in range(5):                  # scope, deref, size, time, typesOnly
                _, _, i = _ber_read(value, i)
            _, _, i = _ber_read(value, i)       # filter
            _, listed, _ = _ber_read(value, i)
            wanted, j = set(), 0
            while j < len(listed):
                _, name, j = _ber_read(listed, j)
                wanted.add(name.decode("utf-8", "replace").lower())
            attrs = b""
            for name, values in _ad_root_dse(svc).items():
                if not wanted or "*" in wanted or name.lower() in wanted:
                    attrs += _ber(0x30, _ber(4, name.encode()) + _ber(0x31, b"".join(_ber(4, v.encode()) for v in values)))
            entry = _ber(0x64, _ber(4, b"") + _ber(0x30, attrs))
            h.send_bytes(_ber(0x30, _ber(2, msg_id) + entry))
            result(0x65, msg_id, 0)
        elif op == 0x42:                        # UnbindRequest
            return
        elif op == 0x77:                        # ExtendedRequest (e.g. StartTLS)
            h.event("command", command="ldap extended request")
            result(0x78, msg_id, 52, b"00000000: LdapErr: DSID-0C091257, comment: Error initializing SSL/TLS, data 0, v4563\0")
        else:
            h.event("command", command=f"ldap op 0x{op:02x}")
            return


# --------------------------------------------------------------------------- #
# SMB2 + NTLM (captures the NTLM response; there is no plaintext to capture)
# --------------------------------------------------------------------------- #

_NTLM_OID = bytes.fromhex("2b06010401823702020a")
_NEGOEX_OID = bytes.fromhex("2b06010401823702021e")
_MS_KRB_OID = bytes.fromhex("2a864882f712010202")
_KRB_OID = bytes.fromhex("2a864886f712010202")
_U2U_OID = bytes.fromhex("2a864886f71201020203")
_SPNEGO_OID = bytes.fromhex("2b0601050502")


def _filetime() -> int:
    return int((time.time() + 11644473600) * 10_000_000)


def _ntlm_challenge(challenge: bytes, domain: str, computer: str, dns_domain: str) -> bytes:
    d, c = domain.encode("utf-16-le"), computer.encode("utf-16-le")
    dd = dns_domain.encode("utf-16-le")
    dc = f"{computer.lower()}.{dns_domain}".encode("utf-16-le")

    def av(kind: int, value: bytes) -> bytes:
        return struct.pack("<HH", kind, len(value)) + value

    info = (av(2, d) + av(1, c) + av(4, dd) + av(3, dc) + av(5, dd)
            + av(7, struct.pack("<Q", _filetime())) + av(0, b""))
    return struct.pack("<8sIHHII8s8sHHI8s", b"NTLMSSP\0", 2, len(d), len(d), 56, 0xE2898215,
                       challenge, b"\0" * 8, len(info), len(info), 56 + len(d),
                       bytes.fromhex("0a0063450000000f")) + d + info   # Windows build 17763


def smb(h, svc: dict) -> None:
    """A Windows Server 2019 file server: SMB 3.1.1, no SMB1."""
    domain = svc.get("domain", "CORP")
    computer = svc.get("computer", "FILESRV01")
    dns_domain = svc.get("dns_domain", f"{domain.lower()}.local")
    session = int.from_bytes(os.urandom(7), "little") | 1
    challenge, guid = os.urandom(8), os.urandom(16)
    booted = _filetime() - 36_000_000_000_000
    mechs = b"".join(_ber(6, oid) for oid in (_NEGOEX_OID, _MS_KRB_OID, _KRB_OID, _U2U_OID, _NTLM_OID))
    hint = _ber(0xA3, _ber(0x30, _ber(0xA0, _ber(0x1B, b"not_defined_in_RFC4178@please_ignore"))))
    mech = _ber(0x60, _ber(6, _SPNEGO_OID) + _ber(0xA0, _ber(0x30, _ber(0xA0, _ber(0x30, mechs)) + hint)))

    def send(command: int, message_id: bytes, status: int, body: bytes, sid: int = 0) -> None:
        header = struct.pack("<4sHHIHHII8sIIQ16s", b"\xfeSMB", 64, 1, status, command,
                             1, 1, 0, message_id, 0, 0, sid, b"\0" * 16)
        packet = header + body
        h.send_bytes(b"\0" + len(packet).to_bytes(3, "big") + packet)

    def negotiate(message_id: bytes, dialect: int, cipher: int = 0) -> None:
        h.event("smb_negotiate", dialect=f"0x{dialect:04x}")
        contexts = b""
        count = 0
        offset = 0
        blob = mech
        if dialect == 0x0311:
            first = struct.pack("<HHI", 1, 38, 0) + struct.pack("<HHH", 1, 32, 1) + os.urandom(32)
            contexts = first + b"\0" * (-len(first) % 8) + struct.pack("<HHI", 2, 4, 0) + struct.pack("<HH", 1, cipher)
            count = 2
            blob = mech + b"\0" * (-(128 + len(mech)) % 8)
            offset = 128 + len(blob)
        capabilities = 0x2F if dialect >= 0x0300 and dialect != 0x02FF else 0x07
        body = struct.pack("<HHHH16sIIIIQQHHI", 65, 1, dialect, count, guid, capabilities, 8388608, 8388608,
                           8388608, _filetime(), booted, 128, len(mech), offset) + blob + contexts
        send(0, message_id, 0, body)

    for _ in range(12):
        netbios = h.recv_exact(4)
        if len(netbios) < 4 or netbios[0] != 0:
            return
        size = int.from_bytes(netbios[1:], "big")
        if not 4 <= size <= _limit(h):
            return
        msg = h.recv_exact(size)
        if msg[:4] == b"\xffSMB":
            if b"SMB 2." not in msg:
                h.event("smb_negotiate", dialect="SMB1 only")
                return                          # SMB1 is off by default on 2019
            negotiate(b"\0" * 8, 0x02FF)
            continue
        if msg[:4] != b"\xfeSMB":
            return
        command = struct.unpack("<H", msg[12:14])[0]
        message_id = msg[24:32]
        if command == 0:
            count = struct.unpack("<H", msg[66:68])[0]
            offered = struct.unpack(f"<{count}H", msg[100:100 + 2 * count])
            dialect = next((d for d in (0x0311, 0x0302, 0x0300, 0x0210, 0x0202) if d in offered), None)
            if dialect is None:
                return
            cipher = 1
            if dialect == 0x0311:
                # Walk the client's contexts to pick the same cipher Windows would.
                at, total = struct.unpack("<IH", msg[92:98])
                for _ in range(min(total, 8)):
                    kind, length = struct.unpack("<HH", msg[at:at + 4])
                    if kind == 2:
                        n = struct.unpack("<H", msg[at + 8:at + 10])[0]
                        ciphers = struct.unpack(f"<{n}H", msg[at + 10:at + 10 + 2 * n])
                        cipher = 2 if 2 in ciphers else ciphers[0]
                    at += 8 + length
                    at += -at % 8
            negotiate(message_id, dialect, cipher)
        elif command == 1:
            off, length = struct.unpack("<HH", msg[76:80])
            blob = msg[off:off + length]
            at = blob.find(b"NTLMSSP\0")
            if at < 0:
                send(1, message_id, 0xC000006D, struct.pack("<HHI", 9, 0, 0) + b"\0", session)
                return
            ntlm = blob[at:]
            kind = struct.unpack("<I", ntlm[8:12])[0]
            if kind == 1:
                token = _ntlm_challenge(challenge, domain, computer, dns_domain)
                if at:                          # client used SPNEGO, so answer in SPNEGO
                    token = _ber(0xA1, _ber(0x30, _ber(0xA0, _ber(0x0A, b"\x01"))
                                            + _ber(0xA1, _ber(6, _NTLM_OID)) + _ber(0xA2, _ber(4, token))))
                body = struct.pack("<HHHH", 9, 0, 72, len(token)) + token
                send(1, message_id, 0xC0000016, body, session)   # MORE_PROCESSING_REQUIRED
            elif kind == 3:
                def field(pos: int) -> bytes:
                    n, _, p = struct.unpack("<HHI", ntlm[pos:pos + 8])
                    return ntlm[p:p + n]
                nt = field(20)
                dom = field(28).decode("utf-16-le", "replace")
                user = field(36).decode("utf-16-le", "replace")
                h.event("login_attempt", username=user, domain=dom,
                        workstation=field(44).decode("utf-16-le", "replace"),
                        ntlm_hash=f"{user}::{dom}:{challenge.hex()}:{nt[:16].hex()}:{nt[16:].hex()}")
                h.pause_auth()
                send(1, message_id, 0xC000006D, struct.pack("<HHI", 9, 0, 0) + b"\0", session)
                return
        else:
            send(command, message_id, 0xC0000022, struct.pack("<HHI", 9, 0, 0) + b"\0", session)
            return


# --------------------------------------------------------------------------- #
# RDP, VNC, NFS
# --------------------------------------------------------------------------- #

def rdp(h, svc: dict) -> None:
    """Windows Server 2019 with Network Level Authentication required."""
    head = h.recv_exact(4)
    if len(head) < 4 or head[0] != 3:
        return
    size = struct.unpack(">H", head[2:])[0]
    if not 11 <= size <= _limit(h):
        return
    body = h.recv_exact(size - 4)
    if len(body) < 7 or body[1] != 0xE0:
        return
    cookie = re.search(rb"Cookie: mstshash=([^\r\n]{1,128})", body)
    requested = 0
    if len(body) >= 8 and body[-8] == 1:
        requested = struct.unpack("<I", body[-4:])[0]
    h.event("rdp_connect", username=cookie.group(1).decode("utf-8", "replace") if cookie else "",
            requested_protocols=requested)
    x224 = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00"
    if requested & 0xA:
        chosen = 8 if requested & 8 else 2
        h.send_bytes(x224 + b"\x02\x1f\x08\x00" + struct.pack("<I", chosen))
        # The client now opens TLS, and CredSSP inside it would need a real
        # domain to continue, so show the certificate and stop there.
        if _context_for(svc) and _start_tls(h, svc):
            h.recv_exact(1)
    else:
        h.send_bytes(x224 + b"\x03\x00\x08\x00" + struct.pack("<I", 5))  # HYBRID_REQUIRED_BY_SERVER


def vnc(h, svc: dict) -> None:
    h.send_bytes(svc.get("banner", "RFB 003.008\n").encode())
    client = h.recv_exact(12)
    if len(client) < 12 or not client.startswith(b"RFB "):
        return
    h.event("vnc_handshake", client_version=client.strip().decode("ascii", "replace"))
    reason = svc.get("auth_failure_reason", "Authentication failed").encode()
    types = list(svc.get("security_types", [2]))
    if client < b"RFB 003.007\n":
        h.send_bytes(struct.pack(">I", 2))
    else:
        h.send_bytes(bytes([len(types)] + types))
        choice = h.recv_exact(1)
        if choice != b"\x02":
            if choice:
                h.event("vnc_security_choice", security_type=choice[0])
                h.send_bytes(struct.pack(">II", 1, len(reason)) + reason)
            return
    challenge = os.urandom(16)
    h.send_bytes(challenge)
    response = h.recv_exact(16)
    if len(response) < 16:
        return
    h.event("login_attempt", username="", password_hash=response.hex(), challenge=challenge.hex())
    h.pause_auth()
    h.send_bytes(struct.pack(">II", 1, len(reason)) + reason)


def nfs(h, svc: dict) -> None:
    """Linux knfsd: NFS v3 and v4, with no exports this client can reach."""
    for _ in range(MAX_COMMANDS):
        mark = h.recv_exact(4)
        if len(mark) < 4:
            return
        size = struct.unpack(">I", mark)[0] & 0x7FFFFFFF
        if not 24 <= size <= _limit(h):
            return
        msg = h.recv_exact(size)
        xid, kind, rpc, program, version, proc = struct.unpack(">IIIIII", msg[:24])
        if kind != 0 or rpc != 2:
            return
        flavor, cred_len = struct.unpack(">II", msg[24:32])
        h.event("nfs_call", program=program, version=version, procedure=proc, auth_flavor=flavor)
        accepted = struct.pack(">IIIII", xid, 1, 0, 0, 0)
        if program != 100003:
            reply = accepted + struct.pack(">I", 1)                 # PROG_UNAVAIL
        elif version not in (3, 4):
            reply = accepted + struct.pack(">III", 2, 3, 4)         # PROG_MISMATCH
        elif proc == 0:
            reply = accepted + struct.pack(">I", 0)                 # NULL succeeds
        elif flavor != 1:
            reply = struct.pack(">IIIII", xid, 1, 1, 1, 5)          # AUTH_ERROR, too weak
        elif version == 3:
            reply = accepted + struct.pack(">III", 0, 10001, 0)     # NFS3ERR_BADHANDLE
        else:
            off = 32 + cred_len + (-cred_len % 4) + 8               # skip credentials and verifier
            tag_len = struct.unpack(">I", msg[off:off + 4])[0]
            tag = msg[off + 4:off + 4 + tag_len + (-tag_len % 4)]
            reply = accepted + struct.pack(">II", 0, 10008) + struct.pack(">I", tag_len) + tag + b"\0\0\0\0"    # DELAY
        h.send_bytes(struct.pack(">I", 0x80000000 | len(reply)) + reply)


HANDLERS = {
    "ftp": ftp, "smtp": smtp, "redis": redis, "https": https, "dns": dns,
    "mysql": mysql, "postgres": postgres, "mongodb": mongodb, "ldap": ldap,
    "smb": smb, "rdp": rdp, "vnc": vnc, "nfs": nfs,
}
