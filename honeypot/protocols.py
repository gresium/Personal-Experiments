#!/usr/bin/env python3
"""
Fake service dialogues for the honeypot.

Each function speaks just enough of one real protocol for a client or scanner
to believe it, records what the client offered, then refuses. None of them
grants access, relays anything, stores data or runs anything a client sends.

Each takes the connection handler `h` (see honeypot.HoneypotHandler) and the
service's config dict. All reads go through the handler's bounded I/O, so the
line, connection-byte and lifetime caps apply. Malformed binary input raises
IndexError/struct.error, which the handler records as an "error" event.

Where a protocol sends the password in the clear (FTP, SMTP, Redis, PostgreSQL,
LDAP) a credential honeytoken can fire. MySQL, MongoDB, SMB and VNC only send a
challenge response, and SSH and RDP encrypt it, so those log what they can.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import ssl
import struct
import time
from email.utils import formatdate

MAX_COMMANDS = 32


def _limit(h) -> int:
    return h.limits["max_conn_bytes"]


# --------------------------------------------------------------------------- #
# SSH (pre-encryption part only)
# --------------------------------------------------------------------------- #

_SSH_ALGOS = [
    "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
    "rsa-sha2-512,rsa-sha2-256,ssh-ed25519",
    "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512",
    "none,zlib@openssh.com", "none,zlib@openssh.com", "", "",
]


def ssh_client(h, svc: dict, client_version: str) -> None:
    """A real SSH client: swap KEXINITs, log its fingerprint, then hang up.

    Passwords are only sent after key exchange, which needs real cryptography,
    so real SSH clients are fingerprinted here but never give up credentials.
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
            body = h.recv_exact(size - 1)
            if body[:1] == b"\x14":
                off, lists = 17, []
                for _ in range(10):
                    n = struct.unpack(">I", body[off:off + 4])[0]
                    lists.append(body[off + 4:off + 4 + n].decode("ascii", "replace"))
                    off += 4 + n
                fields["kex_algorithms"] = lists[0]
                # HASSH: a stable fingerprint of the client's SSH implementation.
                fields["hassh"] = hashlib.md5(
                    ";".join((lists[0], lists[2], lists[4], lists[6])).encode()).hexdigest()
    h.event("ssh_client_hello", **fields)


# --------------------------------------------------------------------------- #
# Text protocols
# --------------------------------------------------------------------------- #

def ftp(h, svc: dict) -> None:
    h.send(svc.get("banner", "220 (vsFTPd 3.0.5)\r\n"))
    user = None
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
            else:
                h.login(user, arg)
                h.send("530 Login incorrect.\r\n")
                user = None
        elif verb == "QUIT":
            h.send("221 Goodbye.\r\n")
            return
        else:
            h.event("command", command=line)
            if verb == "SYST":
                h.send("215 UNIX Type: L8\r\n")
            elif verb == "FEAT":
                h.send("211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n"
                       " REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n")
            else:
                h.send("530 Please login with USER and PASS.\r\n")


def smtp(h, svc: dict) -> None:
    host = svc.get("hostname", "mail.example.com")
    h.send(svc.get("banner", f"220 {host} ESMTP Postfix (Ubuntu)\r\n"))
    fail = "535 5.7.8 Error: authentication failed: authentication failure\r\n"
    for _ in range(MAX_COMMANDS):
        line = h.recv_line()
        if not line and h.eof:
            return
        verb, _, arg = line.partition(" ")
        verb = verb.upper()
        if verb == "EHLO":
            h.event("command", command=line)
            h.send(f"250-{host}\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n"
                   "250-ETRN\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n"
                   "250-8BITMIME\r\n250 DSN\r\n")
        elif verb == "HELO":
            h.event("command", command=line)
            h.send(f"250 {host}\r\n")
        elif verb == "AUTH":
            mech, _, initial = arg.partition(" ")
            mech = mech.upper()
            if mech == "PLAIN":
                if not initial:
                    h.send("334 \r\n")
                    initial = h.recv_line()
                try:
                    parts = base64.b64decode(initial).decode("utf-8", "replace").split("\0")
                    h.login(parts[1], parts[2])
                except (ValueError, IndexError):
                    h.send("501 5.5.2 Cannot decode response\r\n")
                    continue
                h.send(fail)
            elif mech == "LOGIN":
                try:
                    if initial:
                        user = base64.b64decode(initial).decode("utf-8", "replace")
                    else:
                        h.send("334 VXNlcm5hbWU6\r\n")
                        user = base64.b64decode(h.recv_line()).decode("utf-8", "replace")
                    h.send("334 UGFzc3dvcmQ6\r\n")
                    password = base64.b64decode(h.recv_line()).decode("utf-8", "replace")
                except ValueError:
                    h.send("501 5.5.2 Cannot decode response\r\n")
                    continue
                h.login(user, password)
                h.send(fail)
            else:
                h.send("535 5.7.8 Error: authentication failed: Invalid authentication mechanism\r\n")
        elif verb == "MAIL":
            h.event("command", command=line)
            h.send("250 2.1.0 Ok\r\n")
        elif verb == "RCPT":
            h.event("command", command=line)
            h.send("554 5.7.1 Relay access denied\r\n")
        elif verb == "DATA":
            h.event("command", command=line)
            h.send("554 5.5.1 Error: no valid recipients\r\n")
        elif verb in ("RSET", "NOOP"):
            h.send("250 2.0.0 Ok\r\n")
        elif verb == "VRFY":
            h.event("command", command=line)
            h.send("252 2.0.0 Cannot verify user\r\n")
        elif verb == "QUIT":
            h.send("221 2.0.0 Bye\r\n")
            return
        else:
            h.event("command", command=line)
            h.send("502 5.5.2 Error: command not recognized\r\n")


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
    for _ in range(MAX_COMMANDS):
        args = _redis_command(h)
        if not args:
            if h.eof:
                return
            continue
        verb = args[0].upper()
        if verb == "AUTH" and len(args) >= 2:
            user, password = (args[1], args[2]) if len(args) >= 3 else ("default", args[1])
            h.login(user, password)
            h.send("-WRONGPASS invalid username-password pair or user is disabled.\r\n")
        elif verb == "QUIT":
            h.send("+OK\r\n")
            return
        else:
            h.event("command", command=" ".join(args))
            h.send("-NOAUTH Authentication required.\r\n")


# --------------------------------------------------------------------------- #
# HTTP(S) responses
# --------------------------------------------------------------------------- #

def http_401(svc: dict, path: str, host: str) -> str:
    if svc.get("profile") == "elasticsearch":
        schemes = ['Basic realm="security" charset="UTF-8"', "ApiKey"]
        reason = f"missing authentication credentials for REST request [{path[:200]}]"
        error = {"type": "security_exception", "reason": reason,
                 "header": {"WWW-Authenticate": schemes}}
        body = json.dumps({"error": {"root_cause": [error], **error}, "status": 401},
                          separators=(",", ":"))
        head = ("HTTP/1.1 401 Unauthorized\r\n"
                f"WWW-Authenticate: {schemes[0]}\r\nWWW-Authenticate: {schemes[1]}\r\n"
                "X-elastic-product: Elasticsearch\r\n"
                "content-type: application/json\r\n")
    else:
        server = svc.get("server", "Apache/2.4.52 (Ubuntu)")
        port = svc.get("port", 80)
        body = ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
                "<title>401 Unauthorized</title>\n</head><body>\n<h1>Unauthorized</h1>\n"
                "<p>This server could not verify that you\nare authorized to access the "
                "document\nrequested.  Either you supplied the wrong\ncredentials (e.g., bad "
                "password), or your\nbrowser doesn't understand how to supply\nthe "
                "credentials required.</p>\n<hr>\n"
                f"<address>{server} Server at {html.escape(host.split(':')[0][:100])} "
                f"Port {port}</address>\n</body></html>\n")
        head = ("HTTP/1.1 401 Unauthorized\r\n"
                f"Date: {formatdate(usegmt=True)}\r\n"
                f"Server: {server}\r\n"
                'WWW-Authenticate: Basic realm="Restricted"\r\n'
                "Content-Type: text/html; charset=iso-8859-1\r\n")
    return head + f"Content-Length: {len(body.encode())}\r\nConnection: close\r\n\r\n" + body


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
    """Real TLS if a certificate is configured, otherwise log the hello and refuse."""
    cert, key = svc.get("tls_cert"), svc.get("tls_key")
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        try:
            tls = context.wrap_socket(h.request, server_side=True)
        except OSError as exc:
            h.event("tls_error", detail=repr(exc)[:200])
            return
        h.request = tls
        try:
            h._do_http(svc)
        finally:
            tls.close()
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
    version = svc.get("version", "9.18.28-0ubuntu0.22.04.1-Ubuntu").encode()
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

def mysql(h, svc: dict) -> None:
    version = svc.get("version", "8.0.39-0ubuntu0.22.04.1")
    scramble = bytes(b % 94 + 33 for b in os.urandom(20))
    # Everything a normal server offers except TLS and LOCAL INFILE.
    caps = 0x003FF74F
    greeting = (b"\x0a" + version.encode() + b"\0"
                + struct.pack("<I", int.from_bytes(os.urandom(2), "little") + 8)
                + scramble[:8] + b"\0" + struct.pack("<HBHHB", caps & 0xFFFF, 255, 2, caps >> 16, 21)
                + b"\0" * 10 + scramble[8:] + b"\0" + b"mysql_native_password\0")
    h.send_bytes(struct.pack("<I", len(greeting))[:3] + b"\0" + greeting)

    head = h.recv_exact(4)
    if len(head) < 4:
        return
    size = int.from_bytes(head[:3], "little")
    body = h.recv_exact(min(size, _limit(h)))
    if len(body) < 33:
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
    database = ""
    if client_caps & 0x8 and off < len(body):
        database = body[off:body.index(0, off)].decode("utf-8", "replace")
    h.event("login_attempt", username=user, database=database,
            password_hash=response.hex(), challenge=scramble.hex())
    using = "YES" if response else "NO"
    text = f"Access denied for user '{user[:64]}'@'{h.client_address[0]}' (using password: {using})"
    err = b"\xff" + struct.pack("<H", 1045) + b"#28000" + text.encode("utf-8", "replace")
    h.send_bytes(struct.pack("<I", len(err))[:3] + bytes([head[3] + 1]) + err)


def postgres(h, svc: dict) -> None:
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
        if code in (80877103, 80877104):        # SSLRequest / GSSENCRequest
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
    h.send_bytes(b"R" + struct.pack(">II", 8, 3))   # ask for a cleartext password
    head = h.recv_exact(5)
    password = ""
    if len(head) == 5 and head[:1] == b"p":
        size = struct.unpack(">I", head[1:])[0]
        if 4 <= size <= _limit(h):
            password = h.recv_exact(size - 4).rstrip(b"\0").decode("utf-8", "replace")
    h.login(user, password, database=params.get("database", user),
            application=params.get("application_name", ""))
    fields = (b"SFATAL\0VFATAL\0C28P01\0Mpassword authentication failed for user \""
              + user[:64].encode("utf-8", "replace") + b"\"\0Fauth.c\0L326\0Rauth_failed\0\0")
    h.send_bytes(b"E" + struct.pack(">I", 4 + len(fields)) + fields)


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
        elif isinstance(value, list):
            out += b"\x04" + name + _bson({str(i): v for i, v in enumerate(value)})
        elif isinstance(value, tuple):          # ("date", milliseconds)
            out += b"\x09" + name + struct.pack("<q", value[1])
    return struct.pack("<i", len(out) + 5) + out + b"\0"


def mongodb(h, svc: dict) -> None:
    version = svc.get("version", "7.0.14")
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
        if low in ("hello", "ismaster"):
            reply = {"ismaster": True, "helloOk": True, "maxBsonObjectSize": 16777216,
                     "maxMessageSizeBytes": 48000000, "maxWriteBatchSize": 100000,
                     "localTime": ("date", int(time.time() * 1000)),
                     "logicalSessionTimeoutMinutes": 30, "connectionId": 1,
                     "minWireVersion": 0, "maxWireVersion": 21, "readOnly": False, "ok": 1.0}
            h.event("mongo_hello", command=command)
        elif low == "buildinfo":
            parts = [int(p) for p in version.split(".")] + [0]
            reply = {"version": version, "modules": [], "allocator": "tcmalloc",
                     "javascriptEngine": "mozjs", "versionArray": parts, "bits": 64,
                     "debug": False, "maxBsonObjectSize": 16777216, "ok": 1.0}
            h.event("command", command=command)
        elif low == "ping":
            reply = {"ok": 1.0}
        elif low == "saslstart":
            found = re.search(rb"n=([^,\0]{1,128}),r=", doc)
            h.event("login_attempt", username=found.group(1).decode("utf-8", "replace") if found else "")
            reply = {"ok": 0.0, "errmsg": "Authentication failed.", "code": 18,
                     "codeName": "AuthenticationFailed"}
        else:
            h.event("command", command=command)
            reply = {"ok": 0.0, "errmsg": f"command {command[:64]} requires authentication",
                     "code": 13, "codeName": "Unauthorized"}
        encoded = _bson(reply)
        if opcode == 2004:
            payload, code = struct.pack("<iqii", 8, 0, 0, 1) + encoded, 1
        else:
            payload, code = struct.pack("<iB", 0, 0) + encoded, 2013
        h.send_bytes(struct.pack("<iiii", 16 + len(payload), 1, request_id, code) + payload)


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


def ldap(h, svc: dict) -> None:
    def result(tag: int, msg_id: bytes, code: int) -> None:
        body = _ber(0x0A, bytes([code])) + _ber(4, b"") + _ber(4, b"")
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
                if not dn and not secret:
                    h.event("ldap_anonymous_bind")
                    result(0x61, msg_id, 0)
                    continue
                h.login(dn, secret.decode("utf-8", "replace"))
            else:
                h.event("login_attempt", username=dn, auth="sasl")
            result(0x61, msg_id, 49)            # invalidCredentials
        elif op == 0x63:                        # SearchRequest
            _, base, _ = _ber_read(value, 0)
            h.event("ldap_search", base=base.decode("utf-8", "replace"))
            if not base:
                def attr(name: bytes, *vals: bytes) -> bytes:
                    return _ber(0x30, _ber(4, name) + _ber(0x31, b"".join(_ber(4, v) for v in vals)))
                suffix = svc.get("naming_context", "dc=corp,dc=local").encode()
                attrs = attr(b"objectClass", b"top", b"OpenLDAProotDSE") + attr(b"namingContexts", suffix) \
                    + attr(b"supportedLDAPVersion", b"3")
                entry = _ber(0x64, _ber(4, b"") + _ber(0x30, attrs))
                h.send_bytes(_ber(0x30, _ber(2, msg_id) + entry))
                result(0x65, msg_id, 0)
            else:
                result(0x65, msg_id, 50)        # insufficientAccessRights
        elif op == 0x42:                        # UnbindRequest
            return
        elif op == 0x77:                        # ExtendedRequest (e.g. StartTLS)
            result(0x78, msg_id, 2)
        else:
            h.event("command", command=f"ldap op 0x{op:02x}")
            return


# --------------------------------------------------------------------------- #
# SMB2 + NTLM (captures the NTLM response; there is no plaintext to capture)
# --------------------------------------------------------------------------- #

_NTLM_OID = bytes.fromhex("2b06010401823702020a")
_SPNEGO_OID = bytes.fromhex("2b0601050502")


def _filetime() -> int:
    return int((time.time() + 11644473600) * 10_000_000)


def _ntlm_challenge(challenge: bytes, domain: str, computer: str) -> bytes:
    d, c = domain.encode("utf-16-le"), computer.encode("utf-16-le")

    def av(kind: int, value: bytes) -> bytes:
        return struct.pack("<HH", kind, len(value)) + value

    info = (av(2, d) + av(1, c) + av(4, d) + av(3, c)
            + av(7, struct.pack("<Q", _filetime())) + av(0, b""))
    return struct.pack("<8sIHHII8s8sHHI8s", b"NTLMSSP\0", 2, len(d), len(d), 56, 0xE2898215,
                       challenge, b"\0" * 8, len(info), len(info), 56 + len(d),
                       bytes.fromhex("0a00ba470000000f")) + d + info


def smb(h, svc: dict) -> None:
    domain = svc.get("domain", "WORKGROUP")
    computer = svc.get("computer", "FILESRV01")
    session = int.from_bytes(os.urandom(7), "little") | 1
    challenge, guid, booted = os.urandom(8), os.urandom(16), _filetime() - 36_000_000_000_000
    mech = _ber(0x60, _ber(6, _SPNEGO_OID) + _ber(0xA0, _ber(0x30, _ber(0xA0, _ber(0x30, _ber(6, _NTLM_OID))))))

    def send(command: int, message_id: bytes, status: int, body: bytes, sid: int = 0) -> None:
        header = struct.pack("<4sHHIHHI I8sIIQ16s".replace(" ", ""), b"\xfeSMB", 64, 1, status, command,
                             32, 1, 0, message_id, 0, 0, sid, b"\0" * 16)
        packet = header + body
        h.send_bytes(b"\0" + len(packet).to_bytes(3, "big") + packet)

    def negotiate(message_id: bytes, dialect: int) -> None:
        h.event("smb_negotiate", dialect=f"0x{dialect:04x}")
        body = struct.pack("<HHHH16sIIIIQQHHI", 65, 1, dialect, 0, guid, 7, 8388608, 8388608,
                           8388608, _filetime(), booted, 128, len(mech), 0) + mech
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
                return                          # modern servers refuse SMB1
            negotiate(b"\0" * 8, 0x02FF)
            continue
        if msg[:4] != b"\xfeSMB":
            return
        command = struct.unpack("<H", msg[12:14])[0]
        message_id = msg[24:32]
        if command == 0:
            count = struct.unpack("<H", msg[66:68])[0]
            offered = struct.unpack(f"<{count}H", msg[100:100 + 2 * count])
            dialect = next((d for d in (0x0302, 0x0300, 0x0210, 0x0202) if d in offered), None)
            if dialect is None:
                return
            negotiate(message_id, dialect)
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
                token = _ntlm_challenge(challenge, domain, computer)
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
                send(1, message_id, 0xC000006D, struct.pack("<HHI", 9, 0, 0) + b"\0", session)
                return
        else:
            send(command, message_id, 0xC0000022, struct.pack("<HHI", 9, 0, 0) + b"\0", session)
            return


# --------------------------------------------------------------------------- #
# RDP, VNC, NFS
# --------------------------------------------------------------------------- #

def rdp(h, svc: dict) -> None:
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
    if requested & 3:
        chosen = 1 if requested & 1 else 2
        h.send_bytes(x224 + b"\x02\x00\x08\x00" + struct.pack("<I", chosen))
    else:
        h.send_bytes(x224 + b"\x03\x00\x08\x00" + struct.pack("<I", 1))  # SSL_REQUIRED_BY_SERVER


def vnc(h, svc: dict) -> None:
    h.send_bytes(svc.get("banner", "RFB 003.008\n").encode())
    client = h.recv_exact(12)
    if len(client) < 12 or not client.startswith(b"RFB "):
        return
    h.event("vnc_handshake", client_version=client.strip().decode("ascii", "replace"))
    if client < b"RFB 003.007\n":
        h.send_bytes(struct.pack(">I", 2))
    else:
        h.send_bytes(b"\x01\x02")
        if h.recv_exact(1) != b"\x02":
            return
    challenge = os.urandom(16)
    h.send_bytes(challenge)
    response = h.recv_exact(16)
    if len(response) < 16:
        return
    h.event("login_attempt", username="", password_hash=response.hex(), challenge=challenge.hex())
    reason = b"Authentication failed"
    h.send_bytes(struct.pack(">II", 1, len(reason)) + reason)


def nfs(h, svc: dict) -> None:
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
        h.event("nfs_call", program=program, version=version, procedure=proc)
        accepted = struct.pack(">IIIII", xid, 1, 0, 0, 0)
        if program != 100003:
            reply = accepted + struct.pack(">I", 1)                 # PROG_UNAVAIL
        elif version not in (3, 4):
            reply = accepted + struct.pack(">III", 2, 3, 4)         # PROG_MISMATCH
        elif proc == 0:
            reply = accepted + struct.pack(">I", 0)                 # NULL succeeds
        else:
            reply = struct.pack(">IIIII", xid, 1, 1, 1, 5)          # AUTH_ERROR, too weak
        h.send_bytes(struct.pack(">I", 0x80000000 | len(reply)) + reply)


HANDLERS = {
    "ftp": ftp, "smtp": smtp, "redis": redis, "https": https, "dns": dns,
    "mysql": mysql, "postgres": postgres, "mongodb": mongodb, "ldap": ldap,
    "smb": smb, "rdp": rdp, "vnc": vnc, "nfs": nfs,
}
