#!/usr/bin/env python3
"""
Honeytoken manager (CLI).

Create, list and revoke the decoys the honeypot watches for. A honeytoken has
no legitimate use, so any hit on it is a high-confidence intrusion signal.

Token types
-----------
  credential   A fake username/password. Plant it somewhere tempting (a fake
               entry in a password manager, a config file, a wiki page that
               says "ssh admin@<honeypot-host>"). If anyone tries it against
               the honeypot's fake SSH/Telnet/HTTP login, you get a critical alert.

  web          A unique canary URL (http://<honeypot>/t/<id>). Embed it where a
               snoop would follow it: a document's hidden link, a spreadsheet
               cell, a DNS record, an email signature, a fake API endpoint in
               source code. Any request to it raises a critical alert.

  file         A decoy file (e.g. aws_credentials.txt) written into the decoy
               folder, containing an embedded canary URL. Serve it from a file
               share or leave it on a host. When someone opens or exfiltrates it
               and the embedded URL is fetched, you get a critical alert. The
               honeypot serves the file's content at its URL so the fetch looks real.

Examples
--------
  python3 honeytokens.py -c config.json new credential --label "fake DB admin" \\
          --planted-at "wiki: infra runbook"
  python3 honeytokens.py -c config.json new web --label "canary link in budget.xlsx" \\
          --base-url https://trap.example.com
  python3 honeytokens.py -c config.json new file --name aws_credentials.txt \\
          --label "AWS keys on fileserver" --base-url https://trap.example.com
  python3 honeytokens.py -c config.json list
  python3 honeytokens.py -c config.json revoke <id>
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from datetime import datetime, timezone

import honeypot  # reuse config loading + path resolution
from tokens import TokenStore, new_id


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _store(args) -> TokenStore:
    cfg = honeypot.load_config(args.config)
    return TokenStore(honeypot.resolve_token_store(cfg))


def _decoy_dir(args) -> str:
    cfg = honeypot.load_config(args.config)
    return cfg.get("decoy_dir") or os.path.join(
        cfg.get("state_dir") or honeypot.default_state_dir(), "decoys")


def _fake_password() -> str:
    # Looks like a real password, is not one of yours.
    import string
    alpha = string.ascii_letters + string.digits
    return "".join(secrets.choice(alpha) for _ in range(16))


def cmd_new_credential(args) -> int:
    store = _store(args)
    token = {
        "id": new_id(), "type": "credential",
        "label": args.label or "credential honeytoken",
        "planted_at": args.planted_at or "",
        "created": _now(),
        "username": args.username or "svc_backup",
        "password": args.password or _fake_password(),
    }
    store.add(token)
    print("Created credential honeytoken:")
    print(f"  id         {token['id']}")
    print(f"  username   {token['username']}")
    print(f"  password   {token['password']}")
    print(f"  label      {token['label']}")
    print("\nPlant these exact credentials somewhere tempting. If anyone tries")
    print("them against the honeypot's fake login, you get a critical alert.")
    return 0


def cmd_new_web(args) -> int:
    store = _store(args)
    tid = new_id()
    base = args.base_url.rstrip("/")
    token = {
        "id": tid, "type": "web",
        "label": args.label or "web canary",
        "planted_at": args.planted_at or "",
        "created": _now(),
        "path": f"/t/{tid}",
        "url": f"{base}/t/{tid}",
    }
    store.add(token)
    print("Created web canary honeytoken:")
    print(f"  id    {tid}")
    print(f"  url   {token['url']}")
    print(f"  label {token['label']}")
    print("\nEmbed that URL where a snoop would follow it (hidden link in a doc,")
    print("a spreadsheet cell, a fake API endpoint, an email signature). Any")
    print("request to it raises a critical alert.")
    return 0


def cmd_new_file(args) -> int:
    store = _store(args)
    tid = new_id()
    base = args.base_url.rstrip("/")
    url = f"{base}/t/{tid}"
    decoy_dir = _decoy_dir(args)
    os.makedirs(decoy_dir, exist_ok=True)
    filename = args.name or "credentials.txt"
    path = os.path.join(decoy_dir, filename)

    content = (
        "# Infrastructure credentials (DO NOT COMMIT)\n"
        "# Auto-synced from the internal vault.\n"
        "[default]\n"
        f"aws_access_key_id = AKIA{secrets.token_hex(8).upper()}\n"
        f"aws_secret_access_key = {secrets.token_urlsafe(30)}\n"
        f"vault_sync_url = {url}\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    token = {
        "id": tid, "type": "file",
        "label": args.label or f"decoy file {filename}",
        "planted_at": args.planted_at or "",
        "created": _now(),
        "path": f"/t/{tid}", "url": url,
        "file": path, "filename": filename,
    }
    store.add(token)
    print("Created decoy file honeytoken:")
    print(f"  id    {tid}")
    print(f"  file  {path}")
    print(f"  url   {url}  (embedded inside the file)")
    print(f"  label {token['label']}")
    print("\nCopy that file somewhere tempting (a share, a home directory). When")
    print("someone opens or exfiltrates it and the embedded URL is fetched, you")
    print("get a critical alert. The honeypot serves the file's content at the URL.")
    return 0


def cmd_list(args) -> int:
    tokens = _store(args).all()
    if not tokens:
        print("No honeytokens yet. Create one with:  honeytokens.py new ...")
        return 0
    print(f"{'ID':<18}{'TYPE':<12}{'LABEL':<30}PLANTED AT")
    print("-" * 78)
    for t in tokens:
        print(f"{t.get('id',''):<18}{t.get('type',''):<12}"
              f"{(t.get('label','') or '')[:28]:<30}{t.get('planted_at','')}")
    print(f"\n{len(tokens)} token(s). Store: {_store(args).path}")
    return 0


def cmd_revoke(args) -> int:
    removed = _store(args).revoke(args.id)
    print(f"Revoked {removed} token(s) with id {args.id}." if removed
          else f"No token found with id {args.id}.")
    return 0 if removed else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Manage honeytokens for the honeypot.")
    p.add_argument("-c", "--config", help="path to the honeypot JSON config")
    sub = p.add_subparsers(dest="cmd", required=True)

    new = sub.add_parser("new", help="create a token").add_subparsers(dest="kind", required=True)

    c = new.add_parser("credential", help="fake username/password")
    c.add_argument("--label"); c.add_argument("--planted-at", dest="planted_at")
    c.add_argument("--username"); c.add_argument("--password")
    c.set_defaults(func=cmd_new_credential)

    w = new.add_parser("web", help="unique canary URL")
    w.add_argument("--label"); w.add_argument("--planted-at", dest="planted_at")
    w.add_argument("--base-url", default="http://HONEYPOT-HOST:8080",
                   help="public base URL of the honeypot's HTTP service")
    w.set_defaults(func=cmd_new_web)

    f = new.add_parser("file", help="decoy file with an embedded canary URL")
    f.add_argument("--label"); f.add_argument("--planted-at", dest="planted_at")
    f.add_argument("--name", help="decoy file name (e.g. aws_credentials.txt)")
    f.add_argument("--base-url", default="http://HONEYPOT-HOST:8080")
    f.set_defaults(func=cmd_new_file)

    ls = sub.add_parser("list", help="list all tokens"); ls.set_defaults(func=cmd_list)
    rv = sub.add_parser("revoke", help="remove a token by id")
    rv.add_argument("id"); rv.set_defaults(func=cmd_revoke)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
