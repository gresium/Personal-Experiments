#!/usr/bin/env python3
"""
Honeytoken store.

A honeytoken is a decoy that has no legitimate use: a fake credential, a unique
"canary" URL, or a decoy file. Because nothing real ever touches it, any use of
one is a high-confidence sign of an intruder.

This module stores tokens as JSON and lets the honeypot look them up fast:
  * credential tokens  -> matched when someone tries them at a fake login
  * web tokens         -> matched when someone requests their unique URL
  * file tokens        -> a web token plus a generated decoy file served at it

The store is shared between the CLI (honeytokens.py, which creates tokens) and
the running honeypot (honeypot.py, which reads them). The honeypot reloads the
file automatically when it changes, so new tokens take effect without a restart.
"""

from __future__ import annotations

import json
import os
import secrets
import threading


def new_id() -> str:
    """A unique, URL-safe id that also appears inside canary URLs."""
    return secrets.token_hex(8)  # 16 hex chars


class TokenStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._mtime: float | None = None
        self._tokens: list[dict] = []
        self._load()

    # -- persistence ------------------------------------------------------- #

    def _load(self) -> None:
        try:
            mtime = os.stat(self.path).st_mtime
        except FileNotFoundError:
            self._tokens, self._mtime = [], None
            return
        if mtime == self._mtime:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            self._tokens = data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            self._tokens = []
        self._mtime = mtime

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._tokens, f, indent=2)
        os.replace(tmp, self.path)
        try:
            self._mtime = os.stat(self.path).st_mtime
        except OSError:
            self._mtime = None

    # -- reads (used by the honeypot, reload on change) -------------------- #

    def all(self) -> list[dict]:
        with self._lock:
            self._load()
            return list(self._tokens)

    def find_credential(self, username: str, password: str) -> dict | None:
        for t in self.all():
            if t.get("type") == "credential" \
                    and t.get("username") == username and t.get("password") == password:
                return t
        return None

    def find_web(self, raw_path: str) -> dict | None:
        """A web/file token fires if its id appears anywhere in the requested path."""
        for t in self.all():
            if t.get("type") in ("web", "file") and t.get("id") and t["id"] in raw_path:
                return t
        return None

    # -- writes (used by the CLI) ------------------------------------------ #

    def add(self, token: dict) -> dict:
        with self._lock:
            self._load()
            self._tokens.append(token)
            self._save()
        return token

    def revoke(self, token_id: str) -> int:
        with self._lock:
            self._load()
            before = len(self._tokens)
            self._tokens = [t for t in self._tokens if t.get("id") != token_id]
            self._save()
            return before - len(self._tokens)
