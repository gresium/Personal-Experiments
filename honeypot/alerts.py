#!/usr/bin/env python3
"""
Alert dispatch for the honeypot.

A normal probe is written to the main honeypot log. An *alert* is reserved for
high-signal events, above all a honeytoken being used, and goes to its own
alert log and (optionally) to a webhook so it can page a human or land in a
chat channel / SIEM.

Design choices:
  * The webhook POST runs on a background thread with a short timeout, so a slow
    or dead endpoint never stalls a connection handler.
  * Lower-severity alerts are rate-limited per kind; 'critical' alerts
    (honeytoken triggers) are always sent.
  * No third-party libraries; urllib only.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

_alert_log = logging.getLogger("honeypot.alerts")
_webhook_url: str | None = None
_min_interval = 5
_last_sent: dict[str, float] = {}
_lock = threading.Lock()
# Critical alerts aren't rate-limited, so cap how many POSTs can be in flight.
_post_slots = threading.BoundedSemaphore(32)


def setup(path: str, webhook_url: str | None, min_interval: int,
          max_bytes: int, backups: int) -> None:
    global _webhook_url, _min_interval
    _webhook_url = webhook_url or None
    _min_interval = int(min_interval)
    handler = RotatingFileHandler(path, maxBytes=int(max_bytes),
                                  backupCount=int(backups), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _alert_log.setLevel(logging.INFO)
    _alert_log.addHandler(handler)
    _alert_log.propagate = False


def dispatch(alert: dict) -> None:
    """Record an alert and, for high severity, push it to the webhook."""
    alert = {"ts": datetime.now(timezone.utc).isoformat(), **alert}
    severity = str(alert.get("severity", "info"))
    _alert_log.info(json.dumps(alert, ensure_ascii=True, default=str))

    banner = "!!! " if severity == "critical" else ""
    summary = (f"{banner}[ALERT:{severity}] {alert.get('kind','')} "
               f"token={alert.get('token_id','-')} from "
               f"{alert.get('src_ip','-')}:{alert.get('src_port','-')} "
               f"({alert.get('label','')})")
    print(summary, flush=True)
    # Slack and Teams incoming webhooks reject a payload with no "text" field.
    alert = {"text": summary, **alert}

    if not _webhook_url:
        return
    if severity != "critical":
        kind = str(alert.get("kind", ""))
        with _lock:
            if time.time() - _last_sent.get(kind, 0.0) < _min_interval:
                return
            _last_sent[kind] = time.time()
    if not _post_slots.acquire(blocking=False):
        _note("webhook_dropped", "too many webhook posts in flight")
        return
    threading.Thread(target=_post, args=(_webhook_url, alert), daemon=True).start()


def _note(kind: str, detail: str) -> None:
    _alert_log.info(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                "severity": "warning", "kind": kind, "detail": detail}))


def _post(url: str, alert: dict) -> None:
    try:
        data = json.dumps(alert, default=str).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "honeypot"},
            method="POST")
        urllib.request.urlopen(req, timeout=4).read()
    except Exception as exc:
        # Best-effort, but a lost alert must leave a trace. The URL is a secret,
        # so only the error type and status go in the log.
        _note("webhook_failed", f"{type(exc).__name__} {getattr(exc, 'code', '')}".strip())
    finally:
        _post_slots.release()
