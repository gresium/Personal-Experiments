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
    _alert_log.info(json.dumps(alert, ensure_ascii=False, default=str))

    banner = "!!! " if severity == "critical" else ""
    print(f"{banner}[ALERT:{severity}] {alert.get('kind','')} "
          f"token={alert.get('token_id','-')} from "
          f"{alert.get('src_ip','-')}:{alert.get('src_port','-')} "
          f"({alert.get('label','')})", flush=True)

    if not _webhook_url:
        return
    if severity != "critical":
        kind = str(alert.get("kind", ""))
        with _lock:
            if time.time() - _last_sent.get(kind, 0.0) < _min_interval:
                return
            _last_sent[kind] = time.time()
    threading.Thread(target=_post, args=(_webhook_url, alert), daemon=True).start()


def _post(url: str, alert: dict) -> None:
    try:
        data = json.dumps(alert, default=str).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "honeypot"},
            method="POST")
        urllib.request.urlopen(req, timeout=4).read()
    except Exception:
        # Alerting is best-effort; never let it crash or block the honeypot.
        pass
