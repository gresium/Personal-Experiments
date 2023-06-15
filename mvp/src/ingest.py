import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import Flask, request, g

app = Flask(__name__)

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "app.jsonl")

logger = logging.getLogger("secure_mvp")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=5)
handler.setLevel(logging.INFO)

class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "event": getattr(record, "event", "log"),
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            base.update(extra)
        return json.dumps(base, ensure_ascii=False)

handler.setFormatter(JsonLineFormatter())
logger.addHandler(handler)

@app.before_request
def _start_timer():
    g.request_id = uuid.uuid4().hex[:12]
    g.start = time.perf_counter()

@app.after_request
def _log_request(response):
    duration_ms = int((time.perf_counter() - g.start) * 1000)

    logger.info(
        "request completed",
        extra={
            "event": "request",
            "extra": {
                "request_id": g.request_id,
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "client_ip": request.headers.get("X-Forwarded-For", request.remote_addr),
                "user_agent": request.headers.get("User-Agent"),
            },
        },
    )
    return response

@app.post("/ingest")
def ingest():
    data = request.get_json(silent=True) or {}

    logger.info(
        "received payload",
        extra={
            "event": "ingest",
            "extra": {
                "request_id": g.request_id,
                "src_ip": data.get("src_ip"),
                "payload_keys": sorted(list(data.keys()))[:50],
            },
        },
    )

    return {"ok": True, "request_id": g.request_id}, 200
