import datetime
import json
import logging
import os
from logging.handlers import RotatingFileHandler

from flask import has_request_context, request

os.makedirs("logs", exist_ok=True)

_handler = RotatingFileHandler(
    "logs/audit.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8",
)
_handler.setFormatter(logging.Formatter("%(message)s"))

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

if not any(
    isinstance(handler, RotatingFileHandler)
    for handler in audit_logger.handlers
):
    audit_logger.addHandler(_handler)

audit_logger.propagate = False


def audit_log(level, user_id, action, details=None):
    """Write Auth-Service-compatible JSON audit records without credentials."""

    request_details = {}

    if has_request_context():
        request_details = {
            "ip": request.headers.get(
                "X-Forwarded-For", request.remote_addr or "unknown"
            ).split(",")[0].strip(),
            "method": request.method,
            "path": request.path,
        }

    record = {
        "action": action,
        "details": {
            **request_details,
            **(details or {}),
        },
        "level": logging.getLevelName(level).lower(),
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat().replace("+00:00", "Z"),
        "userId": str(user_id) if user_id is not None else "anonymous",
    }

    audit_logger.log(
        level,
        json.dumps(record, separators=(",", ":"), ensure_ascii=False),
    )
