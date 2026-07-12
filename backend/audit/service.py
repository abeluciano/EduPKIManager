from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditEntry:
    schema_version: int
    sequence_number: int
    timestamp: str
    operation: str
    actor: str
    result: str
    details: dict[str, Any]
    previous_hash: str
    entry_hash: str


@dataclass(frozen=True)
class AuditVerificationReport:
    valid_chain: bool
    entry_count: int
    first_hash: str | None
    last_hash: str | None
    broken_at_index: int | None
    errors: list[str]


def default_audit_log_path() -> Path:
    return Path(os.getenv("EDUPKI_DATA_DIR", "data")) / "audit" / "audit.jsonl"


def append_audit_entry(log_path: str | Path, operation: str, actor: str, result: str, details: dict[str, Any] | None = None) -> AuditEntry:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    previous_entry = _last_entry(path)
    previous_hash = str(previous_entry.get("entry_hash")) if previous_entry else "0" * 64
    sequence_number = int(previous_entry.get("sequence_number", _line_count(path)) if previous_entry else 0) + 1
    payload = {
        "schema_version": 2,
        "sequence_number": sequence_number,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "actor": actor,
        "result": result,
        "details": _json_safe(details or {}),
        "previous_hash": previous_hash,
    }
    entry_hash = _hash_payload(payload)
    payload["entry_hash"] = entry_hash
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return AuditEntry(**payload)


def verify_audit_log(log_path: str | Path) -> bool:
    return verify_audit_log_report(log_path).valid_chain


def verify_audit_log_report(log_path: str | Path) -> AuditVerificationReport:
    previous_hash = "0" * 64
    path = Path(log_path)
    if not path.exists():
        return AuditVerificationReport(True, 0, None, None, None, [])

    errors: list[str] = []
    first_hash = None
    last_hash = None
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for index, line in enumerate(lines, start=1):
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            return AuditVerificationReport(False, len(lines), first_hash, last_hash, index, [f"line {index}: invalid JSON ({exc.msg})"])
        entry_hash = payload.pop("entry_hash", None)
        if not entry_hash:
            return AuditVerificationReport(False, len(lines), first_hash, last_hash, index, [f"line {index}: missing entry_hash"])
        if payload["previous_hash"] != previous_hash:
            errors.append(f"line {index}: previous_hash does not match previous entry")
        if _hash_payload(payload) != entry_hash:
            errors.append(f"line {index}: entry_hash does not match payload")
        if errors:
            return AuditVerificationReport(False, len(lines), first_hash, last_hash, index, errors)
        first_hash = first_hash or entry_hash
        last_hash = entry_hash
        previous_hash = entry_hash
    return AuditVerificationReport(True, len(lines), first_hash, last_hash, None, [])


def read_audit_entries(log_path: str | Path) -> list[dict[str, Any]]:
    path = Path(log_path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _last_entry(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return None
    return json.loads(lines[-1])


def _line_count(path: Path) -> int:
    if not path.exists():
        return 0
    return len([line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()])


def _hash_payload(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(key): _json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_json_safe(item) for item in value]
        return str(value)
