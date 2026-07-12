from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

from cryptography.hazmat.primitives import serialization

from crl.service import crl_number, generate_crl


def default_crl_dir() -> Path:
    return Path(os.getenv("EDUPKI_CRL_DIR", "data/crl"))


def publish_crl_if_needed(revoked_certificates: Iterable[Mapping[str, object]], output_dir: str | Path | None = None) -> dict[str, object]:
    directory = Path(output_dir) if output_dir is not None else default_crl_dir()
    directory.mkdir(parents=True, exist_ok=True)
    revoked = _normalize_revoked(revoked_certificates)
    fingerprint = _revoked_fingerprint(revoked)
    manifest = load_manifest(directory)
    latest_pem = directory / "latest.crl.pem"
    latest_der = directory / "latest.crl.der"

    if manifest.get("revoked_fingerprint") == fingerprint and latest_pem.exists() and latest_der.exists():
        return manifest

    number = int(manifest.get("current_number", 0)) + 1
    crl = generate_crl(revoked, crl_number=number)
    pem = crl.public_bytes(serialization.Encoding.PEM)
    der = crl.public_bytes(serialization.Encoding.DER)
    pem_path = directory / f"crl-{number}.pem"
    der_path = directory / f"crl-{number}.der"
    _write_bytes(pem_path, pem)
    _write_bytes(der_path, der)
    _write_bytes(latest_pem, pem)
    _write_bytes(latest_der, der)

    version = {
        "number": number,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_update": crl.last_update_utc.isoformat(),
        "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
        "revoked_count": len(revoked),
        "pem_path": pem_path.name,
        "der_path": der_path.name,
        "pem_sha256": hashlib.sha256(pem).hexdigest(),
        "der_sha256": hashlib.sha256(der).hexdigest(),
        "crl_number": crl_number(crl),
    }
    versions = [*manifest.get("versions", []), version]
    next_manifest = {
        "current_number": number,
        "revoked_fingerprint": fingerprint,
        "latest_pem": latest_pem.name,
        "latest_der": latest_der.name,
        "versions": versions[-50:],
    }
    _write_text(directory / "manifest.json", json.dumps(next_manifest, indent=2, sort_keys=True))
    return next_manifest


def load_manifest(output_dir: str | Path | None = None) -> dict[str, object]:
    directory = Path(output_dir) if output_dir is not None else default_crl_dir()
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        return {"current_number": 0, "versions": []}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def latest_crl_bytes(revoked_certificates: Iterable[Mapping[str, object]], encoding: str, output_dir: str | Path | None = None) -> bytes:
    directory = Path(output_dir) if output_dir is not None else default_crl_dir()
    manifest = publish_crl_if_needed(revoked_certificates, directory)
    key = "latest_der" if encoding == "der" else "latest_pem"
    return (directory / str(manifest[key])).read_bytes()


def versioned_crl_bytes(number: int, encoding: str, output_dir: str | Path | None = None) -> bytes:
    directory = Path(output_dir) if output_dir is not None else default_crl_dir()
    suffix = "der" if encoding == "der" else "pem"
    path = directory / f"crl-{number}.{suffix}"
    if not path.exists():
        raise FileNotFoundError(path)
    return path.read_bytes()


def _normalize_revoked(revoked_certificates: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
    normalized = []
    for item in revoked_certificates:
        revoked_at = item.get("revoked_at")
        if isinstance(revoked_at, datetime):
            revoked_at_value = revoked_at.astimezone(timezone.utc).isoformat()
        else:
            revoked_at_value = str(revoked_at or "")
        normalized.append(
            {
                "serial_number": str(item["serial_number"]),
                "revoked_at": revoked_at_value,
                "reason": str(item.get("reason") or "unspecified"),
            }
        )
    return sorted(normalized, key=lambda value: value["serial_number"])


def _revoked_fingerprint(revoked: list[dict[str, str]]) -> str:
    payload = json.dumps(revoked, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _write_bytes(path: Path, content: bytes) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(content)
    temp.replace(path)


def _write_text(path: Path, content: str) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(content, encoding="utf-8")
    temp.replace(path)

