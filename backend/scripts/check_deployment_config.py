from __future__ import annotations

import argparse
import os
from pathlib import Path


REQUIRED_PRODUCTION_VALUES = (
    "POSTGRES_PASSWORD",
    "CA_KEY_PASSWORD",
    "DJANGO_SECRET_KEY",
    "EDUPKI_ADMIN_PASSWORD",
)

UNSAFE_VALUES = {
    "",
    "admin123",
    "edupki",
    "change-me-admin-password",
    "change-me-ca-key-password",
    "change-me-django-secret-key",
    "change-me-postgres-password",
    "change-this-in-production",
    "change-me-dev-password",
    "dev-only-edupki-secret",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate EduPKIManager deployment configuration.")
    parser.add_argument("--env-file", type=Path, help="Optional .env file to validate.")
    parser.add_argument("--profile", choices=("demo", "production"), default="production")
    args = parser.parse_args()

    config = dict(os.environ)
    if args.env_file:
        config.update(_read_env_file(args.env_file))

    errors: list[str] = []
    warnings: list[str] = []

    for name in REQUIRED_PRODUCTION_VALUES:
        value = config.get(name, "")
        if _is_unsafe(value):
            message = f"{name} must be changed from the demo/default value."
            if args.profile == "production":
                errors.append(message)
            else:
                warnings.append(message)

    if len(config.get("DJANGO_SECRET_KEY", "")) < 32:
        message = "DJANGO_SECRET_KEY should be at least 32 characters."
        if args.profile == "production":
            errors.append(message)
        else:
            warnings.append(message)

    if args.profile == "production" and config.get("DJANGO_DEBUG", "1") != "0":
        errors.append("DJANGO_DEBUG must be 0 for production-like deployments.")

    allowed_hosts = _split_csv(config.get("DJANGO_ALLOWED_HOSTS", ""))
    if args.profile == "production" and ("*" in allowed_hosts or not allowed_hosts):
        errors.append("DJANGO_ALLOWED_HOSTS must be explicit in production-like deployments.")

    cors = _split_csv(config.get("CORS_ALLOWED_ORIGINS", ""))
    csrf = _split_csv(config.get("CSRF_TRUSTED_ORIGINS", ""))
    if args.profile == "production" and not cors:
        errors.append("CORS_ALLOWED_ORIGINS must include the frontend origin.")
    if args.profile == "production" and not csrf:
        errors.append("CSRF_TRUSTED_ORIGINS must include trusted HTTPS origins.")

    for warning in warnings:
        print(f"WARNING: {warning}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        raise SystemExit(1)

    print(f"Deployment configuration check passed for profile: {args.profile}")


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def _is_unsafe(value: str) -> bool:
    return value.strip() in UNSAFE_VALUES


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


if __name__ == "__main__":
    main()
