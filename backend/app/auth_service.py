"""Small, provider-neutral authentication boundary for local deployments.

ClankerShield did not previously have an authentication provider. This module
adds a conservative local development provider without placing privileged
credentials in the browser: passwords are scrypt-hashed, sessions are signed
and delivered as HttpOnly cookies, and verification/reset tokens are stored
only as hashes. Set ``CLANKER_AUTH_REQUIRED=true`` before exposing the API to
multiple users. A production deployment should replace the JSON store with a
managed identity provider or database-backed auth service without changing the
route contract.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path

from .models import new_id, now_iso

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
MIN_PASSWORD_LENGTH = 10
SESSION_COOKIE = "clanker_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
RESET_TTL_SECONDS = 30 * 60

_LOCK = threading.RLock()
_PROCESS_SECRET = secrets.token_bytes(32)


def auth_required() -> bool:
    return os.environ.get("CLANKER_AUTH_REQUIRED", "false").strip().lower() in {"1", "true", "yes", "on"}


def _data_path() -> Path:
    configured = os.environ.get("CLANKER_AUTH_DATA_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / ".clankershield-data" / "auth_users.json"


def _load() -> dict:
    path = _data_path()
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {"users": {}}
    except (OSError, json.JSONDecodeError):
        return {"users": {}}


def _save(data: dict) -> None:
    path = _data_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="auth_", suffix=".tmp", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _secret() -> bytes:
    configured = os.environ.get("CLANKER_AUTH_SECRET")
    return configured.encode("utf-8") if configured else _PROCESS_SECRET


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt$16384$8$1${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=_unb64(salt), n=int(n), r=int(r), p=int(p))
        return hmac.compare_digest(actual, _unb64(expected))
    except (ValueError, TypeError, OSError):
        return False


def validate_credentials(email: str, password: str, confirmation: str | None = None) -> str | None:
    if len(email.strip()) > 254:
        return "Enter a valid email address."
    if not EMAIL_RE.match(email.strip().lower()):
        return "Enter a valid email address."
    if len(password) > 512:
        return "Password is too long."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if confirmation is not None and password != confirmation:
        return "Passwords do not match."
    return None


def _token_hash(token: str) -> str:
    return hmac.new(_secret(), token.encode("utf-8"), hashlib.sha256).hexdigest()


def _public(user: dict) -> dict:
    return {"id": user["id"], "email": user["email"], "role": user.get("role", "analyst"), "email_verified": bool(user.get("email_verified")), "created_at": user.get("created_at")}


def _find_by_email(data: dict, email: str) -> tuple[str, dict] | tuple[None, None]:
    wanted = email.strip().lower()
    for user_id, user in data.get("users", {}).items():
        if user.get("email") == wanted:
            return user_id, user
    return None, None


def create_user(email: str, password: str, confirmation: str | None = None) -> tuple[dict, str]:
    email = email.strip().lower()
    error = validate_credentials(email, password, confirmation)
    if error:
        raise ValueError(error)
    with _LOCK:
        data = _load()
        _, existing = _find_by_email(data, email)
        if existing:
            raise ValueError("Unable to create this account with the supplied details.")
        user_id = new_id("user")
        token = secrets.token_urlsafe(32)
        data.setdefault("users", {})[user_id] = {
            "id": user_id,
            "email": email,
            "password_hash": hash_password(password),
            "role": "analyst",
            "email_verified": False,
            "verification_token_hash": _token_hash(token),
            "created_at": now_iso(),
        }
        _save(data)
        return _public(data["users"][user_id]), token


def verify_email(token: str) -> dict | None:
    if not token or len(token) > 256:
        return None
    with _LOCK:
        data = _load()
        for user in data.get("users", {}).values():
            if hmac.compare_digest(user.get("verification_token_hash", ""), _token_hash(token)):
                user["email_verified"] = True
                user.pop("verification_token_hash", None)
                _save(data)
                return _public(user)
    return None


def authenticate(email: str, password: str) -> dict | None:
    if len(email) > 254 or len(password) > 512:
        return None
    with _LOCK:
        data = _load()
        _, user = _find_by_email(data, email)
        if not user or not verify_password(password, user.get("password_hash", "")) or not user.get("email_verified"):
            return None
        return _public(user)


def issue_session(user_id: str) -> str:
    payload = {"sub": user_id, "iat": int(time.time()), "exp": int(time.time()) + SESSION_TTL_SECONDS}
    encoded = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _b64(hmac.new(_secret(), encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def user_from_session(token: str | None) -> dict | None:
    if not token or token.count(".") != 1:
        return None
    encoded, signature = token.split(".", 1)
    expected = _b64(hmac.new(_secret(), encoded.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(_unb64(encoded).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        user_id = payload.get("sub")
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    with _LOCK:
        user = _load().get("users", {}).get(user_id)
        return _public(user) if user else None


def request_password_reset(email: str) -> str | None:
    if len(email) > 254:
        return None
    token = secrets.token_urlsafe(32)
    with _LOCK:
        data = _load()
        _, user = _find_by_email(data, email)
        if not user:
            return None
        user["reset_token_hash"] = _token_hash(token)
        user["reset_expires_at"] = int(time.time()) + RESET_TTL_SECONDS
        _save(data)
    return token


def reset_password(token: str, password: str, confirmation: str | None = None) -> dict | None:
    error = validate_credentials("reset@example.invalid", password, confirmation)
    if error and "email" not in error.lower():
        raise ValueError(error)
    with _LOCK:
        data = _load()
        for user in data.get("users", {}).values():
            if user.get("reset_token_hash") == _token_hash(token) and int(user.get("reset_expires_at", 0)) >= int(time.time()):
                user["password_hash"] = hash_password(password)
                user.pop("reset_token_hash", None)
                user.pop("reset_expires_at", None)
                _save(data)
                return _public(user)
    return None


def development_tokens_enabled() -> bool:
    configured = os.environ.get("CLANKER_DEV_AUTH_TOKENS")
    # The unprotected single-user demo mode has no mail transport, so expose a
    # local verification token to keep the new auth page usable. Protected
    # deployments must explicitly opt into this development-only behavior.
    if configured is None:
        return not auth_required()
    return configured.lower() in {"1", "true", "yes", "on"}
