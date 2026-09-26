"""Small persistent conversation store for the repository security copilot.

This deliberately stays simpler than Open WebUI's multi-user database layer:
conversations are scoped to a repository and saved as JSON so the MVP keeps a
zero-migration setup while still surviving a backend restart.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from .models import new_id, now_iso

MAX_CONVERSATIONS_PER_REPOSITORY = 50
MAX_MESSAGES_PER_CONVERSATION = 100
MAX_MESSAGE_CHARS = 20_000

_lock = threading.RLock()
_memory: dict[str, dict[str, Any]] = {}


def _store_path() -> Path:
    configured = os.environ.get("CLANKER_CONVERSATIONS_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / ".clankershield-data" / "conversations.json"


def _read() -> dict[str, dict[str, Any]]:
    path = _store_path()
    try:
        if path.is_file():
            document = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(document, dict):
                return document
    except (OSError, json.JSONDecodeError):
        pass
    return dict(_memory)


def _write(document: dict[str, dict[str, Any]]) -> None:
    global _memory
    _memory = document
    path = _store_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
    except OSError:
        # A read-only deployment still gets a usable in-process conversation
        # experience; persistence is best effort rather than a scan blocker.
        pass


def _public(conversation: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(conversation))


def list_conversations(repo_id: str) -> list[dict[str, Any]]:
    with _lock:
        conversations = [item for item in _read().values() if item.get("repo_id") == repo_id]
        conversations.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
        return [_public(item) for item in conversations]


def create_conversation(repo_id: str, title: str = "Security investigation") -> dict[str, Any]:
    with _lock:
        document = _read()
        existing = [item for item in document.values() if item.get("repo_id") == repo_id]
        if len(existing) >= MAX_CONVERSATIONS_PER_REPOSITORY:
            existing.sort(key=lambda item: item.get("updated_at", ""))
            document.pop(existing[0]["id"], None)
        timestamp = now_iso()
        conversation = {
            "id": new_id("conversation"),
            "repo_id": repo_id,
            "title": title.strip()[:120] or "Security investigation",
            "created_at": timestamp,
            "updated_at": timestamp,
            "messages": [],
        }
        document[conversation["id"]] = conversation
        _write(document)
        return _public(conversation)


def get_conversation(repo_id: str, conversation_id: str) -> dict[str, Any] | None:
    with _lock:
        conversation = _read().get(conversation_id)
        if not conversation or conversation.get("repo_id") != repo_id:
            return None
        return _public(conversation)


def append_message(repo_id: str, conversation_id: str, role: str, content: str, **metadata: Any) -> dict[str, Any]:
    if role not in {"user", "assistant", "system", "tool"}:
        raise ValueError("Unsupported conversation message role")
    clean_content = (content or "").strip()
    if not clean_content or len(clean_content) > MAX_MESSAGE_CHARS:
        raise ValueError("Conversation message is empty or too large")
    with _lock:
        document = _read()
        conversation = document.get(conversation_id)
        if not conversation or conversation.get("repo_id") != repo_id:
            return None
        if len(conversation.setdefault("messages", [])) >= MAX_MESSAGES_PER_CONVERSATION:
            conversation["messages"] = conversation["messages"][-(MAX_MESSAGES_PER_CONVERSATION - 1):]
        message = {
            "id": new_id("message"),
            "role": role,
            "content": clean_content,
            "created_at": now_iso(),
            **metadata,
        }
        conversation["messages"].append(message)
        conversation["updated_at"] = message["created_at"]
        if role == "user" and conversation.get("title") == "Security investigation":
            conversation["title"] = clean_content[:80]
        _write(document)
        return _public(message)


def update_message(repo_id: str, conversation_id: str, message_id: str, content: str) -> dict[str, Any] | None:
    clean_content = (content or "").strip()
    if not clean_content or len(clean_content) > MAX_MESSAGE_CHARS:
        raise ValueError("Conversation message is empty or too large")
    with _lock:
        document = _read()
        conversation = document.get(conversation_id)
        if not conversation or conversation.get("repo_id") != repo_id:
            return None
        for message in conversation.get("messages", []):
            if message.get("id") == message_id and message.get("role") == "user":
                message["content"] = clean_content
                message["edited_at"] = now_iso()
                conversation["updated_at"] = message["edited_at"]
                _write(document)
                return _public(message)
        return None


def remove_conversation(repo_id: str, conversation_id: str) -> bool:
    with _lock:
        document = _read()
        conversation = document.get(conversation_id)
        if not conversation or conversation.get("repo_id") != repo_id:
            return False
        document.pop(conversation_id, None)
        _write(document)
        return True
