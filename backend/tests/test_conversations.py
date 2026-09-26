import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.main import REPOS, app


client = TestClient(app)


def _event_map(body: str):
    events = []
    for block in body.split("\n\n"):
        lines = [line for line in block.splitlines() if line]
        if not lines:
            continue
        event = next((line.split(":", 1)[1].strip() for line in lines if line.startswith("event:")), "message")
        raw = next((line.split(":", 1)[1].strip() for line in lines if line.startswith("data:")), "{}")
        events.append((event, json.loads(raw)))
    return events


def setup_function(_):
    REPOS.clear()


def test_conversation_stream_is_persistent_and_evidence_linked(tmp_path, monkeypatch):
    monkeypatch.setenv("CLANKER_CONVERSATIONS_PATH", str(tmp_path / "conversations.json"))
    repo = client.post("/api/repositories/demo").json()
    repo_id = repo["id"]

    created = client.post(f"/api/repositories/{repo_id}/conversations", json={"title": "Triage"})
    assert created.status_code == 200
    conversation_id = created.json()["conversation"]["id"]

    response = client.post(
        f"/api/repositories/{repo_id}/conversations/{conversation_id}/messages",
        json={"content": "What should I fix first?"},
    )
    assert response.status_code == 200
    events = _event_map(response.text)
    assert [event for event, _ in events][0] == "meta"
    assert "delta" in [event for event, _ in events]
    assert [event for event, _ in events][-1] == "done"
    assert events[0][1]["mode"] == "local"

    detail = client.get(f"/api/repositories/{repo_id}/conversations/{conversation_id}").json()["conversation"]
    assert [message["role"] for message in detail["messages"]] == ["user", "assistant"]
    assert detail["messages"][1]["evidence_refs"]


def test_conversation_edit_regenerate_and_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("CLANKER_CONVERSATIONS_PATH", str(tmp_path / "conversations.json"))
    repo = client.post("/api/repositories/demo").json()
    repo_id = repo["id"]
    conversation_id = client.post(f"/api/repositories/{repo_id}/conversations").json()["conversation"]["id"]

    response = client.post(
        f"/api/repositories/{repo_id}/conversations/{conversation_id}/messages",
        json={"content": "Show vulnerable systems."},
    )
    detail = client.get(f"/api/repositories/{repo_id}/conversations/{conversation_id}").json()["conversation"]
    user_message = detail["messages"][0]

    edited = client.patch(
        f"/api/repositories/{repo_id}/conversations/{conversation_id}/messages/{user_message['id']}",
        json={"content": "Show the highest risk system."},
    )
    assert edited.status_code == 200
    assert edited.json()["message"]["content"] == "Show the highest risk system."

    regenerated = client.post(f"/api/repositories/{repo_id}/conversations/{conversation_id}/regenerate")
    assert regenerated.status_code == 200
    assert any(event == "done" for event, _ in _event_map(regenerated.text))

    deleted = client.delete(f"/api/repositories/{repo_id}/conversations/{conversation_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/repositories/{repo_id}/conversations/{conversation_id}").status_code == 404
