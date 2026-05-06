import uuid
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

USER_A = {"display_name": "Alice Test", "email": "alice.msg@vaultchain.gt", "password": "AlicePass#2026"}
USER_B = {"display_name": "Bob Test",   "email": "bob.msg@vaultchain.gt",   "password": "BobPass#2026"}


@pytest.fixture(scope="module")
def two_users():
    resp_a = client.post("/auth/register", json=USER_A)
    assert resp_a.status_code == 201, f"Register A failed: {resp_a.json()}"
    user_a = resp_a.json()

    resp_b = client.post("/auth/register", json=USER_B)
    assert resp_b.status_code == 201, f"Register B failed: {resp_b.json()}"
    user_b = resp_b.json()

    yield user_a, user_b

    client.delete(f"/users/{user_a['user_id']}")
    client.delete(f"/users/{user_b['user_id']}")


def test_send_message_returns_201_with_encrypted_payload(two_users):
    user_a, user_b = two_users
    resp = client.post("/messages", json={
        "sender_id":     user_a["user_id"],
        "recipient_ids": [user_b["user_id"]],
        "content":       "hola Bob",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert "message_id"  in data
    assert "ciphertext"  in data
    assert "nonce"       in data
    assert "auth_tag"    in data
    assert "timestamp"   in data
    assert data["recipient_count"] == 1


def test_get_message_returns_stored_payload(two_users):
    user_a, user_b = two_users
    post_resp = client.post("/messages", json={
        "sender_id":     user_a["user_id"],
        "recipient_ids": [user_b["user_id"]],
        "content":       "mensaje para GET",
    })
    assert post_resp.status_code == 201
    message_id = post_resp.json()["message_id"]

    get_resp = client.get(f"/messages/{message_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["message_id"]  == message_id
    assert data["sender_id"]   == user_a["user_id"]
    assert user_b["user_id"] in data["recipient_ids"]
    assert "ciphertext" in data


def test_group_message_with_two_recipients_returns_correct_count(two_users):
    user_a, user_b = two_users
    resp = client.post("/messages", json={
        "sender_id":     user_a["user_id"],
        "recipient_ids": [user_a["user_id"], user_b["user_id"]],
        "content":       "mensaje grupal",
    })
    assert resp.status_code == 201
    assert resp.json()["recipient_count"] == 2


def test_get_nonexistent_message_returns_404():
    fake_id = str(uuid.uuid4())
    resp = client.get(f"/messages/{fake_id}")
    assert resp.status_code == 404


def test_send_message_with_unknown_sender_returns_404(two_users):
    _, user_b = two_users
    resp = client.post("/messages", json={
        "sender_id":     str(uuid.uuid4()),
        "recipient_ids": [user_b["user_id"]],
        "content":       "mensaje fantasma",
    })
    assert resp.status_code == 404


def test_send_message_with_unknown_recipient_returns_404(two_users):
    user_a, _ = two_users
    resp = client.post("/messages", json={
        "sender_id":     user_a["user_id"],
        "recipient_ids": [str(uuid.uuid4())],
        "content":       "mensaje sin destinatario",
    })
    assert resp.status_code == 404
