import uuid
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

USER_A = {"display_name": "Alice Group", "email": "alice.grp@vaultchain.gt", "password": "AliceGrp#2026"}
USER_B = {"display_name": "Bob Group",   "email": "bob.grp@vaultchain.gt",   "password": "BobGrp#2026"}
USER_C = {"display_name": "Carol Group", "email": "carol.grp@vaultchain.gt", "password": "CarolGrp#2026"}


@pytest.fixture(scope="module")
def three_users():
    users = []
    for user_data in [USER_A, USER_B, USER_C]:
        resp = client.post("/auth/register", json=user_data)
        assert resp.status_code == 201, f"Register failed: {resp.json()}"
        users.append(resp.json())

    yield tuple(users)

    for u in users:
        client.delete(f"/users/{u['user_id']}")


@pytest.fixture(scope="module")
def group_fixture(three_users):
    user_a, user_b, user_c = three_users
    resp = client.post("/groups", json={
        "name":       "Test Group Alpha",
        "creator_id": user_a["user_id"],
        "member_ids": [user_a["user_id"], user_b["user_id"], user_c["user_id"]],
    })
    assert resp.status_code == 201, f"Create group failed: {resp.json()}"
    group = resp.json()

    yield group, three_users


# ── Creación de grupo ─────────────────────────────────────────────────────────

def test_create_group_returns_201_with_member_count(three_users):
    user_a, user_b, _ = three_users
    resp = client.post("/groups", json={
        "name":       "Inline Group",
        "creator_id": user_a["user_id"],
        "member_ids": [user_a["user_id"], user_b["user_id"]],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert "group_id"           in data
    assert data["name"]         == "Inline Group"
    assert data["member_count"] == 2


def test_create_group_with_unknown_creator_returns_404():
    resp = client.post("/groups", json={
        "name":       "Ghost Group",
        "creator_id": str(uuid.uuid4()),
        "member_ids": [],
    })
    assert resp.status_code == 404


def test_create_group_with_unknown_member_returns_404(three_users):
    user_a, _, _ = three_users
    resp = client.post("/groups", json={
        "name":       "Bad Member Group",
        "creator_id": user_a["user_id"],
        "member_ids": [user_a["user_id"], str(uuid.uuid4())],
    })
    assert resp.status_code == 404


def test_create_group_auto_includes_creator_if_omitted(three_users):
    user_a, user_b, _ = three_users
    resp = client.post("/groups", json={
        "name":       "Auto Creator Group",
        "creator_id": user_a["user_id"],
        "member_ids": [user_b["user_id"]],
    })
    assert resp.status_code == 201
    assert resp.json()["member_count"] == 2


# ── Obtener grupo ─────────────────────────────────────────────────────────────

def test_get_group_returns_members(group_fixture):
    group, (user_a, user_b, user_c) = group_fixture
    resp = client.get(f"/groups/{group['group_id']}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["group_id"] == group["group_id"]
    assert data["name"]     == "Test Group Alpha"
    member_ids = [m["user_id"] for m in data["members"]]
    assert user_a["user_id"] in member_ids
    assert user_b["user_id"] in member_ids
    assert user_c["user_id"] in member_ids


def test_get_nonexistent_group_returns_404():
    resp = client.get(f"/groups/{uuid.uuid4()}")
    assert resp.status_code == 404


# ── Enviar mensaje al grupo ───────────────────────────────────────────────────

def test_send_group_message_returns_201_with_encrypted_payload(group_fixture):
    group, (user_a, _, _) = group_fixture
    resp = client.post(f"/groups/{group['group_id']}/messages", json={
        "sender_id": user_a["user_id"],
        "content":   "hola grupo",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert "message_id"      in data
    assert "ciphertext"      in data
    assert "nonce"           in data
    assert "auth_tag"        in data
    assert "timestamp"       in data
    assert data["group_id"]        == group["group_id"]
    assert data["recipient_count"] == 3


def test_send_group_message_recipient_count_matches_member_count(group_fixture):
    group, (_, user_b, _) = group_fixture
    resp = client.post(f"/groups/{group['group_id']}/messages", json={
        "sender_id": user_b["user_id"],
        "content":   "mensaje de Bob al grupo",
    })
    assert resp.status_code == 201
    assert resp.json()["recipient_count"] == 3


def test_send_group_message_non_member_returns_403(group_fixture):
    group, _ = group_fixture
    resp = client.post(f"/groups/{group['group_id']}/messages", json={
        "sender_id": str(uuid.uuid4()),
        "content":   "intento de infiltrado",
    })
    assert resp.status_code == 403


def test_send_message_to_nonexistent_group_returns_404(three_users):
    user_a, _, _ = three_users
    resp = client.post(f"/groups/{uuid.uuid4()}/messages", json={
        "sender_id": user_a["user_id"],
        "content":   "mensaje a grupo fantasma",
    })
    assert resp.status_code == 404


# ── Historial de mensajes del grupo ──────────────────────────────────────────

def test_list_group_messages_contains_sent_message(group_fixture):
    group, (user_a, _, _) = group_fixture
    send_resp = client.post(f"/groups/{group['group_id']}/messages", json={
        "sender_id": user_a["user_id"],
        "content":   "mensaje para listar",
    })
    assert send_resp.status_code == 201
    sent_id = send_resp.json()["message_id"]

    list_resp = client.get(f"/groups/{group['group_id']}/messages")
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["group_id"] == group["group_id"]
    assert isinstance(data["messages"], list)
    message_ids = [m["message_id"] for m in data["messages"]]
    assert sent_id in message_ids


def test_list_messages_each_has_required_fields(group_fixture):
    group, (user_a, _, _) = group_fixture
    client.post(f"/groups/{group['group_id']}/messages", json={
        "sender_id": user_a["user_id"],
        "content":   "verificando campos",
    })
    resp = client.get(f"/groups/{group['group_id']}/messages")
    assert resp.status_code == 200
    for msg in resp.json()["messages"]:
        assert "message_id" in msg
        assert "sender_id"  in msg
        assert "ciphertext" in msg
        assert "nonce"      in msg
        assert "auth_tag"   in msg
        assert "timestamp"  in msg


def test_list_messages_nonexistent_group_returns_404():
    resp = client.get(f"/groups/{uuid.uuid4()}/messages")
    assert resp.status_code == 404
