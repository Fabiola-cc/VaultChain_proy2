import pytest
from fastapi.testclient import TestClient
from main import app
client = TestClient(app)

# Datos del usuario de prueba
TEST_USER = {
    "display_name": "Usuario Test",
    "email": "test.integracion@vaultchain.gt",
    "password": "TestPass#2026",
}


@pytest.fixture(scope="module")
def registered_user():
    """Registra un usuario, lo devuelve para los tests, y lo elimina al final."""
    # 1. Registro
    resp = client.post("/auth/register", json=TEST_USER)
    assert resp.status_code == 201, f"Register falló: {resp.json()}"
    user = resp.json()

    yield user  # los tests corren aquí

    # 2. Cleanup: eliminar el usuario al terminar
    client.delete(f"/users/{user['user_id']}")


def test_register_creates_user_with_public_key(registered_user):
    """El registro debe retornar los datos del usuario incluyendo su llave pública."""
    assert registered_user["email"]      == TEST_USER["email"]
    assert registered_user["display_name"] == TEST_USER["display_name"]
    assert "BEGIN PUBLIC KEY" in registered_user["public_key"] or \
           "BEGIN RSA PUBLIC KEY" in registered_user["public_key"]


def test_login_with_correct_credentials_returns_jwt(registered_user):
    """Login con credenciales correctas debe retornar access y refresh token."""
    resp = client.post("/auth/login", json={
        "email": TEST_USER["email"],
        "password": TEST_USER["password"],
    })

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token"  in data
    assert "refresh_token" in data
    assert data["token_type"]   == "bearer"
    assert data["display_name"] == TEST_USER["display_name"]


def test_login_with_wrong_password_returns_401(registered_user):
    """Login con contraseña incorrecta debe retornar 401."""
    resp = client.post("/auth/login", json={
        "email": TEST_USER["email"],
        "password": "contraseña-incorrecta",
    })
    assert resp.status_code == 401


def test_get_public_key_endpoint(registered_user):
    """GET /users/{id}/key debe retornar la llave pública en PEM."""
    user_id = registered_user["user_id"]
    resp = client.get(f"/users/{user_id}/key")

    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == user_id
    assert "BEGIN" in data["public_key"]


def test_duplicate_register_returns_409(registered_user):
    """Registrar el mismo email dos veces debe retornar 409."""
    resp = client.post("/auth/register", json=TEST_USER)
    assert resp.status_code == 409