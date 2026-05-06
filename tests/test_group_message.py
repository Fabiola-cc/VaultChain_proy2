import pytest
import base64
from Crypto.PublicKey import RSA
from src.crypto.message import encrypt_message_group, decrypt_message


@pytest.fixture
def keypair_a():
    key = RSA.generate(2048)
    return {"public": key.publickey().export_key().decode(),
            "private": key.export_key().decode()}


@pytest.fixture
def keypair_b():
    key = RSA.generate(2048)
    return {"public": key.publickey().export_key().decode(),
            "private": key.export_key().decode()}


def test_encrypt_message_group_retorna_campos_requeridos(keypair_a):
    result = encrypt_message_group("hola grupo", {"user-1": keypair_a["public"]})
    assert set(result.keys()) == {"ciphertext", "nonce", "auth_tag", "timestamp", "encrypted_keys"}


def test_encrypted_keys_tiene_una_entrada_por_destinatario(keypair_a, keypair_b):
    recipients = {"uid-a": keypair_a["public"], "uid-b": keypair_b["public"]}
    result = encrypt_message_group("mensaje", recipients)
    assert set(result["encrypted_keys"].keys()) == {"uid-a", "uid-b"}


def test_diferentes_destinatarios_obtienen_encrypted_key_distintas(keypair_a, keypair_b):
    recipients = {"uid-a": keypair_a["public"], "uid-b": keypair_b["public"]}
    result = encrypt_message_group("mensaje", recipients)
    assert result["encrypted_keys"]["uid-a"] != result["encrypted_keys"]["uid-b"]


def test_single_recipient_via_group_decrypt_recupera_plaintext(keypair_a):
    plaintext = "mensaje de prueba"
    result = encrypt_message_group(plaintext, {"uid-a": keypair_a["public"]})
    payload = {
        "ciphertext":    result["ciphertext"],
        "nonce":         result["nonce"],
        "auth_tag":      result["auth_tag"],
        "encrypted_key": result["encrypted_keys"]["uid-a"],
    }
    recovered = decrypt_message(payload, keypair_a["private"])
    assert recovered == plaintext


def test_encrypted_keys_son_base64_valido(keypair_a, keypair_b):
    recipients = {"uid-a": keypair_a["public"], "uid-b": keypair_b["public"]}
    result = encrypt_message_group("test", recipients)
    for uid, enc_key in result["encrypted_keys"].items():
        try:
            base64.b64decode(enc_key)
        except Exception:
            pytest.fail(f"encrypted_keys[{uid}] no es Base64 valido")


def test_ambos_destinatarios_pueden_descifrar_el_mismo_ciphertext(keypair_a, keypair_b):
    plaintext = "mensaje compartido"
    result = encrypt_message_group(plaintext, {
        "uid-a": keypair_a["public"],
        "uid-b": keypair_b["public"],
    })
    for uid, keypair in [("uid-a", keypair_a), ("uid-b", keypair_b)]:
        payload = {
            "ciphertext":    result["ciphertext"],
            "nonce":         result["nonce"],
            "auth_tag":      result["auth_tag"],
            "encrypted_key": result["encrypted_keys"][uid],
        }
        recovered = decrypt_message(payload, keypair["private"])
        assert recovered == plaintext
