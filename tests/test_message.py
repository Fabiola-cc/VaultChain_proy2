import pytest
import base64
from Crypto.PublicKey import RSA
from src.crypto.message import encrypt_message, decrypt_message

@pytest.fixture
def rsa_keypair():
    key = RSA.generate(2048)
    return {
        "public":  key.publickey().export_key().decode(),
        "private": key.export_key().decode(),
    }

@pytest.fixture(scope="module")
def other_keypair():
    key = RSA.generate(2048)
    return {
        "public":  key.publickey().export_key().decode(),
        "private": key.export_key().decode(),
    }

def test_encrypt_message_retorna_campos_requeridos(rsa_keypair):
    resultado = encrypt_message("hola mundo", rsa_keypair["public"])
    assert set(resultado.keys()) == {"ciphertext", "encrypted_key", "nonce", "auth_tag", "timestamp"}

def test_encrypt_message_valores_son_base64_valido(rsa_keypair):
    resultado = encrypt_message("hola mundo", rsa_keypair["public"])
    for campo in ["ciphertext", "encrypted_key", "nonce", "auth_tag"]:
        try:
            base64.b64decode(resultado[campo])
        except Exception:
            pytest.fail(f"{campo} no es Base64 válido")

def test_encrypt_message_nonce_unico_por_mensaje(rsa_keypair):
    r1 = encrypt_message("mensaje uno", rsa_keypair["public"])
    r2 = encrypt_message("mensaje uno", rsa_keypair["public"])
    assert r1["nonce"] != r2["nonce"]
    assert r1["ciphertext"] != r2["ciphertext"]

def test_encrypt_message_ciphertext_distinto_al_plaintext(rsa_keypair):
    plaintext = "mensaje secreto"
    resultado = encrypt_message(plaintext, rsa_keypair["public"])
    ciphertext_decoded = base64.b64decode(resultado["ciphertext"])
    assert ciphertext_decoded != plaintext.encode()

def test_encrypt_message_llave_publica_invalida():
    with pytest.raises(Exception):
        encrypt_message("hola", "esto_no_es_una_llave_pem")

# test de descifrado
 
def test_decrypt_recupera_plaintext_original(rsa_keypair):
    """El mensaje descifrado debe ser idéntico al original."""
    plaintext = "Hola VaultChain"
    payload   = encrypt_message(plaintext, rsa_keypair["public"])
    recovered = decrypt_message(payload, rsa_keypair["private"])
    assert recovered == plaintext
 
def test_decrypt_falla_con_llave_privada_incorrecta(rsa_keypair, other_keypair):
    """Usar la llave privada equivocada debe lanzar excepción."""
    payload = encrypt_message("mensaje privado", rsa_keypair["public"])
    with pytest.raises(Exception):
        decrypt_message(payload, other_keypair["private"])
 
def test_decrypt_falla_si_ciphertext_alterado(rsa_keypair):
    """Modificar el ciphertext debe invalidar el tag GCM."""
    payload = encrypt_message("mensaje íntegro", rsa_keypair["public"])
    ct = bytearray(base64.b64decode(payload["ciphertext"]))
    ct[0] ^= 0xFF
    payload["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(Exception):
        decrypt_message(payload, rsa_keypair["private"])
 
def test_decrypt_falla_si_auth_tag_alterado(rsa_keypair):
    """Modificar el auth_tag debe hacer fallar la verificación GCM."""
    payload = encrypt_message("mensaje con tag válido", rsa_keypair["public"])
    tag = bytearray(base64.b64decode(payload["auth_tag"]))
    tag[0] ^= 0xFF
    payload["auth_tag"] = base64.b64encode(bytes(tag)).decode()
    with pytest.raises(Exception):
        decrypt_message(payload, rsa_keypair["private"])
 
def test_end_to_end_con_mensaje_largo(rsa_keypair):
    """El flujo completo debe funcionar con mensajes de cualquier longitud."""
    plaintext = "A" * 10_000
    payload   = encrypt_message(plaintext, rsa_keypair["public"])
    recovered = decrypt_message(payload, rsa_keypair["private"])
    assert recovered == plaintext
 