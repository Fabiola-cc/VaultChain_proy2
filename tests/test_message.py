import pytest
import base64
from Crypto.PublicKey import RSA
from src.crypto.message import encrypt_message

@pytest.fixture
def rsa_keypair():
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