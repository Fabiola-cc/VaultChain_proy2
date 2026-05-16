import pytest
import base64
from Crypto.PublicKey import RSA
from src.signatures.sign import sign_message, verify_signature

@pytest.fixture
def rsa_keypair():
    key = RSA.generate(2048)
    return {
        "public":  key.publickey().export_key().decode(),
        "private": key.export_key().decode(),
    }

# --- Test principal: flujo completo firma → verificación ---

def test_firmar_y_verificar_mensaje(rsa_keypair):
    plaintext = "hola mundo secreto"
    signature = sign_message(plaintext, rsa_keypair["private"])
    resultado = verify_signature(plaintext, signature, rsa_keypair["public"])
    assert resultado["verified"] is True

# --- Tests adicionales ---

def test_firma_es_base64_valido(rsa_keypair):
    signature = sign_message("mensaje", rsa_keypair["private"])
    try:
        base64.b64decode(signature)
    except Exception:
        pytest.fail("La firma no es Base64 válido")

def test_firma_invalida_retorna_not_verified(rsa_keypair):
    signature = sign_message("mensaje original", rsa_keypair["private"])
    resultado = verify_signature("mensaje alterado", signature, rsa_keypair["public"])
    assert resultado["verified"] is False
    assert "warning" in resultado

def test_firma_con_llave_incorrecta(rsa_keypair):
    otra_key = RSA.generate(2048)
    otra_publica = otra_key.publickey().export_key().decode()
    signature = sign_message("mensaje", rsa_keypair["private"])
    resultado = verify_signature("mensaje", signature, otra_publica)
    assert resultado["verified"] is False

def test_firma_distinta_por_probabilismo(rsa_keypair):
    # RSA-PSS es probabilístico — dos firmas del mismo texto deben ser distintas
    sig1 = sign_message("mismo mensaje", rsa_keypair["private"])
    sig2 = sign_message("mismo mensaje", rsa_keypair["private"])
    assert sig1 != sig2