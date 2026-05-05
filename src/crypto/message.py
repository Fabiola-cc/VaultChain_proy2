import os, base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from datetime import datetime, timezone

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

def _b64dec(s: str) -> bytes:
    return base64.b64decode(s)

def encrypt_message(plaintext: str, recipient_public_key_pem: str) -> dict:
    # 1. Generar clave AES-256 efímera — 32 bytes aleatorios
    aes_key = os.urandom(32)

    # 2. Cifrar el mensaje con esa clave AES
    #    AES.new genera el nonce automáticamente en MODE_GCM
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext.encode())

    # 3. Cifrar la clave AES con RSA-OAEP
    rsa_key = RSA.import_key(recipient_public_key_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_key = rsa_cipher.encrypt(aes_key)

    # 4. Retornar dict
    return {
        "ciphertext":    b64(ciphertext),
        "encrypted_key": b64(encrypted_key),
        "nonce":         b64(aes_cipher.nonce),
        "auth_tag":      b64(tag),
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }

def decrypt_message(payload: dict, recipient_private_key_pem: str) -> str:

    # 1. Recuperar clave AES con RSA-OAEP y la llave privada del destinatario
    rsa_key    = RSA.import_key(recipient_private_key_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    aes_key    = rsa_cipher.decrypt(_b64dec(payload["encrypted_key"]))
 
    # 2. Descifrar y verificar tag GCM verificando el tag de autenticación
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=_b64dec(payload["nonce"]))
    plaintext  = aes_cipher.decrypt_and_verify(
        _b64dec(payload["ciphertext"]),
        _b64dec(payload["auth_tag"]),
    )
 
    return plaintext.decode("utf-8")
 