import os
import base64
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


# --- Generacion de par de llaves ---

def generate_rsa_keypair() -> tuple[str, str]:
    """Genera par RSA-2048. Retorna (public_pem, private_pem)."""
    key = RSA.generate(2048)
    public_pem = key.publickey().export_key().decode()
    private_pem = key.export_key().decode()
    return public_pem, private_pem


def generate_ecc_keypair() -> tuple[str, str]:
    """Genera par ECC P-256. Retorna (public_pem, private_pem)."""
    key = ECC.generate(curve="P-256")
    public_pem = key.public_key().export_key(format="PEM")
    private_pem = key.export_key(format="PEM")
    return public_pem, private_pem


# --- Cifrado de llave privada con PBKDF2 + AES-256-GCM ---

def encrypt_private_key(private_pem: str, password: str) -> str:
    """
    Cifra la llave privada PEM usando una clave derivada de la contraseña
    con PBKDF2 + AES-256-GCM.
    Retorna string Base64 con formato: salt:nonce:tag:ciphertext
    """
    salt = os.urandom(16)
    derived_key = PBKDF2(
        password.encode(),
        salt,
        dkLen=32,
        count=310_000,
        prf=lambda p, s: __import__("hmac").new(p, s, SHA256).digest(),
    )

    cipher = AES.new(derived_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(private_pem.encode())

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    return f"{b64(salt)}:{b64(cipher.nonce)}:{b64(tag)}:{b64(ciphertext)}"


def decrypt_private_key(encrypted_blob: str, password: str) -> str:
    """
    Descifra la llave privada cifrada con encrypt_private_key.
    Retorna el PEM original.
    """
    parts = encrypted_blob.split(":")
    if len(parts) != 4:
        raise ValueError("Formato de llave privada cifrada invalido")

    salt, nonce, tag, ciphertext = [base64.b64decode(p) for p in parts]

    derived_key = PBKDF2(
        password.encode(),
        salt,
        dkLen=32,
        count=310_000,
        prf=lambda p, s: __import__("hmac").new(p, s, SHA256).digest(),
    )

    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
