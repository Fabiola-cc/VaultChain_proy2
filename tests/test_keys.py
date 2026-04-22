import pytest
from Crypto.PublicKey import RSA, ECC
from src.auth.keys import (
    generate_rsa_keypair,
    generate_ecc_keypair,
    encrypt_private_key,
    decrypt_private_key,
)


def test_generate_rsa_keypair_returns_valid_pem():
    public_pem, private_pem = generate_rsa_keypair()

    assert "BEGIN PUBLIC KEY" in public_pem or "BEGIN RSA PUBLIC KEY" in public_pem
    assert "BEGIN RSA PRIVATE KEY" in private_pem

    key = RSA.import_key(private_pem)
    assert key.size_in_bits() == 2048


def test_generate_ecc_keypair_returns_valid_pem():
    public_pem, private_pem = generate_ecc_keypair()

    assert "BEGIN PUBLIC KEY" in public_pem
    assert "BEGIN PRIVATE KEY" in private_pem

    key = ECC.import_key(private_pem)
    assert "P-256" in key.curve


def test_encrypt_and_decrypt_private_key_roundtrip():
    _, private_pem = generate_rsa_keypair()
    password = "contrasena-de-prueba-123!"

    encrypted = encrypt_private_key(private_pem, password)
    decrypted = decrypt_private_key(encrypted, password)

    assert decrypted == private_pem


def test_encrypted_key_has_four_parts():
    _, private_pem = generate_rsa_keypair()
    encrypted = encrypt_private_key(private_pem, "test123")

    parts = encrypted.split(":")
    assert len(parts) == 4


def test_decrypt_fails_with_wrong_password():
    _, private_pem = generate_rsa_keypair()
    encrypted = encrypt_private_key(private_pem, "contrasena-correcta")

    with pytest.raises(Exception):
        decrypt_private_key(encrypted, "contrasena-incorrecta")


def test_each_keypair_is_unique():
    pub1, priv1 = generate_rsa_keypair()
    pub2, priv2 = generate_rsa_keypair()

    assert pub1 != pub2
    assert priv1 != priv2
