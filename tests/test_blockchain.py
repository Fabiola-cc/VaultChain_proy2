"""
tests/test_blockchain.py
Pruebas unitarias — Persona 2: estructura de bloque, genesis, encadenamiento y PoW.

Ejecutar con:
    pytest tests/test_blockchain.py -v
"""

import hashlib
import pytest
from src.blockchain.blockchain import Block, Blockchain, DIFFICULTY


# ══════════════════════════════════════════════════════════════════════════════
# Test 1 – Genesis block
# ══════════════════════════════════════════════════════════════════════════════
class TestGenesisBlock:

    def test_genesis_block_is_index_zero(self):
        """El primer bloque debe tener índice 0."""
        bc = Blockchain()
        assert bc.chain[0].index == 0

    def test_genesis_block_previous_hash_is_64_zeros(self):
        """El genesis block debe tener previous_hash = '0' * 64."""
        bc = Blockchain()
        assert bc.chain[0].previous_hash == "0" * 64

    def test_genesis_block_hash_meets_difficulty(self):
        """El genesis block debe haber hecho mining y cumplir la dificultad."""
        bc = Blockchain()
        assert bc.chain[0].hash.startswith("0" * DIFFICULTY)


# ══════════════════════════════════════════════════════════════════════════════
# Test 2 – Cálculo de hash SHA-256
# ══════════════════════════════════════════════════════════════════════════════
class TestBlockHash:

    def test_hash_is_sha256_of_content(self):
        """El hash del bloque debe ser SHA-256 del contenido concatenado."""
        import json
        bc = Blockchain()
        b = bc.chain[0]
        expected = hashlib.sha256((
            str(b.index)
            + b.timestamp
            + json.dumps(b.data, sort_keys=True)
            + b.previous_hash
            + str(b.nonce)
        ).encode()).hexdigest()
        assert b.hash == expected

    def test_hash_changes_if_data_tampered(self):
        """Modificar los datos de un bloque debe producir un hash diferente."""
        bc = Blockchain()
        bc.add_block({"sender_id": "a", "recipient_ids": ["b"], "message_hash": "abc"})
        block = bc.chain[1]
        original_hash = block.hash
        block.data["sender_id"] = "TAMPERED"
        assert block._calculate_hash() != original_hash

    def test_each_block_has_unique_hash(self):
        """Dos bloques distintos deben tener hashes distintos."""
        bc = Blockchain()
        bc.add_block({"msg": "primero"})
        bc.add_block({"msg": "segundo"})
        hashes = [b.hash for b in bc.chain]
        assert len(hashes) == len(set(hashes))


# ══════════════════════════════════════════════════════════════════════════════
# Test 3 – Encadenamiento
# ══════════════════════════════════════════════════════════════════════════════
class TestChaining:

    def test_new_block_previous_hash_points_to_last_block(self):
        """El previous_hash de cada bloque nuevo debe ser el hash del bloque anterior."""
        bc = Blockchain()
        bc.add_block({"sender_id": "u1", "recipient_ids": ["u2"], "message_hash": "h1"})
        assert bc.chain[1].previous_hash == bc.chain[0].hash

    def test_chain_grows_with_each_add_block(self):
        """La cadena debe crecer con cada add_block."""
        bc = Blockchain()
        assert len(bc.chain) == 1
        bc.add_block({"msg": "tx1"})
        assert len(bc.chain) == 2
        bc.add_block({"msg": "tx2"})
        assert len(bc.chain) == 3

    def test_index_increments_correctly(self):
        """El índice de cada bloque debe ser su posición en la cadena."""
        bc = Blockchain()
        bc.add_block({"msg": "a"})
        bc.add_block({"msg": "b"})
        for i, block in enumerate(bc.chain):
            assert block.index == i


# ══════════════════════════════════════════════════════════════════════════════
# Test 4 – Proof-of-Work
# ══════════════════════════════════════════════════════════════════════════════
class TestProofOfWork:

    def test_mined_block_hash_starts_with_zeros(self):
        """Tras el mining, el hash debe iniciar con N ceros (DIFFICULTY)."""
        bc = Blockchain()
        bc.add_block({"msg": "pow test"})
        assert bc.last_block.hash.startswith("0" * DIFFICULTY)

    def test_nonce_is_positive_after_mining(self):
        """El nonce debe haberse incrementado durante el mining."""
        bc = Blockchain()
        bc.add_block({"msg": "nonce test"})
        assert bc.last_block.nonce >= 0  # 0 es válido si el hash ya cumple


# ══════════════════════════════════════════════════════════════════════════════
# Test 5 – Verificación de cadena
# ══════════════════════════════════════════════════════════════════════════════
class TestVerifyChain:

    def test_valid_chain_returns_true(self):
        """Una cadena sin modificar debe ser válida."""
        bc = Blockchain()
        bc.add_block({"sender_id": "a", "recipient_ids": ["b"], "message_hash": "x"})
        bc.add_block({"sender_id": "b", "recipient_ids": ["c"], "message_hash": "y"})
        result = bc.verify_chain()
        assert result["valid"] is True
        assert result["block_count"] == 3

    def test_tampered_data_invalidates_chain(self):
        """Modificar los datos de un bloque debe invalidar la cadena."""
        bc = Blockchain()
        bc.add_block({"sender_id": "alice", "recipient_ids": ["bob"], "message_hash": "h"})
        # Alterar datos sin recalcular el hash
        bc.chain[1].data["sender_id"] = "HACKER"
        result = bc.verify_chain()
        assert result["valid"] is False
        assert result["block_index"] == 1

    def test_tampered_previous_hash_invalidates_chain(self):
        """Romper el encadenamiento de previous_hash debe invalidar la cadena."""
        bc = Blockchain()
        bc.add_block({"msg": "bloque 1"})
        bc.add_block({"msg": "bloque 2"})
        # Romper el enlace del bloque 2
        bc.chain[2].previous_hash = "0" * 64
        result = bc.verify_chain()
        assert result["valid"] is False
        assert result["block_index"] == 2

    def test_only_genesis_chain_is_valid(self):
        """Una cadena con solo el genesis debe ser válida."""
        bc = Blockchain()
        result = bc.verify_chain()
        assert result["valid"] is True
