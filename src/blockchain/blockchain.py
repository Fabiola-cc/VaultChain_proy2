import hashlib
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field


DIFFICULTY = 3  # Proof-of-work simplificado: el hash debe iniciar con N ceros


@dataclass
class Block:
    index:         int
    timestamp:     str
    data:          dict          # {"sender_id", "recipient_ids", "message_hash"}
    previous_hash: str
    nonce:         int  = 0
    hash:          str = field(default="", init=False)

    def __post_init__(self):
        self.hash = self._calculate_hash()

    def _calculate_hash(self) -> str:
        """SHA-256(index + timestamp + data + previous_hash + nonce)"""
        content = (
            str(self.index)
            + self.timestamp
            + json.dumps(self.data, sort_keys=True)
            + self.previous_hash
            + str(self.nonce)
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def mine(self, difficulty: int = DIFFICULTY) -> None:
        """Proof-of-work: incrementa nonce hasta que el hash empiece con N ceros."""
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self._calculate_hash()


class Blockchain:
    def __init__(self):
        self.chain: list[Block] = []
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        genesis = Block(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data={"info": "Genesis Block"},
            previous_hash="0" * 64,
        )
        genesis.mine()
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, transaction_data: dict) -> Block:
        """
        Crea un nuevo bloque con la transacción y lo agrega a la cadena.

        Args:
            transaction_data: dict con al menos sender_id, recipient_ids, message_hash.

        Returns:
            El bloque recién añadido.
        """
        block = Block(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=transaction_data,
            previous_hash=self.last_block.hash,
        )
        block.mine()
        self.chain.append(block)
        return block

    def verify_chain(self) -> dict:
        """
        Recorre toda la cadena verificando:
          1. Que el hash almacenado coincide con el hash recalculado.
          2. Que previous_hash apunta correctamente al bloque anterior.

        Returns:
            {"valid": True} si la cadena es íntegra,
            {"valid": False, "error": "...", "block_index": N} si no.
        """
        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

            # 1. Hash del bloque actual debe coincidir con el recalculado
            if current.hash != current._calculate_hash():
                return {
                    "valid": False,
                    "error": "Hash del bloque no coincide con su contenido",
                    "block_index": i,
                }

            # 2. previous_hash debe apuntar al hash real del bloque anterior
            if current.previous_hash != previous.hash:
                return {
                    "valid": False,
                    "error": "El encadenamiento de hashes está roto",
                    "block_index": i,
                }

        return {"valid": True, "block_count": len(self.chain)}

    def to_dict(self) -> list[dict]:
        """Serializa la cadena completa para respuestas REST."""
        return [
            {
                "index":         b.index,
                "timestamp":     b.timestamp,
                "data":          b.data,
                "previous_hash": b.previous_hash,
                "nonce":         b.nonce,
                "hash":          b.hash,
            }
            for b in self.chain
        ]


# ── Instancia global — Majo importa esto ─────────────────────────────
blockchain = Blockchain()


def add_block(transaction_data: dict) -> Block:
    # Majo, usa está función para agregar transacciones a la cadena sin manipular la instancia directamente.
    """
    Uso:
        from src.blockchain.blockchain import add_block
        add_block({
            "sender_id":     str(user.id),
            "recipient_ids": [str(r) for r in recipient_ids],
            "message_hash":  hashlib.sha256(plaintext.encode()).hexdigest(),
        })
    """
    return blockchain.add_block(transaction_data)
