from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

def sign_message(plaintext: str, sender_private_key_pem: str) -> str:
    """
        Firma un mensaje usando RSA-PSS + SHA-256. 
        Utiliza el mensaje antes de cifrar y la llave privada descifrada del usuario que envía.

        El resultado es el valor de la firma en base 64. 
        Que se guarda en 'signature' en la tabla de mensajes.
    """
    private_key = RSA.import_key(sender_private_key_pem)

    # Hacer hash SHA-256 del plaintext
    message_hash = SHA256.new(plaintext.encode())

    # Firmar el hash con RSA-PSS
    signature = pss.new(private_key).sign(message_hash)

    # Retornar en Base64 para guardarlo en DB
    return base64.b64encode(signature).decode()


def verify_signature(plaintext: str, signature_b64: str, public_key_pem: str) -> dict:
    """
        Verificar autenticidad de firma 
        Utiliza el mensaje descifrado, la firma y la llave pública del usuario que envía.

        El resultado un diccionario con el estado y alerta de inseguridad si es necesario.
    """
    try:
        public_key = RSA.import_key(public_key_pem)
        message_hash = SHA256.new(plaintext.encode())
        pss.new(public_key).verify(message_hash, base64.b64decode(signature_b64))
        return {"verified": True}
    except (ValueError, TypeError):
        return {"verified": False, "warning": "Firma inválida — mensaje no verificado"}