import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.auth.models import User
from src.crypto.models import Message, MessageRecipient
from src.crypto.schemas import SendMessageRequest, SendMessageResponse, GetMessageResponse, GetDecryptedMessageResponse, DecryptRequest
from src.crypto.message import encrypt_message_group, decrypt_message
from src.auth.keys import decrypt_private_key

router = APIRouter(prefix="/messages", tags=["messages"])

@router.post("", response_model=SendMessageResponse, status_code=status.HTTP_201_CREATED)
def send_message(body: SendMessageRequest, db: Session = Depends(get_db)):
    # 1. Validar sender
    if not db.query(User).filter(User.id == body.sender_id).first():
        raise HTTPException(status_code=404, detail="Sender not found")

    # 2. Recopilar llaves públicas de cada destinatario
    recipients_map: dict[str, str] = {}
    for rid in body.recipient_ids:
        user = db.query(User).filter(User.id == rid).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"Recipient {rid} not found")
        recipients_map[rid] = user.public_key

    # 3. Cifrado híbrido grupal: un AES-256-GCM para todos, clave cifrada por cada destinatario con RSA-OAEP
    payload = encrypt_message_group(body.content, recipients_map)

    # 4. Guardar Message (flush para obtener el ID sin hacer commit aún)
    message = Message(
        sender_id  = uuid.UUID(body.sender_id),
        ciphertext = payload["ciphertext"],
        nonce      = payload["nonce"],
        auth_tag   = payload["auth_tag"],
        timestamp  = payload["timestamp"],
    )
    db.add(message)
    db.flush()

    # 5. Guardar un MessageRecipient por destinatario
    for rid, enc_key in payload["encrypted_keys"].items():
        db.add(MessageRecipient(
            message_id    = message.id,
            recipient_id  = uuid.UUID(rid),
            encrypted_key = enc_key,
        ))

    db.commit()
    db.refresh(message)

    return SendMessageResponse(
        message_id      = str(message.id),
        ciphertext      = message.ciphertext,
        nonce           = message.nonce,
        auth_tag        = message.auth_tag,
        timestamp       = message.timestamp,
        recipient_count = len(body.recipient_ids),
    )


@router.get("/{message_id}", response_model=GetMessageResponse)
def get_message(message_id: str, db: Session = Depends(get_db)):
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    rows = db.query(MessageRecipient).filter(
        MessageRecipient.message_id == message.id
    ).all()

    return GetMessageResponse(
        message_id    = str(message.id),
        sender_id     = str(message.sender_id),
        recipient_ids = [str(r.recipient_id) for r in rows],
        ciphertext    = message.ciphertext,
        nonce         = message.nonce,
        auth_tag      = message.auth_tag,
        timestamp     = message.timestamp,
    )

@router.post("/{message_id}/decrypt", response_model=GetDecryptedMessageResponse)
def get_message_decrypted(
    message_id: str,
    body: DecryptRequest,
    db: Session = Depends(get_db),
):
    # Obtener mensaje
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Verificar acceso
    user = db.query(User).filter(
        User.email == body.email
    ).first()

    row = db.query(MessageRecipient).filter(
        MessageRecipient.message_id == message.id,
        MessageRecipient.recipient_id == user.id
    ).first()

    if not row:
        raise HTTPException(status_code=403, detail="No access to this message")

    # Descifrar private key
    try:
        user_private_key = decrypt_private_key(
            user.encrypted_private_key,
            body.password
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Preparar payload
    payload = {
        "ciphertext": message.ciphertext,
        "nonce": message.nonce,
        "auth_tag": message.auth_tag,
        "encrypted_key": row.encrypted_key
    }

    # Descifrar mensaje
    try:
        message_decrypted = decrypt_message(payload, user_private_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Error decrypting message")

    return GetDecryptedMessageResponse(
        message_id=str(message.id),
        sender_id=str(message.sender_id),
        message=message_decrypted,
        timestamp=message.timestamp,
    )