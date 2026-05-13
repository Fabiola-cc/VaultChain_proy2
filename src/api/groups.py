import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.auth.models import User
from src.auth.keys import decrypt_private_key
from src.crypto.models import Message, MessageRecipient
from src.crypto.models import Group, GroupMember, GroupMessage
from src.crypto.schemas import (
    CreateGroupRequest, CreateGroupResponse,
    GetGroupResponse, MemberInfo,
    SendGroupMessageRequest, SendGroupMessageResponse,
    GroupMessageSummary, ListGroupMessagesResponse,
    GroupDecryptedMessageSummary, ListDecryptedGroupMessagesResponse,
    DecryptGroupMessagesRequest
)
from src.crypto.message import encrypt_message_group, decrypt_message

router = APIRouter(prefix="/groups", tags=["groups"])


@router.post("", response_model=CreateGroupResponse, status_code=status.HTTP_201_CREATED)
def create_group(body: CreateGroupRequest, db: Session = Depends(get_db)):
    # 1. Validar que el creator existe
    if not db.query(User).filter(User.id == body.creator_id).first():
        raise HTTPException(status_code=404, detail="Creator not found")

    # 2. Deduplicar member_ids y validar que existen
    member_ids = list(dict.fromkeys(body.member_ids))
    for mid in member_ids:
        if not db.query(User).filter(User.id == mid).first():
            raise HTTPException(status_code=404, detail=f"Member {mid} not found")

    # 3. Asegurar que el creator está incluido en los miembros
    if body.creator_id not in member_ids:
        member_ids.insert(0, body.creator_id)

    # 4. Guardar el grupo
    group = Group(
        name       = body.name,
        creator_id = uuid.UUID(body.creator_id),
    )
    db.add(group)
    db.flush()

    # 5. Guardar un GroupMember por cada miembro
    for mid in member_ids:
        db.add(GroupMember(
            group_id = group.id,
            user_id  = uuid.UUID(mid),
        ))

    db.commit()
    db.refresh(group)

    return CreateGroupResponse(
        group_id     = str(group.id),
        name         = group.name,
        creator_id   = str(group.creator_id),
        member_count = len(member_ids),
    )


@router.get("/{group_id}", response_model=GetGroupResponse)
def get_group(group_id: str, db: Session = Depends(get_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    rows = db.query(GroupMember).filter(GroupMember.group_id == group.id).all()
    members = []
    for row in rows:
        user = db.query(User).filter(User.id == row.user_id).first()
        if user:
            members.append(MemberInfo(user_id=str(user.id), display_name=user.display_name))

    return GetGroupResponse(
        group_id   = str(group.id),
        name       = group.name,
        creator_id = str(group.creator_id),
        members    = members,
    )


@router.post(
    "/{group_id}/messages",
    response_model=SendGroupMessageResponse,
    status_code=status.HTTP_201_CREATED,
)
def send_group_message(group_id: str, body: SendGroupMessageRequest, db: Session = Depends(get_db)):
    # 1. Verificar que el grupo existe
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # 2. Verificar que el sender es miembro del grupo
    membership = db.query(GroupMember).filter(
        GroupMember.group_id == group.id,
        GroupMember.user_id  == body.sender_id,
    ).first()
    if not membership:
        raise HTTPException(status_code=403, detail="Sender is not a member of this group")

    # 3. Obtener la llave pública de cada miembro del grupo
    rows = db.query(GroupMember).filter(GroupMember.group_id == group.id).all()
    recipients_map: dict[str, str] = {}
    for row in rows:
        user = db.query(User).filter(User.id == row.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"Member {row.user_id} not found")
        recipients_map[str(user.id)] = user.public_key

    # 4. Cifrado híbrido grupal — reutiliza la función existente sin cambios
    payload = encrypt_message_group(body.content, recipients_map)

    # 5. Guardar Message (tabla existente — sin modificar)
    message = Message(
        sender_id  = uuid.UUID(body.sender_id),
        ciphertext = payload["ciphertext"],
        nonce      = payload["nonce"],
        auth_tag   = payload["auth_tag"],
        timestamp  = payload["timestamp"],
    )
    db.add(message)
    db.flush()

    # 6. Guardar un MessageRecipient por cada miembro (tabla existente — sin modificar)
    for rid, enc_key in payload["encrypted_keys"].items():
        db.add(MessageRecipient(
            message_id    = message.id,
            recipient_id  = uuid.UUID(rid),
            encrypted_key = enc_key,
        ))

    # 7. Guardar la relación grupo-mensaje (tabla nueva)
    db.add(GroupMessage(
        group_id   = group.id,
        message_id = message.id,
    ))

    db.commit()
    db.refresh(message)

    return SendGroupMessageResponse(
        message_id      = str(message.id),
        group_id        = group_id,
        ciphertext      = message.ciphertext,
        nonce           = message.nonce,
        auth_tag        = message.auth_tag,
        timestamp       = message.timestamp,
        recipient_count = len(recipients_map),
    )


@router.get("/{group_id}/messages", response_model=ListGroupMessagesResponse)
def list_group_messages(group_id: str, db: Session = Depends(get_db)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    join_rows = db.query(GroupMessage).filter(GroupMessage.group_id == group.id).all()
    message_ids = [row.message_id for row in join_rows]

    summaries = []
    if message_ids:
        messages = (
            db.query(Message)
            .filter(Message.id.in_(message_ids))
            .order_by(Message.created_at.asc())
            .all()
        )
        for msg in messages:
            summaries.append(GroupMessageSummary(
                message_id = str(msg.id),
                sender_id  = str(msg.sender_id),
                ciphertext = msg.ciphertext,
                nonce      = msg.nonce,
                auth_tag   = msg.auth_tag,
                timestamp  = msg.timestamp,
            ))

    return ListGroupMessagesResponse(group_id=group_id, messages=summaries)

@router.post("/{group_id}/messages/decrypted", response_model=ListDecryptedGroupMessagesResponse)
def list_decrypted_group_messages(
    group_id: str, 
    body: DecryptGroupMessagesRequest,
    db: Session = Depends(get_db)
):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    join_rows = db.query(GroupMessage).filter(GroupMessage.group_id == group.id).all()
    message_ids = [row.message_id for row in join_rows]

    # Verificar acceso
    user = db.query(User).filter(
        User.email == body.email
    ).first()

    row = db.query(GroupMember).filter(
        GroupMember.group_id == group.id,
        GroupMember.user_id == user.id
    ).first()
    
    if not row:
        raise HTTPException(status_code=403, detail="User is not part of the group")
    
    # Descifrar private key del usuario
    try:
        user_private_key = decrypt_private_key(
            user.encrypted_private_key,
            body.password
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid password")

    summaries = []
    if message_ids:
        messages = (
            db.query(Message)
            .filter(Message.id.in_(message_ids))
            .order_by(Message.created_at.asc())
            .all()
        )
        for msg in messages:
            msg_info = db.query(MessageRecipient).filter(
                MessageRecipient.message_id == msg.id,
                MessageRecipient.recipient_id == user.id
            ).first()

            if not msg_info:
                raise HTTPException(status_code=403, detail="User is not part of the group")
            
            # Preparar payload
            payload = {
                "ciphertext": msg.ciphertext,
                "nonce": msg.nonce,
                "auth_tag": msg.auth_tag,
                "encrypted_key": msg_info.encrypted_key
            }

            # Descifrar mensaje
            try:
                message_decrypted = decrypt_message(payload, user_private_key)
            except Exception:
                raise HTTPException(status_code=500, detail="Error decrypting message")

            summaries.append(GroupDecryptedMessageSummary(
                message_id = str(msg.id),
                sender_id  = str(msg.sender_id),
                message = message_decrypted,
                timestamp  = msg.timestamp,
            ))

    return ListDecryptedGroupMessagesResponse(group_id=group_id, messages=summaries)
