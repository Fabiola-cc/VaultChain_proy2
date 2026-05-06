import uuid
from sqlalchemy import Column, Text, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from src.database import Base


class Message(Base):
    __tablename__ = "messages"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    ciphertext = Column(Text, nullable=False)
    nonce      = Column(Text, nullable=False)
    auth_tag   = Column(Text, nullable=False)
    timestamp  = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class MessageRecipient(Base):
    __tablename__ = "message_recipients"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id    = Column(UUID(as_uuid=True), ForeignKey("messages.id", ondelete="CASCADE"), nullable=False)
    recipient_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    encrypted_key = Column(Text, nullable=False)
