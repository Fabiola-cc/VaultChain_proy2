from pydantic import BaseModel
from typing import List


class SendMessageRequest(BaseModel):
    sender_id:     str
    recipient_ids: List[str]
    content:       str


class SendMessageResponse(BaseModel):
    message_id:      str
    ciphertext:      str
    nonce:           str
    auth_tag:        str
    timestamp:       str
    recipient_count: int


class GetMessageResponse(BaseModel):
    message_id:    str
    sender_id:     str
    recipient_ids: List[str]
    ciphertext:    str
    nonce:         str
    auth_tag:      str
    timestamp:     str
