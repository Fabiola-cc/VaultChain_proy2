from pydantic import BaseModel
from typing import List


class CreateGroupRequest(BaseModel):
    name:       str
    creator_id: str
    member_ids: List[str]


class SendGroupMessageRequest(BaseModel):
    sender_id: str
    content:   str


class MemberInfo(BaseModel):
    user_id:      str
    display_name: str


class CreateGroupResponse(BaseModel):
    group_id:     str
    name:         str
    creator_id:   str
    member_count: int


class GetGroupResponse(BaseModel):
    group_id:   str
    name:       str
    creator_id: str
    members:    List[MemberInfo]


class SendGroupMessageResponse(BaseModel):
    message_id:      str
    group_id:        str
    ciphertext:      str
    nonce:           str
    auth_tag:        str
    timestamp:       str
    recipient_count: int


class GroupMessageSummary(BaseModel):
    message_id: str
    sender_id:  str
    ciphertext: str
    nonce:      str
    auth_tag:   str
    timestamp:  str

class ListGroupMessagesResponse(BaseModel):
    group_id: str
    messages: List[GroupMessageSummary]

class DecryptGroupMessagesRequest(BaseModel):
    email:    str
    password: str

class GroupDecryptedMessageSummary(BaseModel):
    message_id: str
    sender_id:  str
    message:    str
    timestamp:  str

class ListDecryptedGroupMessagesResponse(BaseModel):
    group_id: str
    messages: List[GroupDecryptedMessageSummary]
