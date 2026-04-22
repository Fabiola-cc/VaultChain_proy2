from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    display_name: str
    email: EmailStr
    password: str


class RegisterResponse(BaseModel):
    user_id: str
    email: str
    display_name: str
    public_key: str


class PublicKeyResponse(BaseModel):
    user_id: str
    public_key: str
