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


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
 

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    display_name: str
