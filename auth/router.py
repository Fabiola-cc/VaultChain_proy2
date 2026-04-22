from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr
from psycopg2.errors import UniqueViolation

from auth.password import hash_password
from auth.repository import create_user

router = APIRouter(prefix="/users", tags=["users"])

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class RegisterResponse(BaseModel):
    id: int
    name: str
    email: str

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest):
    try:
        hashed = hash_password(body.password)
        user = create_user(body.name, body.email, hashed)
        return user
    except UniqueViolation:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El correo ya está registrado",
        )