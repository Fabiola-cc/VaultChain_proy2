from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import bcrypt

from src.database import get_db
from src.auth.models import User
from src.auth.keys import generate_rsa_keypair, encrypt_private_key
from src.auth.schemas import RegisterRequest, RegisterResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """
    Registra un nuevo usuario:
    1. Hashea la contrasena con bcrypt
    2. Genera par RSA-2048
    3. Cifra la llave privada con PBKDF2 + AES-256-GCM
    4. Guarda todo en la DB
    """
    password_hash = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    public_pem, private_pem = generate_rsa_keypair()
    encrypted_private = encrypt_private_key(private_pem, body.password)

    user = User(
        email=body.email,
        display_name=body.display_name,
        password_hash=password_hash,
        public_key=public_pem,
        encrypted_private_key=encrypted_private,
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El correo electronico ya esta registrado",
        )

    return RegisterResponse(
        user_id=str(user.id),
        email=user.email,
        display_name=user.display_name,
        public_key=user.public_key,
    )
