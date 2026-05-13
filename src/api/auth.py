from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
import bcrypt
import os
from jose import jwt
from datetime import datetime, timedelta, timezone

from src.database import get_db
from src.auth.models import User
from src.auth.keys import generate_rsa_keypair, encrypt_private_key, decrypt_private_key
from src.auth.schemas import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse

router = APIRouter(prefix="/auth", tags=["auth"])

# Configuración de JWT
SECRET_KEY = os.getenv("SECRET_KEY", "no-truena-si-aun-no-hay-env")
# El segundo valor solo es por si no está la variable en el .env usa como ese string para hacer los tokens, pero solo es cómo una validación para no matar todo
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS   = 7

# Función auxiliar para crear JWT
def _create_token(subject: str, expires_delta: timedelta, token_type: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub":  subject,
        "iat":  now,
        "exp":  now + expires_delta,
        "type": token_type,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Endpoint de registrar
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

# Endpoint de login
@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    """
    Inicio de sesión:
    1. Busca al usuario por email
    2. Verifica la contraseña con bcrypt
    3. Descifra la llave privada en memoria (valida integridad del par)
    4. Emite access token (30 min) + refresh token (7 días)
    """
    # 1. Buscar usuario
    user: User | None = db.query(User).filter(User.email == body.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales invalidas",
        )

    # 2. Verificar hash bcrypt
    if not bcrypt.checkpw(body.password.encode(), user.password_hash.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales invalidas",
        )

    # 3. Descifrar llave privada en memoria (PBKDF2 + AES-256-GCM)
    #    Si la contraseña es correcta pero el blob está corrupto, falla aquí.
    try:
        _private_key_pem = decrypt_private_key(user.encrypted_private_key, body.password)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al descifrar la llave privada",
        )

    # 4. Emitir tokens JWT
    user_id_str = str(user.id)
    access_token = _create_token(
        subject=user_id_str,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )
    refresh_token = _create_token(
        subject=user_id_str,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh",
    )

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user_id=user_id_str,
        display_name=user.display_name,
    )