from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from src.database import get_db
from src.auth.models import User

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/{user_id}/key")
def get_public_key(user_id: str, db: Session = Depends(get_db)):
    """Retorna la llave publica PEM del usuario."""
    row = db.execute(
        text("SELECT public_key FROM users WHERE id = :uid"),
        {"uid": user_id},
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return {"user_id": user_id, "public_key": row.public_key}


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: str, db: Session = Depends(get_db)):
    """Elimina un usuario por ID. Usado principalmente en tests de integracion."""
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.delete(user)
    db.commit()