from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from src.database import get_db

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
