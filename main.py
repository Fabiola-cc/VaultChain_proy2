from fastapi import FastAPI
from src.database import engine, Base
from src.auth.router import router as auth_router
from src.api.users import router as users_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="VaultChain", version="1.0.0")

app.include_router(auth_router)
app.include_router(users_router)


@app.get("/")
def root():
    return {"message": "VaultChain API running"}
