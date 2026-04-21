from fastapi import FastAPI
from auth.router import register

app = FastAPI()
app.include_router(register)