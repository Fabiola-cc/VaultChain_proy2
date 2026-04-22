from fastapi import FastAPI
from auth.router import router

app = FastAPI()
app.include_router(router)