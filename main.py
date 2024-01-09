from fastapi import FastAPI
from routers.users import users_pg
from routers.auth import auth

app = FastAPI()
app.include_router(auth.router)
app.include_router(users_pg.router)

@app.get('/')
async def welcome_reaprofile():
    return {'message': 'Welcome to REAprofile'}