from fastapi import FastAPI
from routers.users import users

app = FastAPI()
app.include_router(users.router)

@app.get('/', tags=['Welcome Page'])
async def welcome_reaprofile():
    return {'message': 'Welcome to REAprofile'}