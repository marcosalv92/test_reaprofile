from fastapi import FastAPI, Depends
from routers.users import users
from db_postgres.database import Base, engine, get_db
from sqlalchemy.orm import Session
from db_postgres.models import models

def create_table():
    Base.metadata.create_all(bind=engine)
create_table()

app = FastAPI()
app.include_router(users.router)

@app.get('/')
async def welcome_reaprofile():
    return {'message': 'Welcome to REAprofile'}

@app.get('/db')
async def get_user(db: Session = Depends(get_db)):
    data = db.query(models.User).all()
    return {'message': 'Welcome to REAprofile'}