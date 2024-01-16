from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from core.config import settings

# SQLALCHEMY_DATABASE_URL = 'postgresql://fl0user:Jl2fSYogCVP8@ep-damp-tooth-78921972.ap-southeast-1.aws.neon.fl0.io:5432/reaprofiledb?sslmode=require'
SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()