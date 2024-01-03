from db_postgres.database import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime

class User(Base):
    __tablename__ = 'user' 
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String)
    full_name = Column(String)
    disabled = Column(Boolean)
    uuid = Column(String)
    created = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    
