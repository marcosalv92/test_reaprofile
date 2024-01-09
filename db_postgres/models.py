from uuid import uuid4
from db_postgres.database import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime, LargeBinary, ARRAY, ForeignKey
from datetime import datetime
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = 'user' 
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True)
    full_name = Column(String, default='empty')
    disabled = Column(Boolean, default=False)
    uuid = Column(String, default=uuid4())
    created = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    hashed_password = Column(String)
    user_profile = relationship('UserProfile', backref='user', cascade='delete, merge')
    def as_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class UserProfile(Base):
    __tablename__ = 'user_profile'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'))
    cover_photo = Column(LargeBinary)
    profile_picture = Column(LargeBinary)
    phone = Column(String(15))
    cv = Column(LargeBinary)
    images_certificates_titles = Column(ARRAY(LargeBinary))
    description = Column(String(100))
    country = Column(String)
    years_experiences = Column(Integer)
    profession_or_title = Column(String(30))
    languages = Column(ARRAY(String))
    links_social_networks = Column(ARRAY(String))

#     class User(BaseModel):
#     id: str | None = 0
#     uuid: str | None = ''
#     username: EmailStr
#     full_name: str
#     disabled: bool | None = True

# class UserDB(User):
#     hashed_password: str = constr(min_length=8, pattern="^(?=.*[A-Z])(?=.*[0-9])")

# class UserRegister(User):
#     password: str = constr(min_length=8)
#     @validator("password")
#     def validate_password(cls, value):
#         if not any(char.isdigit() for char in value):
#             raise ValueError("Password must contain at least one number")
#         if not any(char.isupper() for char in value):
#             raise ValueError("Password must contain at least one uppercase letter")
#         return value

    
