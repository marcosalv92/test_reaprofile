from sqlalchemy.orm import relationship
from pydantic import BaseModel, ConfigDict, EmailStr, UUID4, Field, constr, field_validator
from datetime import datetime

# class UserProfileBase(BaseModel):
#     user_id: str | None = None
#     cover_photo: str | None = None
#     profile_picture: str | None = None
#     phone: str | None = None
#     cv: str | None = None
#     images_certificates_titles: str | None = None
#     description: str | None = None
#     country: str | None = None
#     years_experiences: str | None = None
#     profession_or_title: str | None = None
#     languages: str | None = None
#     links_social_networks: str | None = None

# class UserProfile(UserProfileBase):
#     id: str
#     user_id: int
#     class Config(ConfigDict):
#         orm_mode = True

class UserBase(BaseModel):
    username: EmailStr
    full_name: str

class UserCreate(UserBase):
    password: str = constr(min_length=8)
    @field_validator("password")
    def validate_password(cls, value):
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must contain at least one number")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must contain at least one uppercase letter")
        return value

class User(UserBase):
    disabled: bool
    uuid: UUID4
    created: datetime
    # user_profile = UserProfile
    class Config(ConfigDict):
        orm_mode: True

class UserDB(User):
    hashed_password: str

class CurrentUser(UserBase):
    uuid: UUID4
    disabled: bool
    class Config(ConfigDict):
        orm_mode: True

class UserUpdate(BaseModel):
    username: EmailStr = Field(default=None)
    full_name: str = Field(default=None)
    password: str = Field(default=None)
    disabled: bool = Field(default=None)
    @field_validator("password")
    def validate_password(cls, value):
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must contain at least one number")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must contain at least one uppercase letter")
        return value
    
    
    








    