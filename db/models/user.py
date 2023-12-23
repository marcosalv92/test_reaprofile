from pydantic import BaseModel, EmailStr, constr, validator

class User(BaseModel):
    id: str | None = 0
    username: EmailStr
    full_name: str
    disabled: bool | None = True

class UserDB(User):
    hashed_password: str = constr(min_length=8, pattern="^(?=.*[A-Z])(?=.*[0-9])")

class UserRegister(User):
    password: str = constr(min_length=8)
    @validator("password")
    def validate_password(cls, value):
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must contain at least one number")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must contain at least one uppercase letter")
        return value