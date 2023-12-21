from pydantic import BaseModel

class User(BaseModel):
    id: str | None = 0
    username: str
    email: str
    disabled: bool | None = True

class UserDB(User):
    hashed_password: str