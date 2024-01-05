from uuid import UUID
from pydantic import BaseModel, EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []

class TokenResponse(Token):
    uuid: UUID
    username: EmailStr
    full_name: str
    disabled: bool
    