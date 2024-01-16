from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenKamilo(Token):
    uuid: str
    username: str
    full_name: str
    disabled: bool


class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []








