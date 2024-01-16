from datetime import datetime, timedelta
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Security, status
from pydantic import ValidationError
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from db_postgres import models, schemas
from db_postgres.database import get_db
from db_postgres import crud
from db_postgres.schemas import User
from routers.oauth import authenticate_user
from routers.schemas import Token, TokenData, TokenKamilo
from routers.hashing import Hash
from jose import jwt, JWTError

from routers.token import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token

router = APIRouter(prefix='/login', tags=['Login'], responses={404: {'message': status.HTTP_404_NOT_FOUND}})

@router.post("")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "scopes": form_data.scopes}, expires_delta=access_token_expires
    )

    return TokenKamilo(uuid=user.uuid, username=user.username, full_name=user.full_name, disabled=user.disabled, access_token=access_token, token_type="bearer")


# @router.get("/me")
# async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
#     return current_user