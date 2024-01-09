from datetime import timedelta
from typing import Annotated, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import UUID4
from sqlalchemy.orm import Session
from db_postgres.database import get_db
from db_postgres import schemas, crud
from routers.oauth import authenticate_user, get_current_active_user, get_current_user, oauth2_scheme
from routers.token import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token
from routers.schemas import Token



router = APIRouter(prefix='/user', tags=['Users'], responses={404: {'message': status.HTTP_404_NOT_FOUND}})


@router.post("/register", response_model=schemas.CurrentUser, status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)

@router.get("/me", response_model=schemas.CurrentUser, status_code=status.HTTP_200_OK)
async def read_users_me(current_user: Annotated[schemas.User, Depends(get_current_user)]):
    return current_user

@router.get("/all", response_model=List[schemas.CurrentUser], status_code=status.HTTP_200_OK, dependencies=[Security(get_current_active_user, scopes=['admin'])])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@router.get("/{uuid}", response_model=schemas.CurrentUser, status_code=status.HTTP_200_OK, dependencies=[Depends(get_current_user)])
def read_user(uuid: UUID4, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_uuid(db, uuid=uuid)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.patch("/{uuid}", response_model=schemas.CurrentUser, status_code=status.HTTP_201_CREATED ,dependencies=[Depends(get_current_user)])
def update_user(uuid: UUID4, user_update: schemas.UserUpdate, db: Session = Depends(get_db)):
    return crud.update_user_by_uuid(db=db, updated_user=user_update, uuid=uuid)

@router.delete("/{uuid}", dependencies=[Depends(oauth2_scheme)], response_model=Dict, status_code=status.HTTP_200_OK)
def delete_user(uuid: UUID4, db: Session = Depends(get_db)):
    return crud.delete_user_by_uuid(db=db, uuid=uuid)

# @router.get("/items/", response_model=list[schemas.Item])
# def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
#     items = crud.get_items(db, skip=skip, limit=limit)
#     return items