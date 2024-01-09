from fastapi import HTTPException, status
from pydantic import UUID4
from sqlalchemy.orm import Session
from db_postgres import models
from db_postgres import schemas
from db_postgres.schemas import UserCreate
from routers.hashing import Hash


def get_user_by_uuid(db: Session, uuid: UUID4):
    try:
        return db.query(models.User).filter(models.User.uuid == str(uuid)).first()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'Error obtained user by uuid: {e}'            
            )

def get_user_by_username(db: Session, username: str):
    try:
        return db.query(models.User).filter(models.User.username == username).first()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'Error obtained user by username: {e}'            
            )

def get_users(db: Session, skip: int = 0, limit: int = 100):
    try:
        return db.query(models.User).offset(skip).limit(limit).all()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'Error obtained users: {e}'            
            )

def create_user(db: Session, user: UserCreate):
    try:
        hashed_password = Hash.get_password_hash(user.password)
        db_user = models.User(username=user.username,full_name=user.full_name, hashed_password=hashed_password)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'Error created user: {e}'            
            )

# Operación para actualizar una user por ID
def update_user_by_uuid(db: Session, uuid: UUID4, updated_user: schemas.UserUpdate ):
    try:
        existing_user = db.query(models.User).filter(models.User.uuid == str(uuid)).first()
        
        # Comprobar que el username a actualizar en caso de ser distinto el campo username del usuario a actualizar no exista en la BD
        if not (updated_user.username == None or updated_user.username == existing_user.username):
            db_user = get_user_by_username(db, username=updated_user.username)
            if db_user:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
        
        # Comprobar si exite ese usuario con uuid
        if existing_user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not updated_user.password == None:
            new_pass = updated_user.password
            existing_user.hashed_password = Hash.get_password_hash(new_pass)        
    
        for field, value in updated_user.model_dump(exclude_unset=True).items():
            setattr(existing_user, field, value)
        
        db.commit()
        db.refresh(existing_user)
        return existing_user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'Error updated user by uuid: {e}'            
            )

# Operación para eliminar una tarea por ID
def delete_user_by_uuid(db: Session, uuid: UUID4):
    try:
        user = db.query(models.User).filter(models.User.uuid == str(uuid)).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

        db.delete(user)
        db.commit()
        return {"message": "user deleted successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'Error deleted user: {e}'            
            )
# def get_items(db: Session, skip: int = 0, limit: int = 100):
#     return db.query(Item).offset(skip).limit(limit).all()


# def create_user_item(db: Session, item: schemas.ItemCreate, user_id: int):
#     db_item = Item(**item.dict(), owner_id=user_id)
#     db.add(db_item)
#     db.commit()
#     db.refresh(db_item)
#     return db_item