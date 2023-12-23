from fastapi import APIRouter, status, HTTPException, Depends, Security
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from db.client import db_client
from db.models.user import User, UserDB, UserRegister
from db.models.token import Token, TokenData
from db.schemas.user import users_schema, user_schema
from passlib.context import CryptContext
from pydantic import ValidationError
from jose import JWTError, jwt
from bson import ObjectId
from datetime import datetime, timedelta


SECRET_KEY = "9e4e2827670f54e7e09d353d70a907a44f63e3f590ac64f81017943f89d8cbbe"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2 = OAuth2PasswordBearer(tokenUrl='login', scopes={"user": "Read information about the current user.", "admin": "All permissions"})

router = APIRouter(prefix='/users', tags=['users'],  responses={404: {'message' : status.HTTP_404_NOT_FOUND}})

def search_user(field: str, key):
    try:
        find_one = db_client.users.find_one({field: key})
        if find_one:
            user = user_schema(find_one)        
            return User(**user)
        else:
            return None  
    except:
        return {'error':'No se ha encontrado el usuario '}

def search_user_db(field: str, key):
    try:
        find_one = db_client.users.find_one({field: key})
        if find_one:
            user = user_schema(find_one)
            return UserDB(**user)
        else:
            return None
    except:
        return {'error':'No se ha encontrado el usuario '}
    
    
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    return UserDB(**[user for user in db if user['username'] == username][0])


def authenticate_user(username: str, password: str):
    user = search_user_db('username', username)
    if user == None:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2)]):
    
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except (JWTError, ValidationError):
        raise credentials_exception
    user = search_user('username', token_data.username)
    if user is None:
        raise credentials_exception
    
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Security(get_current_user, scopes=["user"])]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_all_users(user: Annotated[User, Depends(get_current_user)]):
    try:
        return db_client.users.find()
    except:
        return {'message': 'Data not found'}
    
 # Store token in DB for implement logout
# async def add_token(token: Token):
#     if type(search_user('email', user.email)) == User:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='El usuario ya exite')
    
#     user_dict = dict(user)
#     del user_dict['id']
#     user_dict['hashed_password'] = get_password_hash(user_dict['hashed_password']) 
    
#     id = db_client.users.insert_one(user_dict).inserted_id
#     new_user = user_schema(db_client.users.find_one({'_id': id}))
    
#     return User(**new_user)



@router.get('/all')
async def get_all_users(user: Annotated[User, Security(get_current_active_user, scopes=["admin"])]) -> list[User]:
    return users_schema(db_client.users.find())


# Path
@router.get('/{user_id}', response_model=User)
async def get_user_by_id(user_id: str, user: Annotated[User, Security(get_current_user, scopes=['user'])]):
    return search_user('_id', ObjectId(user_id))

# # Query
# @router.get('/')
# async def get_user_by_id(id: str):
#     return search_user('_id', ObjectId(id))

@router.post('/register', response_model=User, status_code=status.HTTP_201_CREATED)
async def add_user(user: UserRegister):
    if type(search_user('username', user.username)) == User:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='El usuario ya exite')
    
    user_dict = dict(user)
    del user_dict['id']
    user_dict['hashed_password'] = get_password_hash(user_dict['password'])
    del user_dict ['password']
    
    id = db_client.users.insert_one(user_dict).inserted_id
    new_user = user_schema(db_client.users.find_one({'_id': id}))
    
    return User(**new_user)

@router.put('/', response_model=User)
async def update_user(user_update: UserRegister, user: Annotated[User, Security(get_current_user, scopes=['user'])]):
    user_update = dict(user_update)
    user_update['hashed_password'] = get_password_hash(user_update['password'])
    del user_update['password']
    del user_update['id']
    try:
        db_client.users.find_one_and_replace({'_id': ObjectId(user.id)}, user_update)

    except:
        return {'message': 'User not found'}
    
    return user_schema(db_client.users.find_one({'_id': ObjectId(user.id)}))


@router.delete('/{id}', status_code=status.HTTP_204_NO_CONTENT)
async def user(id: str, user: Annotated[User, Security(get_current_user, scopes=['user'])]):
    try:
        found = db_client.users.find_one_and_delete({'_id': ObjectId(id)})
        if not found:
            raise HTTPException(status_code=404, detail="User not found")
        return {"mensaje": f"User with ID {id} remove"}      
    except:
        raise HTTPException(status_code=404, detail="User not found")


@router.post("/login")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    
    user = authenticate_user(form_data.username, form_data.password)

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
    
    # Store token in DB for implement logout
    


    return {"access_token": access_token, "token_type": "bearer"}






