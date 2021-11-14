import json
from datetime import timedelta, datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.openapi.utils import get_openapi
import uvicorn
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from passlib.context import CryptContext

# to get a string like this run:
# openssl rand -hex 32
from jose import jwt, JWTError
from pydantic import BaseModel
from starlette.responses import RedirectResponse

SECRET_KEY = "d3c65ec90117b30be9bf2e4141a30d8b259b5e5fb66e6f9a7ceb3c5a56737337"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$HPVFr8XnWHCneaZkUsT8IuWPM0PYRk8dhSwPC./YCqsMf9tOccVJ2",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "disabled": False,
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI(docs_url="/docs")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        app.openapi_schema = None
        app.openapi_schema = custom_openapi1(user.username)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/items/")
async def read_items():
    return RedirectResponse("127.0.0.1:8001/docs")

@app.get("/products/")
async def read_items(current_user: User = Depends(get_current_active_user)):
    return [{"name": "Foo"}]

def custom_openapi():

    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Custom title",
        version="2.5.0",
        description="This is a very custom OpenAPI schema",
        routes=app.routes,
    )

    key_to_be_deleted = ['/token','/products/', '/items/']

    for key in key_to_be_deleted:
        openapi_schema["paths"].pop(key,None)

    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema

    return app.openapi_schema

def custom_openapi1(username: str = None):

    if username == 'admin':
        print(username)

    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Custom title",
        version="2.5.0",
        description="This is a very custom OpenAPI schema",
        routes=app.routes,
    )

    key_to_be_deleted = ['/token']

    for key in key_to_be_deleted:
        openapi_schema["paths"].pop(key,None)

    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run(app,host="127.0.0.1",port=8001)
