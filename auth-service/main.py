from fastapi import FastAPI, Depends, HTTPException
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated


ALGORITHM = "HS256"
SECRET_KEY = "A Secure Secret Key"


fake_users_db: dict[str, dict[str, str]] = {
    "ameenalam": {
        "username": "ameenalam",
        "full_name": "Ameen Alam",
        "email": "ameenalam@example.com",
        "password": "ameenalamsecret",
    },
    "mjunaid": {
        "username": "mjunaid",
        "full_name": "Muhammad Junaid",
        "email": "mjunaid@example.com",
        "password": "mjunaidsecret",
    },
}


app = FastAPI()

def create_access_token(subject: str , expires_delta: timedelta) -> str:
    expire = datetime.utcnow() + expires_delta
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(access_token: str):
    decoded_jwt = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    return decoded_jwt

@app.get("/new_route")
def get_access_token(user_name: str):
    """
    Understanding the access token
    -> Takes user_name as input and returns access token
    -> timedelta(minutes=1) is used to set the expiry time of the access token to 1 minute
    """
    
    access_token_expires = timedelta(minutes=1)
    access_token = create_access_token(subject=user_name, expires_delta=access_token_expires)
    
    return {"access_token": access_token}

@app.get("/decode_token")
def decoding_token(access_token: str):
    """
    Understanding the access token decoding and validation
    """
    try:
        decoded_token_data = decode_access_token(access_token)
        return {"decoded_token": decoded_token_data}
    except JWTError as e:
        return {"error": str(e)}
    
@app.post("/login")
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)]):
     user_in_fake_db = fake_users_db.get(form_data.username)
     if not user_in_fake_db:
        raise HTTPException(status_code=400, detail="Incorrect username")

     if not form_data.password == user_in_fake_db["password"]:
        raise HTTPException(status_code=400, detail="Incorrect password")

     access_token_expires = timedelta(minutes=1)

     access_token = create_access_token(
        subject=user_in_fake_db["username"], expires_delta=access_token_expires)

     return {"access_token": access_token, "token_type": "bearer", "expires_in": access_token_expires.total_seconds() }