from flask import request, jsonify
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from ..model.model import Signup
from ..config.config import SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES, ALGORITHM, User_details
from passlib.context import CryptContext

pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    if not token:
        return None

    token = token.removeprefix("Bearer").strip()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        if not email:
            return None
        return get_user(email)
    except JWTError as e:
        print(f"JWT decoding error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error decoding token: {e}")
        return None

def get_user(email: str):
    try:
        existing_user = User_details.find_one({'email': email})
        return existing_user if existing_user else None
    except Exception as e:
        print(f"Database error: {e}")
        return None
