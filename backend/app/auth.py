import bcrypt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status, Request, Header
from fastapi.responses import Response
from jose import JWTError, jwt
from app.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from app.database import get_db

COOKIE_NAME = "soc_token"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_agent_token(agent_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    payload = {"sub": str(agent_id), "scope": "agent", "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def set_token_cookie(response: Response, token: str):
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )


def get_current_user(request: Request, db=Depends(get_db)):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = int(sub)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user



def get_current_agent(authorization: str = Header(default=""), db=Depends(get_db)):
    token = authorization
    if token.startswith("Bearer "):
        token = token[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Missing agent token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") != "agent":
            raise HTTPException(status_code=403, detail="Invalid token scope")
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        agent_id = int(sub)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    agent = db.agent_keys.find_one({"id": agent_id})
    if not agent or agent.get("status") == "revoked":
        raise HTTPException(status_code=401, detail="Agent not found or revoked")
    return agent
