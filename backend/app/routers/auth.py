from fastapi import APIRouter, Depends, HTTPException, Response
from app.database import get_db, get_next_id, strip_mongo_id
from app.auth import hash_password, verify_password, create_access_token, set_token_cookie, get_current_user, COOKIE_NAME
from app.models.user import UserCreate, UserLogin, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", summary="Create a user account")
def register(body: UserCreate, response: Response, db=Depends(get_db)):
    existing = db.users.find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    user = {
        "id": get_next_id("users"),
        "email": body.email,
        "hashed_password": hash_password(body.password),
        "name": body.name,
        "created_at": now,
    }
    db.users.insert_one(user)
    token = create_access_token({"sub": str(user["id"])})
    set_token_cookie(response, token)
    return {"token": token, "user": UserResponse(id=user["id"], email=user["email"], name=user["name"], created_at=user["created_at"])}


@router.post("/login", summary="Log in with email + password")
def login(body: UserLogin, response: Response, db=Depends(get_db)):
    """Authenticate and set the session cookie; returns a bearer token too."""
    user = db.users.find_one({"email": body.email})
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": str(user["id"])})
    set_token_cookie(response, token)
    return {"token": token, "message": "Logged in"}


@router.post("/logout", summary="Log out (clears session cookie)")
def logout(response: Response):
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return {"message": "Logged out"}


@router.get("/me", summary="Get the current user's profile")
def me(user=Depends(get_current_user)):
    return UserResponse(id=user["id"], email=user["email"], name=user["name"], created_at=user["created_at"])
