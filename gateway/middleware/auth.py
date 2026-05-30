from fastapi import Request, HTTPException
from jose import jwt, JWTError
from config import JWT_SECRET, JWT_ALGORITHM

async def verify_jwt(request: Request) -> dict:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. USE: Bearer <token>")
    token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user_id = payload.get("sub")
    role = payload.get("role")
    if not user_id or not role:
        raise HTTPException(status_code=401, detail="Token missing required claims")
    if role not in ["admin", "analyst", "guest"]:
        raise HTTPException(status_code=403, detail=f"Unknown role: {role}")
    return {"user_id": user_id, "role": role}
