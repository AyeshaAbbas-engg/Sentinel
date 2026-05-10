import os
from datetime import datetime, timezone
from fastapi import Request, HTTPException
from jose import jwt, JWTError

JWT_SECRET=os.getenv("JWT_SECRET","sentinel-super-secret-key-2026")
ALGORITHM="HS256"

async def verify_jwt(request:Request)-> dict :
    auth_header=request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not auth_header.startswith("Bearer"):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. USE: Bearer <token>")
    token=auth_header.split(" ")[1]
    try:
        payload=jwt.decode(token,JWT_SECRET,algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401,detail="Invalid or expired token")
    user_id=payload.get("sub")
    role=payload.get("role")
    if not user_id or not role:
        raise HTTPException(status_code=401, detail="Token missing required claims")
    if role not in ["admin","user","guest"]:
        raise HTTPException(status_code=403, detail="Unknown role : {role}")
    return {"user_id":user_id,"role":role}    
