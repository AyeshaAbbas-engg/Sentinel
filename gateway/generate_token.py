import os
from datetime import datetime, timedelta, timezone
from jose import jwt
JWT_SECRET="sentinel-super-secret-key-2026"
ALGORITHM="HS256"

def generate_token(user_id:str,role:str,expires_minutues:int=60):
    payload={
        "sub":user_id,
        "role":role,
        "iat":datetime.now(timezone.utc),
        "exp":datetime.now(timezone.utc)+timedelta(minutes=expires_minutues)
    }
    token=jwt.encode(payload,JWT_SECRET,algorithm=ALGORITHM)
    return token

print("======SENTINEL TEST TOKENS======\n")
print("ADMIN Token:")
print(generate_token("u_admin001","admin"))
print()
print("ANALYST Token:")
print(generate_token("u_analyst001","analyst"))
print()
print("GUEST Token:")
print(generate_token("u_guest001","guest"))