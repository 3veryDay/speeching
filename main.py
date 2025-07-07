import json

import httpx
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

COGNITO_REGION = "ap-northeast-2"
USER_POOL_ID = "ap-northeast-2_UZxbw6cTN"
APP_CLIENT_ID = "3ositbvugrvfla0ea5d1ipcvpo"

JWKS_URL = "https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_UZxbw6cTN/.well-known/jwks.json"
app = FastAPI()
async def get_public_keys():
    async with httpx.AsyncClient() as client:
        resp = await client.get(JWKS_URL)
        keys = resp.json()["keys"]
        key_map = {}
        for key in keys:
            kid = key["kid"]
            public_key_pem = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key)).public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_map[kid] = public_key_pem
        return key_map

async def verify_cognito_token(
    authorization: str = Header(None)
):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Missing Authorization Header")

    token = authorization.replace("Bearer ", "")
    keys = await get_public_keys()

    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header["kid"]

    key = keys.get(kid)
    if key is None:
        raise HTTPException(status_code=401, detail="Invalid key")

    try:
        decoded = jwt.decode(
            token,
            key=key,
            audience=APP_CLIENT_ID,
            algorithms=["RS256"],
        )
        return decoded
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Token invalid: {str(e)}")

@app.get("/")
async def root():
    return {"message": "Hello Speeching!"}

@app.get("/protected")
async def protected_route(payload=Depends(verify_cognito_token)):
    return JSONResponse(content={"message": "Access granted!", "user": payload})