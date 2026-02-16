from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import uuid

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import jwt
from jwt import PyJWK
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# -----------------------------
# Config
# -----------------------------

JWT_ISSUER = "example-issuer"
JWT_AUDIENCE = "example-audience"
JWT_LIFETIME_SECONDS = 300  # 5 minutes
KEY_LIFETIME_SECONDS = 600  # 10 minutes

ALGORITHM = "RS256"


# -----------------------------
# Key store and models
# -----------------------------

class KeyEntry(BaseModel):
    kid: str
    private_pem: str
    public_pem: str
    expires_at: datetime


class KeyStore:
    """
    In-memory key store with expiry.
    For a real system, you'd persist keys and rotate them properly.
    """

    def __init__(self):
        self._keys: Dict[str, KeyEntry] = {}
        self._expired_key: Optional[KeyEntry] = None

    def _generate_rsa_keypair(self) -> KeyEntry:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        kid = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=KEY_LIFETIME_SECONDS)

        return KeyEntry(
            kid=kid,
            private_pem=private_pem,
            public_pem=public_pem,
            expires_at=expires_at,
        )

    def get_active_key(self) -> KeyEntry:
        """
        Return an unexpired key. If none exists, generate a new one.
        """
        now = datetime.now(timezone.utc)
        # Remove expired keys from active store, but keep the last expired one separately
        expired_kids = []
        for kid, entry in self._keys.items():
            if entry.expires_at <= now:
                expired_kids.append(kid)
                self._expired_key = entry
        for kid in expired_kids:
            del self._keys[kid]

        # If there is at least one active key, return any
        for entry in self._keys.values():
            if entry.expires_at > now:
                return entry

        # Otherwise, generate a new one
        new_entry = self._generate_rsa_keypair()
        self._keys[new_entry.kid] = new_entry
        return new_entry

    def get_expired_key(self) -> Optional[KeyEntry]:
        """
        Return a previously expired key, if any.
        """
        return self._expired_key

    def get_unexpired_public_jwks(self) -> Dict:
        """
        Return JWKS containing only unexpired public keys.
        """
        now = datetime.now(timezone.utc)
        keys: List[Dict] = []

        for entry in list(self._keys.values()):
            if entry.expires_at <= now:
                # Move to expired slot
                self._expired_key = entry
                del self._keys[entry.kid]
                continue

            # Convert PEM to JWK
            jwk_obj = PyJWK.from_buffer(entry.public_pem.encode("utf-8"))
            jwk_dict = jwk_obj.to_dict()
            jwk_dict["kid"] = entry.kid
            jwk_dict["alg"] = ALGORITHM
            jwk_dict["use"] = "sig"
            keys.append(jwk_dict)

        return {"keys": keys}


key_store = KeyStore()
app = FastAPI()


# -----------------------------
# JWT helpers
# -----------------------------

def create_jwt_for_key(entry: KeyEntry, expired: bool = False) -> str:
    """
    Create a JWT signed with the given key.
    If expired=True, the 'exp' claim will be in the past.
    """
    now = datetime.now(timezone.utc)
    if expired:
        exp = now - timedelta(seconds=60)
    else:
        exp = now + timedelta(seconds=JWT_LIFETIME_SECONDS)

    payload = {
        "sub": "fake-user-id",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    token = jwt.encode(
        payload,
        entry.private_pem,
        algorithm=ALGORITHM,
        headers={"kid": entry.kid},
    )
    return token


# -----------------------------
# Routes
# -----------------------------

@app.get("/jwks")
def jwks():
    """
    JWKS endpoint.
    Returns only unexpired public keys in JWKS format.
    """
    jwks_body = key_store.get_unexpired_public_jwks()
    return JSONResponse(content=jwks_body)


@app.post("/auth")
def auth(expired: bool = Query(default=False)):
    """
    Authentication endpoint.
    - Always returns a JWT (no real auth for this assignment).
    - If expired=false (default): sign with an unexpired key and unexpired exp.
    - If expired=true: sign with an expired key and expired exp.
    """
    if not expired:
        key_entry = key_store.get_active_key()
        token = create_jwt_for_key(key_entry, expired=False)
        return {"access_token": token, "token_type": "bearer"}

    # expired == True
    expired_key = key_store.get_expired_key()
    if expired_key is None:
        # Force creation of an active key, then let it expire quickly for demo
        active = key_store.get_active_key()
        # Simulate expiry by setting its expiry in the past
        active.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        # Next call to get_expired_key will pick it up
        expired_key = key_store.get_expired_key()

    if expired_key is None:
        raise HTTPException(status_code=500, detail="No expired key available")

    token = create_jwt_for_key(expired_key, expired=True)
    return {"access_token": token, "token_type": "bearer"}


# -----------------------------
# Entry point for running
# -----------------------------

# Run with:
#   uvicorn main:app --host 0.0.0.0 --port 8080
#
# The assignment specifies port 8080, so use that when starting uvicorn.