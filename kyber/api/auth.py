from fastapi import Header, HTTPException

from kyber.config import settings


def require_api_key(x_api_key: str | None = Header(default=None)):
    if not x_api_key or x_api_key not in settings.api_key_set:
        raise HTTPException(status_code=401, detail="invalid API key")
    return x_api_key
