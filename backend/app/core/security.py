"""API key + per-device token auth."""
from __future__ import annotations

import hmac
import secrets

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db import get_session
from app.models import Device
from app.services.text_utils import sha256_hex


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if not hmac.compare_digest(x_api_key, get_settings().api_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid api key")


def new_device_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, sha256_hex(token)


async def current_device(
    x_device_token: str = Header(default=""),
    _: None = Depends(require_api_key),
    session: AsyncSession = Depends(get_session),
) -> Device:
    if not x_device_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing device token")
    dev = (await session.execute(select(Device).where(Device.token_hash == sha256_hex(x_device_token)))).scalar_one_or_none()
    if dev is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown device")
    return dev
