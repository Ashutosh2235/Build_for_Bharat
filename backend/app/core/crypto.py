"""At-rest encryption for message text / SMS logs (Fernet)."""
from __future__ import annotations

import json
import logging
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

log = logging.getLogger(__name__)


@lru_cache
def _fernet() -> Fernet:
    s = get_settings()
    key = s.fernet_key
    if not key:
        if s.is_production:
            raise RuntimeError("FERNET_KEY must be set in production")
        log.warning("FERNET_KEY not set — using an ephemeral key; stored text is unreadable after restart")
        key = Fernet.generate_key().decode()
    return Fernet(key.encode())


def encrypt_json(obj) -> str:
    return _fernet().encrypt(json.dumps(obj, ensure_ascii=False).encode()).decode()


def decrypt_json(token: str | None):
    if not token:
        return None
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except InvalidToken:
        log.error("could not decrypt stored data (key changed?)")
        return None
