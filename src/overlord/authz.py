from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from typing import Callable

log = logging.getLogger(__name__)

Authorizer = Callable[[str], "str | None"]


def env_authorizer(token: str) -> str | None:
    """Verify a Tier 2 token against OVERLORD_TIER2_AUTHORIZERS.

    The variable holds JSON mapping an authorizer's name to the SHA-256 hex digest
    of their token. It fails closed: unset or malformed means nobody can authorize.
    """
    raw = os.environ.get("OVERLORD_TIER2_AUTHORIZERS", "")
    if not raw or not token:
        return None
    try:
        table = json.loads(raw)
    except json.JSONDecodeError:
        log.error("OVERLORD_TIER2_AUTHORIZERS is not valid JSON; rejecting all authorizations")
        return None
    if not isinstance(table, dict):
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    match = None
    for name, expected in table.items():
        if hmac.compare_digest(digest, str(expected).lower()):
            match = str(name)
    return match
