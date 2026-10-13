"""Sign in, sign out, and "who am I".

There is no sign-up: accounts are seeded once per deployment and handed out.
The session is an HMAC-signed HttpOnly cookie, so it cannot be read or forged
from JavaScript, and no session table has to be kept in step with it.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from .. import auth, store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    username: str
    password: str


def current_user(request: Request) -> dict:
    """Dependency: the signed-in user, or 401.

    Routers depend on this rather than checking cookies themselves, so there is
    exactly one place where "is this request authenticated" is decided.
    """
    payload = auth.read_token(request.cookies.get(auth.COOKIE_NAME))
    if not payload:
        raise HTTPException(status_code=401, detail="Not signed in")
    user = store.get_user(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    return user


def require_write(user: dict = Depends(current_user)) -> dict:
    """Dependency for anything that starts a run or deletes data."""
    # Data-driven, not the constant set: a custom role granted write access
    # must actually get it.
    if not auth.may_write(user["role"]):
        raise HTTPException(
            status_code=403,
            detail="Your role has read-only access to analyses.",
        )
    return user


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


@router.post("/login")
def login(body: LoginBody, response: Response, request: Request):
    ip = _client_ip(request)
    agent = request.headers.get("user-agent", "")
    user = auth.authenticate(body.username, body.password)

    if not user:
        # Same message either way - never reveal whether the username exists.
        # The attempt is still recorded: a run of failures against one name is
        # exactly what the activity log exists to surface.
        logger.info("failed sign-in for %r", body.username[:40])
        store.record_audit(
            action="auth.login", target=(body.username or "")[:40],
            detail="incorrect username or password", outcome="denied",
            ip=ip, user_agent=agent,
        )
        raise HTTPException(status_code=401, detail="Incorrect username or password.")

    store.touch_login(user["id"])
    store.record_audit(action="auth.login", actor=user, ip=ip, user_agent=agent)
    token = auth.issue_token(user["id"], user["role"])
    response.set_cookie(
        auth.COOKIE_NAME, token,
        max_age=auth.SESSION_TTL,
        httponly=True,
        samesite="lax",
        # Only mark Secure when actually on HTTPS; a Secure cookie is dropped
        # over plain HTTP, which is how this runs on a workstation.
        secure=request.url.scheme == "https",
        path="/",
    )
    logger.info("sign-in: %s (%s)", user["username"], user["role"])
    return {"user": auth.public_user(user)}


@router.post("/logout")
def logout(response: Response, request: Request):
    payload = auth.read_token(request.cookies.get(auth.COOKIE_NAME))
    if payload:
        user = store.get_user(payload["sub"])
        if user:
            store.record_audit(
                action="auth.logout", actor=user,
                ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
            )
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
def me(request: Request):
    """Used at boot to decide between the login screen and the app.

    Returns 200 with `user: null` rather than 401 when signed out, so the shell
    can render the login form without treating it as an error.
    """
    payload = auth.read_token(request.cookies.get(auth.COOKIE_NAME))
    if not payload:
        return {"user": None}
    user = store.get_user(payload["sub"])
    return {"user": auth.public_user(user) if user else None}


@router.get("/roles")
def roles(_user: dict = Depends(current_user)):
    """Role reference, for the admin view."""
    return {
        "roles": [
            {
                "value": role,
                "label": auth.ROLE_LABEL[role],
                "sections": auth.sections_for(role),
                "view": auth.ROLE_VIEW[role],
                "may_switch_view": auth.may_switch_view(role),
                "may_write": role in auth.CAN_WRITE,
            }
            for role in auth.ROLES
        ]
    }
