"""Administration: accounts, roles, and the activity log.

Every route requires an administrator. Role definitions live in the database
rather than in code, so an administrator can add a role for their own
organisation without a deployment.
"""

import logging
import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import auth, store
from .auth import current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin(user: dict = Depends(current_user)) -> dict:
    if not auth.is_admin(user["role"]):
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


# ── Users ────────────────────────────────────────────────────────────────


class NewUser(BaseModel):
    username: str = Field(min_length=2, max_length=40)
    display_name: str = Field(min_length=1, max_length=80)
    role: str
    password: Optional[str] = Field(default=None, min_length=8, max_length=200)


class RoleChange(BaseModel):
    role: str


class PasswordChange(BaseModel):
    password: Optional[str] = Field(default=None, min_length=8, max_length=200)


@router.get("/users")
def list_users(_admin: dict = Depends(require_admin)):
    users = store.list_users()
    for user in users:
        record = auth.role_record(user["role"])
        user["role_label"] = record["label"]
        user["may_write"] = bool(record["may_write"])
    return {"items": users}


@router.post("/users", status_code=201)
def create_user(body: NewUser, request: Request, admin: dict = Depends(require_admin)):
    username = body.username.strip().lower()
    if not username.isidentifier() and not username.replace("-", "_").isidentifier():
        raise HTTPException(status_code=400, detail="Username may contain letters, digits, - and _ only.")
    if store.get_user_by_username(username):
        raise HTTPException(status_code=409, detail=f"User '{username}' already exists.")
    if not store.get_role(body.role):
        raise HTTPException(status_code=400, detail=f"No such role: {body.role}")

    password = body.password or secrets.token_urlsafe(9)
    store.create_user(
        user_id=f"USR_{secrets.token_hex(6)}",
        username=username,
        display_name=body.display_name.strip(),
        role=body.role,
        password_hash=auth.hash_password(password),
    )
    store.record_audit(
        action="user.create", actor=admin, target=username,
        detail=f"role={body.role}", ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    # Returned once so the administrator can hand it over; never stored in clear.
    return {"username": username, "password": password, "generated": body.password is None}


@router.patch("/users/{user_id}/role")
def change_role(user_id: str, body: RoleChange, request: Request,
                admin: dict = Depends(require_admin)):
    user = store.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not store.get_role(body.role):
        raise HTTPException(status_code=400, detail=f"No such role: {body.role}")

    # Removing the last administrator would leave nobody able to grant the role
    # back, so that particular change is refused.
    if auth.is_admin(user["role"]) and not auth.is_admin(body.role):
        admins = [u for u in store.list_users() if auth.is_admin(u["role"])]
        if len(admins) <= 1:
            raise HTTPException(
                status_code=409,
                detail="This is the only administrator. Promote someone else first.",
            )

    previous = user["role"]
    store.set_user_role(user_id, body.role)
    store.record_audit(
        action="user.role_change", actor=admin, target=user["username"],
        detail=f"{previous} -> {body.role}", ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    return {"ok": True, "username": user["username"], "role": body.role}


@router.post("/users/{user_id}/password")
def reset_user_password(user_id: str, body: PasswordChange, request: Request,
                        admin: dict = Depends(require_admin)):
    user = store.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    password = body.password or secrets.token_urlsafe(9)
    store.set_password(user_id, auth.hash_password(password))
    store.record_audit(
        action="user.password_reset", actor=admin, target=user["username"],
        ip=client_ip(request), user_agent=request.headers.get("user-agent", ""),
    )
    return {"username": user["username"], "password": password, "generated": body.password is None}


@router.delete("/users/{user_id}", status_code=204)
def remove_user(user_id: str, request: Request, admin: dict = Depends(require_admin)):
    user = store.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user["id"] == admin["id"]:
        raise HTTPException(status_code=409, detail="You cannot delete your own account.")
    if auth.is_admin(user["role"]):
        admins = [u for u in store.list_users() if auth.is_admin(u["role"])]
        if len(admins) <= 1:
            raise HTTPException(status_code=409, detail="This is the only administrator.")

    store.delete_user(user_id)
    store.record_audit(
        action="user.delete", actor=admin, target=user["username"],
        detail=f"role={user['role']}", ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
    )
    return None


# ── Roles ────────────────────────────────────────────────────────────────


class RoleBody(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    label: str = Field(min_length=1, max_length=60)
    sections: List[str]
    view: str
    may_switch_view: bool = False
    may_write: bool = False
    description: str = ""


@router.get("/roles")
def list_roles(_admin: dict = Depends(require_admin)):
    roles = store.list_roles()
    for role in roles:
        role["user_count"] = store.count_users_with_role(role["name"])
    return {
        "items": roles,
        "all_sections": auth.ALL_SECTIONS,
        "all_views": auth.ALL_VIEWS,
    }


@router.post("/roles", status_code=201)
def create_role(body: RoleBody, request: Request, admin: dict = Depends(require_admin)):
    name = body.name.strip().lower().replace(" ", "_")
    if not name.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="Role name may contain letters, digits, - and _ only.")
    if store.get_role(name):
        raise HTTPException(status_code=409, detail=f"Role '{name}' already exists.")

    unknown = [s for s in body.sections if s not in auth.ALL_SECTIONS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown section(s): {', '.join(unknown)}")
    if body.view not in auth.ALL_VIEWS:
        raise HTTPException(status_code=400, detail=f"View must be one of: {', '.join(auth.ALL_VIEWS)}")

    store.upsert_role(
        name=name, label=body.label.strip(), sections=body.sections, view=body.view,
        may_switch_view=body.may_switch_view, may_write=body.may_write,
        description=body.description.strip(), is_builtin=False,
    )
    store.record_audit(
        action="role.create", actor=admin, target=name,
        detail=f"sections={'|'.join(body.sections)} view={body.view}",
        ip=client_ip(request), user_agent=request.headers.get("user-agent", ""),
    )
    return store.get_role(name)


@router.put("/roles/{name}")
def update_role(name: str, body: RoleBody, request: Request,
                admin: dict = Depends(require_admin)):
    existing = store.get_role(name)
    if not existing:
        raise HTTPException(status_code=404, detail="Role not found")

    unknown = [s for s in body.sections if s not in auth.ALL_SECTIONS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown section(s): {', '.join(unknown)}")
    if body.view not in auth.ALL_VIEWS:
        raise HTTPException(status_code=400, detail=f"View must be one of: {', '.join(auth.ALL_VIEWS)}")
    # A built-in keeps its identity; only its grants may be edited.
    if existing["is_builtin"] and name == auth.ADMINISTRATOR and not body.may_switch_view:
        raise HTTPException(
            status_code=409,
            detail="The Administrator role must keep full view access.",
        )

    store.upsert_role(
        name=name, label=body.label.strip(), sections=body.sections, view=body.view,
        may_switch_view=body.may_switch_view, may_write=body.may_write,
        description=body.description.strip(), is_builtin=existing["is_builtin"],
    )
    store.record_audit(
        action="role.update", actor=admin, target=name,
        detail=f"sections={'|'.join(body.sections)} view={body.view}",
        ip=client_ip(request), user_agent=request.headers.get("user-agent", ""),
    )
    return store.get_role(name)


@router.delete("/roles/{name}", status_code=204)
def remove_role(name: str, request: Request, admin: dict = Depends(require_admin)):
    role = store.get_role(name)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role["is_builtin"]:
        raise HTTPException(status_code=409, detail="Built-in roles cannot be deleted.")

    holders = store.count_users_with_role(name)
    if holders:
        raise HTTPException(
            status_code=409,
            detail=f"{holders} account(s) still use this role. Reassign them first.",
        )

    store.delete_role(name)
    store.record_audit(
        action="role.delete", actor=admin, target=name,
        ip=client_ip(request), user_agent=request.headers.get("user-agent", ""),
    )
    return None


# ── Activity ─────────────────────────────────────────────────────────────


@router.get("/audit")
def list_audit(
    limit: int = 100, offset: int = 0,
    action: Optional[str] = None, actor: Optional[str] = None,
    outcome: Optional[str] = None, search: Optional[str] = None,
    _admin: dict = Depends(require_admin),
):
    result = store.query_audit(
        limit=min(limit, 500), offset=offset, action=action,
        actor=actor, outcome=outcome, search=search,
    )
    result["actions"] = store.audit_actions()
    return result
