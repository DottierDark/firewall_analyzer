"""Authentication and role-based access.

Standard library only, matching the rest of the service: PBKDF2-SHA256 for
password hashing and an HMAC-signed cookie for the session. No sign-up flow -
accounts are seeded once and handed out, which is what an internal assessment
tool actually needs.

Roles are a fixed ladder, not a permission matrix. Each role maps to what it may
see (`ROLE_SECTIONS`) and which dashboard preset it gets (`ROLE_VIEW`); the
administrator is the only role that may switch between presets.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional

from . import config, store

# ── Roles ────────────────────────────────────────────────────────────────

ADMINISTRATOR = "administrator"
EXECUTIVE = "executive"
SECURITY_MANAGER = "security_manager"
ANALYST = "analyst"

ROLES = [ADMINISTRATOR, EXECUTIVE, SECURITY_MANAGER, ANALYST]

ROLE_LABEL = {
    ADMINISTRATOR: "Administrator",
    EXECUTIVE: "Executive",
    SECURITY_MANAGER: "Security Manager",
    ANALYST: "Analyst",
}

#: Which sidebar sections each role may see. "dashboard" and "analysis" are the
#: read-only views; "configuration" runs analyses and changes settings;
#: "history" lists past runs. An executive gets the findings, not the machinery.
ROLE_SECTIONS = {
    ADMINISTRATOR:    ["dashboard", "analysis", "configuration", "history"],
    SECURITY_MANAGER: ["dashboard", "analysis", "configuration", "history"],
    ANALYST:          ["dashboard", "analysis", "configuration", "history"],
    EXECUTIVE:        ["dashboard", "analysis"],
}

#: The dashboard preset a role lands on. Only the administrator may change it -
#: for everyone else the preset is the role, so the switcher is hidden.
ROLE_VIEW = {
    ADMINISTRATOR:    "analyst",
    EXECUTIVE:        "executive",
    SECURITY_MANAGER: "manager",
    ANALYST:          "analyst",
}

#: Roles allowed to start a run or delete an analysis.
CAN_WRITE = {ADMINISTRATOR, SECURITY_MANAGER, ANALYST}


#: The sections a role may be granted. Anything outside this set is rejected
#: when a role is created, so a typo cannot silently grant nothing.
ALL_SECTIONS = ["dashboard", "analysis", "configuration", "history"]

#: Dashboard presets a role may land on.
ALL_VIEWS = ["executive", "manager", "analyst"]


def seed_roles() -> None:
    """Write the four built-in roles into the roles table if absent.

    Roles live in the database rather than in this module so an administrator
    can add their own without a code change. The four below are marked
    is_builtin and cannot be deleted - removing Administrator would lock
    everyone out of role management permanently.
    """
    descriptions = {
        ADMINISTRATOR: "Full access, including user and role administration.",
        EXECUTIVE: "Posture and findings only. No configuration or run history.",
        SECURITY_MANAGER: "Runs analyses and owns the remediation list.",
        ANALYST: "Rule-level detail and the evidence behind every score.",
    }
    for role in ROLES:
        if store.get_role(role):
            continue
        store.upsert_role(
            name=role,
            label=ROLE_LABEL[role],
            sections=ROLE_SECTIONS[role],
            view=ROLE_VIEW[role],
            may_switch_view=(role == ADMINISTRATOR),
            may_write=(role in CAN_WRITE),
            description=descriptions.get(role, ""),
            is_builtin=True,
        )


def role_record(role: str) -> Dict[str, Any]:
    """Role definition from the database, falling back to the built-in constants.

    The fallback matters during the first request after an upgrade, before
    seed_roles has run, and for a user whose role row was deleted.
    """
    found = store.get_role(role)
    if found:
        return found
    return {
        "name": role,
        "label": ROLE_LABEL.get(role, role.replace("_", " ").title()),
        "sections": ROLE_SECTIONS.get(role, ROLE_SECTIONS[EXECUTIVE]),
        "view": ROLE_VIEW.get(role, "executive"),
        "may_switch_view": role == ADMINISTRATOR,
        "may_write": role in CAN_WRITE,
        "is_builtin": role in ROLES,
        "description": "",
    }


def may_switch_view(role: str) -> bool:
    return bool(role_record(role)["may_switch_view"])


def sections_for(role: str) -> List[str]:
    return role_record(role)["sections"]


def may_write(role: str) -> bool:
    return bool(role_record(role)["may_write"])


def is_admin(role: str) -> bool:
    """Administration is gated on the ability to manage roles, which is what
    `may_switch_view` marks on the built-in Administrator. Kept as its own
    predicate so a custom role can be granted it deliberately."""
    return role == ADMINISTRATOR or "administration" in role_record(role)["sections"]


# ── Passwords ────────────────────────────────────────────────────────────

_ITERATIONS = 200_000


def hash_password(password: str, *, salt: Optional[bytes] = None) -> str:
    """`pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>`."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return "$".join([
        "pbkdf2_sha256", str(_ITERATIONS),
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    ])


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), base64.b64decode(salt_b64), int(iterations)
        )
        # compare_digest: constant time, so a wrong password cannot be narrowed
        # down by timing the response.
        return hmac.compare_digest(digest, base64.b64decode(hash_b64))
    except (ValueError, TypeError):
        return False


# ── Session cookie ───────────────────────────────────────────────────────

COOKIE_NAME = "fwa_session"
SESSION_TTL = int(os.environ.get("FWA_SESSION_TTL", 12 * 60 * 60))  # 12 hours


def _secret_key() -> bytes:
    """Persist a signing key beside the database.

    Regenerating it on every boot would sign every user out on restart; keeping
    it in the data directory (0600) keeps sessions alive across restarts without
    putting a secret in the repo.
    """
    override = os.environ.get("FWA_SECRET_KEY")
    if override:
        return override.encode()

    config.ensure_dirs()
    key_path = config.DATA_DIR / "session.key"
    if key_path.exists():
        return key_path.read_bytes()

    key = secrets.token_bytes(32)
    key_path.write_bytes(key)
    try:
        key_path.chmod(0o600)
    except OSError:
        pass  # best effort; Windows has no POSIX modes
    return key


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_token(user_id: str, role: str) -> str:
    """A signed, self-contained session token: `<payload>.<signature>`."""
    payload = {"sub": user_id, "role": role, "exp": int(time.time()) + SESSION_TTL}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(_secret_key(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64(signature)}"


def read_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Validate signature and expiry; return the payload or None."""
    if not token or "." not in token:
        return None
    body, _, signature = token.partition(".")
    expected = hmac.new(_secret_key(), body.encode(), hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(expected, _unb64(signature)):
            return None
        payload = json.loads(_unb64(body))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None

    if payload.get("exp", 0) < time.time():
        return None
    return payload


# ── Seeding ──────────────────────────────────────────────────────────────

#: One account per role, created on first run only.
SEED_ACCOUNTS = [
    ("admin", "Platform Administrator", ADMINISTRATOR),
    ("executive", "Executive Viewer", EXECUTIVE),
    ("manager", "Security Manager", SECURITY_MANAGER),
    ("analyst", "Security Analyst", ANALYST),
]


def seed_users() -> List[Dict[str, str]]:
    """Create the four role accounts if the table is empty.

    Passwords come from `FWA_PASSWORD_<USERNAME>` when set, otherwise they are
    generated. The plaintext is returned once so the launcher can print it; only
    the hash is ever stored.
    """
    if store.count_users() > 0:
        return []

    created = []
    for username, display_name, role in SEED_ACCOUNTS:
        env_key = f"FWA_PASSWORD_{username.upper()}"
        password = os.environ.get(env_key) or secrets.token_urlsafe(9)
        store.create_user(
            user_id=f"USR_{secrets.token_hex(6)}",
            username=username,
            display_name=display_name,
            role=role,
            password_hash=hash_password(password),
        )
        created.append({
            "username": username,
            "password": password,
            "role": ROLE_LABEL[role],
            "generated": env_key not in os.environ,
        })
    return created


def reset_passwords() -> List[Dict[str, str]]:
    """Set a fresh password on every seeded role account.

    `seed_users` deliberately runs only once, so a deployment whose generated
    passwords were lost had no way back in. This is that way back: it creates
    any missing account and re-hashes the rest, honouring FWA_PASSWORD_<ROLE>
    when set and generating one otherwise. Returns the plaintext once so the
    launcher can print it.
    """
    results = []
    for username, display_name, role in SEED_ACCOUNTS:
        env_key = f"FWA_PASSWORD_{username.upper()}"
        password = os.environ.get(env_key) or secrets.token_urlsafe(9)
        existing = store.get_user_by_username(username)
        if existing:
            store.set_password(existing["id"], hash_password(password))
        else:
            store.create_user(
                user_id=f"USR_{secrets.token_hex(6)}",
                username=username,
                display_name=display_name,
                role=role,
                password_hash=hash_password(password),
            )
        results.append({
            "username": username,
            "password": password,
            "role": ROLE_LABEL[role],
            "generated": env_key not in os.environ,
        })
    return results


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = store.get_user_by_username((username or "").strip().lower())
    if not user or not verify_password(password or "", user["password_hash"]):
        return None
    return user


def public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    """The shape the frontend receives - never the hash."""
    role = user["role"]
    record = role_record(role)
    sections = list(record["sections"])
    if is_admin(role) and "administration" not in sections:
        sections.append("administration")
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "role": role,
        "role_label": record["label"],
        "sections": sections,
        "view": record["view"],
        "may_switch_view": bool(record["may_switch_view"]),
        "may_write": bool(record["may_write"]),
        "is_admin": is_admin(role),
        "last_login": user.get("last_login"),
    }
