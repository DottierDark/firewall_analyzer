"""SQLite persistence.

Plain `sqlite3` rather than an ORM: the schema is five tables, the analyzer has
no runtime dependencies, and keeping it that way means the API installs with
three packages. Findings and rules land in real tables (not a JSON blob) so the
Findings and Rule Explorer pages can filter, sort and paginate server-side.
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from . import config

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS roles (
    name             TEXT PRIMARY KEY,
    label            TEXT NOT NULL,
    sections         TEXT NOT NULL,        -- json array
    view             TEXT NOT NULL,        -- dashboard preset
    may_switch_view  INTEGER NOT NULL DEFAULT 0,
    may_write        INTEGER NOT NULL DEFAULT 0,
    is_builtin       INTEGER NOT NULL DEFAULT 0,
    description      TEXT,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    actor_id     TEXT,
    actor_name   TEXT,
    actor_role   TEXT,
    action       TEXT NOT NULL,
    target       TEXT,
    detail       TEXT,
    outcome      TEXT NOT NULL DEFAULT 'ok',
    ip           TEXT,
    user_agent   TEXT
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts DESC);
CREATE INDEX IF NOT EXISTS ix_audit_actor ON audit(actor_name, ts DESC);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyses (
    id            TEXT PRIMARY KEY,
    project_id    TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    label         TEXT NOT NULL,
    vendor        TEXT,
    framework     TEXT,
    filename      TEXT NOT NULL,
    source_path   TEXT NOT NULL,
    status        TEXT NOT NULL,          -- queued | running | succeeded | failed
    progress      TEXT,                   -- human-readable current step
    error         TEXT,
    created_at    TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT,
    summary       TEXT,                   -- json
    stats         TEXT,                   -- json
    zone_summary  TEXT,                   -- json
    compliance    TEXT,                   -- json: one assessment per framework (see _compliance_v2)
    report_path   TEXT
);
CREATE INDEX IF NOT EXISTS ix_analyses_project ON analyses(project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id    TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    rule_id        TEXT,
    rule_name      TEXT,
    issue_type     TEXT,
    risk_level     TEXT,
    score          INTEGER,
    description    TEXT,
    recommendation TEXT,
    formula        TEXT,
    details        TEXT                   -- json
);
CREATE INDEX IF NOT EXISTS ix_findings_analysis ON findings(analysis_id, score DESC);
CREATE INDEX IF NOT EXISTS ix_findings_risk     ON findings(analysis_id, risk_level);

CREATE TABLE IF NOT EXISTS rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id   TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    seq           INTEGER,
    rule_id       TEXT,
    name          TEXT,
    action        TEXT,
    disabled      INTEGER,
    src_zones     TEXT,
    dst_zones     TEXT,
    src_addresses TEXT,
    dst_addresses TEXT,
    services      TEXT,
    applications  TEXT,
    logging       TEXT,
    rule_usage    TEXT,
    risk_score    INTEGER,
    finding_count INTEGER,
    -- 1 when the engine actually scored this rule. A risk_score of 0 is
    -- otherwise ambiguous between "assessed and clean" and "never assessed",
    -- and counting the latter as clean flatters the hygiene figure.
    analyzed      INTEGER NOT NULL DEFAULT 1,
    raw           TEXT                    -- json
);
CREATE INDEX IF NOT EXISTS ix_rules_analysis ON rules(analysis_id, risk_score DESC);
"""


def connect() -> sqlite3.Connection:
    """One connection per thread; SQLite objects are not shareable across them."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        config.ensure_dirs()
        conn = sqlite3.connect(config.DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    with tx() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)


def _migrate(conn: sqlite3.Connection) -> None:
    """Additive migrations for databases created by an earlier version.

    One function, deliberately: a second def with this name silently shadows
    the first and its migrations never run, which is exactly what happened when
    the compliance column was added alongside an existing framework migration.
    """
    analyses_columns = {r["name"] for r in conn.execute("PRAGMA table_info(analyses)")}
    if "framework" not in analyses_columns:
        conn.execute("ALTER TABLE analyses ADD COLUMN framework TEXT")
    if "compliance" not in analyses_columns:
        conn.execute("ALTER TABLE analyses ADD COLUMN compliance TEXT")

    columns = {r["name"] for r in conn.execute("PRAGMA table_info(rules)")}
    if "analyzed" not in columns:
        conn.execute("ALTER TABLE rules ADD COLUMN analyzed INTEGER NOT NULL DEFAULT 1")
        # Backfill using the engine's own exclusion rule, so existing analyses
        # report the same population a fresh run would: disabled rules and
        # catch-all deny any->any cleanup rules were never scored.
        conn.execute(
            """UPDATE rules SET analyzed = 0
               WHERE disabled = 1
                  OR (LOWER(action) = 'deny'
                      AND src_addresses IN ('["any"]', '["Any"]', '["ANY"]')
                      AND dst_addresses IN ('["any"]', '["Any"]', '["ANY"]'))"""
        )

def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _loads(value: Optional[str]) -> Any:
    return json.loads(value) if value else None


# ---------------------------------------------------------------- projects


def upsert_project(project_id: str, name: str) -> Dict[str, Any]:
    with tx() as conn:
        existing = conn.execute(
            "SELECT * FROM projects WHERE name = ?", (name,)
        ).fetchone()
        if existing:
            return dict(existing)
        conn.execute(
            "INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)",
            (project_id, name, now()),
        )
    return {"id": project_id, "name": name, "created_at": now()}


def list_projects() -> List[Dict[str, Any]]:
    rows = connect().execute(
        """
        SELECT p.*,
               (SELECT COUNT(*) FROM analyses a WHERE a.project_id = p.id) AS analysis_count
        FROM projects p ORDER BY p.created_at DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- analyses


def create_analysis(record: Dict[str, Any]) -> None:
    cols = ", ".join(record)
    marks = ", ".join("?" for _ in record)
    with tx() as conn:
        conn.execute(f"INSERT INTO analyses ({cols}) VALUES ({marks})", tuple(record.values()))


def update_analysis(analysis_id: str, **fields: Any) -> None:
    if not fields:
        return
    assignments = ", ".join(f"{k} = ?" for k in fields)
    with tx() as conn:
        conn.execute(
            f"UPDATE analyses SET {assignments} WHERE id = ?",
            (*fields.values(), analysis_id),
        )


def get_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
    row = connect().execute(
        """
        SELECT a.*, p.name AS project_name
        FROM analyses a JOIN projects p ON p.id = a.project_id
        WHERE a.id = ?
        """,
        (analysis_id,),
    ).fetchone()
    if not row:
        return None
    record = dict(row)
    for key in ("summary", "stats", "zone_summary", "compliance"):
        record[key] = _loads(record.get(key))
    record["compliance"] = _compliance_v2(record.get("compliance"), record.get("framework"))
    record["frameworks"] = record["compliance"]["frameworks"]
    return record


def _compliance_v2(value: Optional[Dict[str, Any]], framework_col: Optional[str]) -> Dict[str, Any]:
    """Every stored compliance record in the current shape:

        {"version": 2, "frameworks": [keys, in the order requested],
         "assessments": {key: {..result.., "status": assessed|not_implemented|error|missing}}}

    Version 1 (before multi-framework) stored one bare result, or a bare
    not-implemented marker, and kept the single key in the `framework` column.
    Upgrading on read means no migration rewrites anyone's data. A framework
    that was requested but has nothing stored gets an explicit status, so the
    UI can say why instead of showing an empty tab.
    """
    from firewall_analyzer.analysis.frameworks import REGISTRY

    def describe(key: str) -> Dict[str, Any]:
        fw = REGISTRY.get(key)
        if fw:
            return {"key": fw.key, "short": fw.short, "name": fw.name, "group_label": fw.group_label}
        return {"key": key, "short": key.upper(), "name": key.upper(), "group_label": "Group"}

    requested = [k.strip().lower() for k in (framework_col or "").split(",") if k.strip()]

    if isinstance(value, dict) and value.get("version") == 2:
        record = value
    elif isinstance(value, dict) and (value.get("controls") or value.get("status") == "not_implemented"):
        key = str(value.get("requested_framework") or (requested[0] if requested else "ecc")).lower()
        if value.get("status") == "not_implemented":
            entry = {"status": "not_implemented", "message": value.get("message", "")}
        else:
            entry = {**value, "status": "assessed"}
        record = {"version": 2, "frameworks": [key], "assessments": {key: {**entry, **describe(key)}}}
    else:
        record = {"version": 2, "frameworks": requested, "assessments": {}}

    for key in record["frameworks"]:
        if key in record["assessments"]:
            continue
        fw = REGISTRY.get(key)
        if fw is not None and not fw.implemented:
            status, message = "not_implemented", (
                "Its controls are not implemented yet, so no assessment was produced on this run.")
        else:
            status, message = "missing", (
                "This run was made before compliance results were stored. "
                "Re-run the export to produce an assessment.")
        record["assessments"][key] = {**describe(key), "status": status, "message": message}
    return record

def list_analyses(limit: int = 50, project_id: Optional[str] = None) -> List[Dict[str, Any]]:
    sql = """
        SELECT a.id, a.label, a.vendor, a.filename, a.status, a.progress, a.error,
               a.created_at, a.finished_at, a.summary, a.stats, p.name AS project_name
        FROM analyses a JOIN projects p ON p.id = a.project_id
    """
    params: List[Any] = []
    if project_id:
        sql += " WHERE a.project_id = ?"
        params.append(project_id)
    sql += " ORDER BY a.created_at DESC LIMIT ?"
    params.append(limit)

    out = []
    for row in connect().execute(sql, params).fetchall():
        record = dict(row)
        record["summary"] = _loads(record.get("summary"))
        record["stats"] = _loads(record.get("stats"))
        out.append(record)
    return out


def delete_analysis(analysis_id: str) -> bool:
    with tx() as conn:
        cur = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    return cur.rowcount > 0


# ------------------------------------------------------- findings and rules


def insert_findings(analysis_id: str, findings: List[Dict[str, Any]]) -> None:
    if not findings:
        return
    with tx() as conn:
        conn.executemany(
            """INSERT INTO findings
               (analysis_id, rule_id, rule_name, issue_type, risk_level, score,
                description, recommendation, formula, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    analysis_id, f["rule_id"], f["rule_name"], f["issue_type"],
                    f["risk_level"], f["score"], f["description"],
                    f["recommendation"], f.get("formula", ""),
                    json.dumps(f.get("details") or {}),
                )
                for f in findings
            ],
        )


def insert_rules(analysis_id: str, rules: List[Dict[str, Any]]) -> None:
    if not rules:
        return
    with tx() as conn:
        conn.executemany(
            """INSERT INTO rules
               (analysis_id, seq, rule_id, name, action, disabled, src_zones, dst_zones,
                src_addresses, dst_addresses, services, applications, logging,
                rule_usage, risk_score, finding_count, analyzed, raw)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    analysis_id, r["seq"], r["rule_id"], r["name"], r["action"],
                    int(r["disabled"]), json.dumps(r["src_zones"]), json.dumps(r["dst_zones"]),
                    json.dumps(r["src_addresses"]), json.dumps(r["dst_addresses"]),
                    json.dumps(r["services"]), json.dumps(r["applications"]),
                    r.get("logging", ""), r.get("rule_usage", ""),
                    r["risk_score"], r["finding_count"], int(r.get("analyzed", True)),
                    json.dumps(r.get("raw") or {}),
                )
                for r in rules
            ],
        )


#: Sort keys the API will accept, mapped to real columns. Anything not in this
#: map is rejected, so the value never reaches the SQL string.
FINDING_SORTS = {
    "score": "score", "risk": "risk_level", "rule": "rule_name", "type": "issue_type",
}
#: Findings per rule, counted from the findings table. The stored
#: `finding_count` is taken before the rule-base-wide checks run (staleness,
#: security profiles, deny-all), so it undercounts what the rule detail shows.
_RULE_FINDINGS = ("(SELECT COUNT(*) FROM findings f"
                  " WHERE f.analysis_id = rules.analysis_id AND f.rule_id = rules.rule_id)")

_RULE_SORTS = {
    "risk": "risk_score", "name": "name", "findings": _RULE_FINDINGS,
    "action": "action", "seq": "seq",
}


def query_findings(
    analysis_id: str,
    *,
    risk: Optional[List[str]] = None,
    issue_type: Optional[List[str]] = None,
    rule_id: Optional[str] = None,
    search: Optional[str] = None,
    sort: str = "score",
    direction: str = "desc",
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    where = ["analysis_id = ?"]
    params: List[Any] = [analysis_id]

    if risk:
        where.append(f"risk_level IN ({','.join('?' * len(risk))})")
        params.extend(risk)
    if issue_type:
        where.append(f"issue_type IN ({','.join('?' * len(issue_type))})")
        params.extend(issue_type)
    if rule_id is not None:
        where.append("rule_id = ?")
        params.append(rule_id)
    if search:
        where.append("(rule_name LIKE ? OR description LIKE ?)")
        params.extend([f"%{search}%"] * 2)

    clause = " AND ".join(where)
    total = connect().execute(
        f"SELECT COUNT(*) FROM findings WHERE {clause}", params
    ).fetchone()[0]

    column = FINDING_SORTS.get(sort, "score")
    order = "ASC" if direction == "asc" else "DESC"
    rows = connect().execute(
        f"""SELECT rule_id, rule_name, issue_type, risk_level, score, description,
                   recommendation, formula, details
            FROM findings WHERE {clause}
            ORDER BY {column} {order}, id ASC LIMIT ? OFFSET ?""",
        (*params, limit, offset),
    ).fetchall()

    items = []
    for row in rows:
        item = dict(row)
        item["details"] = _loads(item["details"]) or {}
        items.append(item)
    return {"total": total, "items": items, "limit": limit, "offset": offset}


def query_rules(
    analysis_id: str,
    *,
    action: Optional[str] = None,
    search: Optional[str] = None,
    with_findings_only: bool = False,
    sort: str = "seq",
    direction: str = "asc",
    limit: int = 50,
    offset: int = 0,
) -> Dict[str, Any]:
    where = ["analysis_id = ?"]
    params: List[Any] = [analysis_id]

    if action:
        where.append("action = ?")
        params.append(action)
    if with_findings_only:
        where.append(f"{_RULE_FINDINGS} > 0")
    if search:
        where.append("(name LIKE ? OR rule_id LIKE ? OR src_addresses LIKE ? OR dst_addresses LIKE ?)")
        params.extend([f"%{search}%"] * 4)

    clause = " AND ".join(where)
    total = connect().execute(
        f"SELECT COUNT(*) FROM rules WHERE {clause}", params
    ).fetchone()[0]

    column = _RULE_SORTS.get(sort or "seq", "seq")
    order = "DESC" if str(direction).lower() == "desc" else "ASC"
    # f-string is safe here: both halves come from a fixed allow-list, never input.
    rows = connect().execute(
        f"""SELECT seq, rule_id, name, action, disabled, src_zones, dst_zones,
                   src_addresses, dst_addresses, services, applications, logging,
                   rule_usage, risk_score, {_RULE_FINDINGS} AS finding_count
            FROM rules WHERE {clause}
            ORDER BY {column} {order}, seq ASC LIMIT ? OFFSET ?""",
        (*params, limit, offset),
    ).fetchall()

    items = []
    for row in rows:
        item = dict(row)
        for key in ("src_zones", "dst_zones", "src_addresses", "dst_addresses",
                    "services", "applications"):
            item[key] = _loads(item[key]) or []
        item["disabled"] = bool(item["disabled"])
        items.append(item)
    return {"total": total, "items": items, "limit": limit, "offset": offset}


def rule_detail(analysis_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
    row = connect().execute(
        "SELECT * FROM rules WHERE analysis_id = ? AND rule_id = ? LIMIT 1",
        (analysis_id, rule_id),
    ).fetchone()
    if not row:
        return None
    rule = dict(row)
    for key in ("src_zones", "dst_zones", "src_addresses", "dst_addresses",
                "services", "applications", "raw"):
        rule[key] = _loads(rule[key]) or ([] if key != "raw" else {})
    rule["disabled"] = bool(rule["disabled"])
    # Every finding on THIS rule, worst first. (Filtering the analysis-wide top
    # 200 instead silently dropped any finding that ranked below 200th.)
    rule["findings"] = query_findings(analysis_id, rule_id=rule_id, limit=1000)["items"]
    return rule


def finding_facets(analysis_id: str, search: Optional[str] = None) -> Dict[str, Any]:
    """Counts per risk level and issue type, for the filter chips, plus a
    per-category breakdown for the Findings board. `search` narrows only the
    breakdown (the chips always show the whole run)."""
    conn = connect()
    by_risk = {
        r["risk_level"]: r["n"]
        for r in conn.execute(
            "SELECT risk_level, COUNT(*) AS n FROM findings WHERE analysis_id = ? GROUP BY risk_level",
            (analysis_id,),
        )
    }
    by_type = {
        r["issue_type"]: r["n"]
        for r in conn.execute(
            "SELECT issue_type, COUNT(*) AS n FROM findings WHERE analysis_id = ?"
            " GROUP BY issue_type ORDER BY n DESC",
            (analysis_id,),
        )
    }

    # Rules bucketed by the analyzer's own risk thresholds. Counting "rules with
    # any finding" is close to useless here: several analyzers emit a score-1
    # finding to record that a rule is compliant, so nearly every rule has one.
    # Only rules the engine actually scored. Three bands, no "clean" bucket:
    # a rule scoring 0 after assessment belongs in Low, and a rule that was
    # never assessed must not be reported as clean at all.
    bands = conn.execute(
        """
        SELECT
          SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END)                     AS high,
          SUM(CASE WHEN risk_score >= 40 AND risk_score < 70 THEN 1 ELSE 0 END) AS medium,
          SUM(CASE WHEN risk_score <  40 THEN 1 ELSE 0 END)                     AS low,
          COUNT(*)                                                              AS total
        FROM rules WHERE analysis_id = ? AND analyzed = 1
        """,
        (analysis_id,),
    ).fetchone()

    # Everything the engine skipped, split so the reason is visible.
    skipped = conn.execute(
        """
        SELECT
          SUM(CASE WHEN disabled = 1 THEN 1 ELSE 0 END)                AS disabled,
          SUM(CASE WHEN disabled = 0 THEN 1 ELSE 0 END)                AS cleanup,
          COUNT(*)                                                     AS total
        FROM rules WHERE analysis_id = ? AND analyzed = 0
        """,
        (analysis_id,),
    ).fetchone()

    # Findings board: every category present in this run, with its severity
    # mix, distinct rules and how many rows are pass records (score <= 1).
    where, params = "analysis_id = ?", [analysis_id]
    if search:
        where += " AND (rule_name LIKE ? OR description LIKE ?)"
        params += [f"%{search}%"] * 2
    categories: Dict[str, Dict[str, Any]] = {}
    for r in conn.execute(
        f"""SELECT issue_type, risk_level, COUNT(*) AS n,
                   SUM(CASE WHEN score <= 1 THEN 1 ELSE 0 END) AS passes
            FROM findings WHERE {where} GROUP BY issue_type, risk_level""", params,
    ):
        cat = categories.setdefault(r["issue_type"], {
            "type": r["issue_type"], "total": 0, "pass_records": 0, "by_risk": {}, "rules": 0})
        cat["total"] += r["n"]
        cat["pass_records"] += r["passes"] or 0
        cat["by_risk"][r["risk_level"]] = r["n"]
    for r in conn.execute(
        f"""SELECT issue_type, COUNT(DISTINCT rule_id) AS rules
            FROM findings WHERE {where} GROUP BY issue_type""", params,
    ):
        categories[r["issue_type"]]["rules"] = r["rules"]

    return {
        "by_risk": by_risk,
        "by_type": by_type,
        "categories": sorted(categories.values(), key=lambda c: -c["total"]),
        "rule_bands": {
            **{k: (bands[k] or 0) for k in ("high", "medium", "low", "total")},
            "not_assessed": skipped["total"] or 0,
            "not_assessed_disabled": skipped["disabled"] or 0,
            "not_assessed_cleanup": skipped["cleanup"] or 0,
        },
    }


# ------------------------------------------------------------------- users


def count_users() -> int:
    return connect().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(*, user_id: str, username: str, display_name: str,
                role: str, password_hash: str) -> None:
    with tx() as conn:
        conn.execute(
            """INSERT INTO users (id, username, display_name, role, password_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user_id, username, display_name, role, password_hash, now()),
        )


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    row = connect().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    return dict(row) if row else None


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    row = connect().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def touch_login(user_id: str) -> None:
    with tx() as conn:
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now(), user_id))


def list_users() -> List[Dict[str, Any]]:
    rows = connect().execute(
        "SELECT id, username, display_name, role, created_at, last_login"
        " FROM users ORDER BY username"
    ).fetchall()
    return [dict(r) for r in rows]


def set_password(user_id: str, password_hash: str) -> None:
    with tx() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id)
        )


# ------------------------------------------------------------------- roles


def list_roles() -> List[Dict[str, Any]]:
    rows = connect().execute("SELECT * FROM roles ORDER BY is_builtin DESC, name").fetchall()
    return [_role_row(r) for r in rows]


def get_role(name: str) -> Optional[Dict[str, Any]]:
    row = connect().execute("SELECT * FROM roles WHERE name = ?", (name,)).fetchone()
    return _role_row(row) if row else None


def _role_row(row) -> Dict[str, Any]:
    role = dict(row)
    role["sections"] = json.loads(role["sections"])
    role["may_switch_view"] = bool(role["may_switch_view"])
    role["may_write"] = bool(role["may_write"])
    role["is_builtin"] = bool(role["is_builtin"])
    return role


def upsert_role(*, name: str, label: str, sections: List[str], view: str,
                may_switch_view: bool, may_write: bool, description: str = "",
                is_builtin: bool = False) -> None:
    with tx() as conn:
        conn.execute(
            """INSERT INTO roles (name, label, sections, view, may_switch_view,
                                  may_write, is_builtin, description, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                   label = excluded.label,
                   sections = excluded.sections,
                   view = excluded.view,
                   may_switch_view = excluded.may_switch_view,
                   may_write = excluded.may_write,
                   description = excluded.description""",
            (name, label, json.dumps(sections), view, int(may_switch_view),
             int(may_write), int(is_builtin), description, now()),
        )


def delete_role(name: str) -> bool:
    with tx() as conn:
        cur = conn.execute("DELETE FROM roles WHERE name = ? AND is_builtin = 0", (name,))
    return cur.rowcount > 0


def count_users_with_role(name: str) -> int:
    return connect().execute(
        "SELECT COUNT(*) FROM users WHERE role = ?", (name,)
    ).fetchone()[0]


def set_user_role(user_id: str, role: str) -> None:
    with tx() as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))


def delete_user(user_id: str) -> bool:
    with tx() as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return cur.rowcount > 0


# ------------------------------------------------------------------- audit


def record_audit(*, action: str, actor: Optional[Dict[str, Any]] = None,
                 target: str = "", detail: str = "", outcome: str = "ok",
                 ip: str = "", user_agent: str = "") -> None:
    """Append one entry. Never raises - an audit failure must not break the
    request it is describing, but it is logged so it is not silent."""
    try:
        with tx() as conn:
            conn.execute(
                """INSERT INTO audit (ts, actor_id, actor_name, actor_role, action,
                                      target, detail, outcome, ip, user_agent)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (now(),
                 (actor or {}).get("id"), (actor or {}).get("username"),
                 (actor or {}).get("role"), action, target, detail, outcome,
                 ip, user_agent[:300]),
            )
    except Exception:  # pragma: no cover
        import logging
        logging.getLogger(__name__).warning("audit write failed for %s", action, exc_info=True)


def query_audit(*, limit: int = 100, offset: int = 0, action: Optional[str] = None,
                actor: Optional[str] = None, outcome: Optional[str] = None,
                search: Optional[str] = None) -> Dict[str, Any]:
    where, params = ["1=1"], []
    if action:
        where.append("action = ?"); params.append(action)
    if actor:
        where.append("actor_name = ?"); params.append(actor)
    if outcome:
        where.append("outcome = ?"); params.append(outcome)
    if search:
        where.append("(target LIKE ? OR detail LIKE ? OR actor_name LIKE ?)")
        params.extend([f"%{search}%"] * 3)

    clause = " AND ".join(where)
    total = connect().execute(f"SELECT COUNT(*) FROM audit WHERE {clause}", params).fetchone()[0]
    rows = connect().execute(
        f"SELECT * FROM audit WHERE {clause} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
        (*params, limit, offset),
    ).fetchall()
    return {"total": total, "items": [dict(r) for r in rows], "limit": limit, "offset": offset}


def audit_actions() -> List[str]:
    return [r[0] for r in connect().execute(
        "SELECT DISTINCT action FROM audit ORDER BY action").fetchall()]
