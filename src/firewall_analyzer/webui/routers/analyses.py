"""Analysis lifecycle: upload, run, poll, read results, download artifacts."""

import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse

from firewall_analyzer.analysis import frameworks as compliance_frameworks
from firewall_analyzer.config.manager import ConfigurationManager
from firewall_analyzer.core.models import VendorType

from .. import config, dashboard, jobs, store
from ..runner import sniff_headers
from .auth import current_user, require_write

router = APIRouter(
    prefix="/analyses",
    tags=["analyses"],
    # Every analysis route needs a signed-in user; individual write routes
    # additionally depend on require_write.
    dependencies=[Depends(current_user)],
)

ALLOWED_SUFFIXES = {".csv", ".xlsx", ".xls", ".xlsm", ".txt"}
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _new_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{stamp}_{uuid.uuid4().hex[:8]}"


def _require(analysis_id: str) -> dict:
    record = store.get_analysis(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return record


@router.get("")
def list_analyses(
    limit: int = Query(50, ge=1, le=200),
    project_id: Optional[str] = None,
):
    return {"items": store.list_analyses(limit=limit, project_id=project_id)}


@router.post("", status_code=201, dependencies=[Depends(require_write)])
async def create_analysis(
    request: Request,
    file: UploadFile = File(...),
    project: str = Form("Default Project"),
    label: Optional[str] = Form(None),
    vendor: Optional[str] = Form(None),
    frameworks: Optional[List[str]] = Form(None),
    framework: Optional[str] = Form(None),
    actor: dict = Depends(require_write),
):
    """Accept a rule export and queue it for analysis.

    `frameworks` may be repeated (one form field per framework) or given once
    comma-separated. The single `framework` field is still accepted from older
    clients. Unknown keys are rejected before anything is written.
    """
    try:
        chosen = compliance_frameworks.normalize_keys((frameworks or []) + ([framework] if framework else []))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    chosen = chosen or list(compliance_frameworks.DEFAULT_FRAMEWORKS)

    original = Path(file.filename or "rules.csv").name
    suffix = Path(original).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Upload a CSV or Excel rule export.",
        )

    analysis_id = _new_id("FWA")
    safe = SAFE_NAME.sub("_", original) or "rules.csv"
    target = config.UPLOAD_DIR / f"{analysis_id}__{safe}"
    config.ensure_dirs()

    # Stream to disk with a running size check so an oversized upload cannot
    # fill the volume before it is rejected.
    written = 0
    try:
        with open(target, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds the {config.MAX_UPLOAD_BYTES // (1024*1024)} MB limit.",
                    )
                out.write(chunk)
    except HTTPException:
        target.unlink(missing_ok=True)
        raise
    finally:
        await file.close()

    if written == 0:
        target.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if vendor:
        try:
            vendor_type = VendorType(vendor)
        except ValueError:
            target.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail=f"Unknown vendor '{vendor}'")

        schema = ConfigurationManager().get_vendor_schema(vendor_type)
        required = schema.get("required_fields", [])
        if required:
            found = {_normalize_col(h) for h in sniff_headers(target)}
            missing = [f for f in required if _normalize_col(f) not in found]
            if missing:
                target.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"This file does not match the '{vendor}' column schema. "
                        f"Missing required column(s): {', '.join(missing)}."
                    ),
                )
    project_id = store.upsert_project(_new_id("PRJ"), project.strip() or "Default Project")["id"]

    store.create_analysis(
        {
            "id": analysis_id,
            "project_id": project_id,
            "label": (label or Path(original).stem)[:120],
            "vendor": vendor,
            "framework": ",".join(chosen),
            "filename": original,
            "source_path": str(target),
            "status": "queued",
            "created_at": store.now(),
        }
    )
    store.record_audit(
        action="analysis.create", actor=actor, target=analysis_id,
        detail=f"file={original} vendor={vendor or 'auto-detect'} project={project} "
               f"frameworks={','.join(chosen)}",
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
    )
    jobs.submit(analysis_id, target, vendor, chosen)
    return {"id": analysis_id, "status": "queued"}


def _normalize_col(name: str) -> str:
    """Match SchemaNormalizer's own column comparison exactly, so this preview
    check agrees with what the real parser will do on the full run."""
    return name.strip().lower().replace(" ", "_").replace("-", "_")


@router.post("/preview", dependencies=[Depends(require_write)])
async def preview_headers(
    file: UploadFile = File(...),
    vendor: Optional[str] = Form(None),
):
    """Return the column headers of an upload, and — when a vendor has already
    been chosen — whether that vendor's required columns are present.

    The vendor is picked by the user before upload (see the wizard), so this
    validates against that choice rather than guessing one from the headers.
    """
    original = Path(file.filename or "rules.csv").name
    tmp = config.UPLOAD_DIR / f"preview_{uuid.uuid4().hex[:8]}{Path(original).suffix.lower()}"
    config.ensure_dirs()
    try:
        with open(tmp, "wb") as out:
            shutil.copyfileobj(file.file, out, 1024 * 1024)
        headers = sniff_headers(tmp)
    finally:
        await file.close()
        tmp.unlink(missing_ok=True)
        tmp.with_suffix(".converted.csv").unlink(missing_ok=True)

    result = {"filename": original, "headers": headers, "column_count": len(headers)}

    if vendor:
        try:
            vendor_type = VendorType(vendor)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown vendor '{vendor}'")

        schema = ConfigurationManager().get_vendor_schema(vendor_type)
        found = {_normalize_col(h) for h in headers}
        field_check = [
            {"field": field, "found": _normalize_col(field) in found}
            for field in schema.get("required_fields", [])
        ]
        result["vendor"] = vendor
        result["field_check"] = field_check
        result["all_required_found"] = all(f["found"] for f in field_check) if field_check else True

    return result


@router.get("/{analysis_id}")
def get_analysis(analysis_id: str):
    record = _require(analysis_id)
    record.pop("source_path", None)
    return record


@router.delete("/{analysis_id}", status_code=204, dependencies=[Depends(require_write)])
def delete_analysis(analysis_id: str, request: Request,
                    actor: dict = Depends(require_write)):
    record = _require(analysis_id)
    for path in (record.get("source_path"), record.get("report_path")):
        if path:
            Path(path).unlink(missing_ok=True)
    store.delete_analysis(analysis_id)
    store.record_audit(
        action="analysis.delete", actor=actor, target=analysis_id,
        detail=f"label={record['label']}",
        ip=_client_ip(request), user_agent=request.headers.get("user-agent", ""),
    )
    return None


@router.get("/{analysis_id}/findings")
def get_findings(
    analysis_id: str,
    risk: Optional[List[str]] = Query(None),
    issue_type: Optional[List[str]] = Query(None),
    search: Optional[str] = None,
    sort: str = "score",
    direction: str = "desc",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    _require(analysis_id)
    return store.query_findings(
        analysis_id, risk=risk, issue_type=issue_type, search=search,
        sort=sort, direction=direction, limit=limit, offset=offset,
    )


@router.get("/{analysis_id}/facets")
def get_facets(analysis_id: str, search: Optional[str] = None):
    _require(analysis_id)
    return store.finding_facets(analysis_id, search=search)


@router.get("/{analysis_id}/dashboard")
def get_dashboard(analysis_id: str):
    """Everything the three Overview presets draw, in one response."""
    record = _require(analysis_id)
    return dashboard.build(analysis_id, record)


@router.get("/{analysis_id}/rules")
def get_rules(
    analysis_id: str,
    action: Optional[str] = None,
    search: Optional[str] = None,
    with_findings_only: bool = False,
    sort: str = Query("seq"),
    direction: str = Query("asc"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    _require(analysis_id)
    return store.query_rules(
        analysis_id, action=action, search=search,
        with_findings_only=with_findings_only, sort=sort,
        direction=direction, limit=limit, offset=offset,
    )


@router.get("/{analysis_id}/rules/{rule_id}")
def get_rule(analysis_id: str, rule_id: str):
    _require(analysis_id)
    rule = store.rule_detail(analysis_id, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.get("/{analysis_id}/report")
def get_report(analysis_id: str, download: bool = False):
    """The analyzer's own HTML report.

    Served INLINE by default. Passing `filename=` to FileResponse sets
    Content-Disposition: attachment, which makes the browser download the file
    instead of rendering it - that is why this page could not be previewed.
    Downloading is now opt-in via ?download=1.
    """
    record = _require(analysis_id)
    path = record.get("report_path")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=404, detail="No report for this analysis yet")

    safe = SAFE_NAME.sub("_", record["label"]) or analysis_id
    disposition = "attachment" if download else "inline"
    return FileResponse(
        path,
        media_type="text/html",
        headers={"Content-Disposition": f'{disposition}; filename="{safe}.html"'},
    )


@router.get("/{analysis_id}/export.json")
def export_json(analysis_id: str):
    record = _require(analysis_id)
    payload = {
        "analysis_id": analysis_id,
        "label": record["label"],
        "project": record["project_name"],
        "vendor": record["vendor"],
        "filename": record["filename"],
        "created_at": record["created_at"],
        "summary": record["summary"],
        "statistics": record["stats"],
        "zone_summary": record["zone_summary"],
        "findings": store.query_findings(analysis_id, limit=500)["items"],
    }
    body = json.dumps(payload, indent=2)
    return StreamingResponse(
        iter([body]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{analysis_id}.json"'},
    )


@router.get("/{analysis_id}/export.csv")
def export_csv(analysis_id: str):
    """Findings as CSV - the format that actually gets pasted into a tracker."""
    _require(analysis_id)
    import csv as csv_module
    import io

    buffer = io.StringIO()
    writer = csv_module.writer(buffer)
    writer.writerow(
        ["Rule ID", "Rule Name", "Issue Type", "Risk Level", "Score",
         "Description", "Recommendation"]
    )
    for item in store.query_findings(analysis_id, limit=500)["items"]:
        writer.writerow([
            item["rule_id"], item["rule_name"], item["issue_type"],
            item["risk_level"], item["score"], item["description"],
            item["recommendation"],
        ])
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{analysis_id}_findings.csv"'},
    )
