"""Background execution of analyses.

Analysis is CPU-bound and takes seconds to minutes, so it must not run inside
the request. A small thread pool owns the work; the API polls the row for
status. That keeps the deployment to one process - no broker, no worker service
- which suits a tool a team runs against its own exports.
"""

import logging
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Optional

from . import config, store
from .runner import run_analysis

logger = logging.getLogger(__name__)

_pool = ThreadPoolExecutor(max_workers=config.MAX_WORKERS, thread_name_prefix="analysis")


def submit(analysis_id: str, source_path: Path, vendor: Optional[str],
           frameworks: Optional[List[str]] = None) -> None:
    _pool.submit(_execute, analysis_id, source_path, vendor, frameworks)


def shutdown() -> None:
    _pool.shutdown(wait=False, cancel_futures=True)


def _execute(analysis_id: str, source_path: Path, vendor: Optional[str],
             frameworks: Optional[List[str]] = None) -> None:
    report_path = config.REPORT_DIR / f"{analysis_id}.html"

    def progress(step: str) -> None:
        store.update_analysis(analysis_id, progress=step)

    store.update_analysis(
        analysis_id, status="running", started_at=store.now(), progress="Starting"
    )
    try:
        meta, findings, rules = run_analysis(
            source_path, vendor=vendor, report_path=report_path,
            progress=progress, frameworks=frameworks,
        )
        store.insert_findings(analysis_id, findings)
        store.insert_rules(analysis_id, rules)
        store.update_analysis(
            analysis_id,
            status="succeeded",
            progress=None,
            finished_at=store.now(),
            vendor=meta["vendor"],
            summary=_json(meta["summary"]),
            stats=_json(meta["stats"]),
            zone_summary=_json(meta["zone_summary"]),
            compliance=_json(meta.get("compliance") or {}),
            report_path=str(report_path),
        )
        logger.info("analysis %s succeeded (%d findings)", analysis_id, len(findings))
    except Exception as exc:
        logger.exception("analysis %s failed", analysis_id)
        store.update_analysis(
            analysis_id,
            status="failed",
            progress=None,
            finished_at=store.now(),
            error=f"{type(exc).__name__}: {exc}"[:2000],
        )
        logger.debug("%s", traceback.format_exc())


def _json(value: object) -> str:
    import json

    return json.dumps(value)
