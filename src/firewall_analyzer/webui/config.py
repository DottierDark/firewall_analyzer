"""Runtime settings for the Firewall Analyzer web UI.

Every path is environment-overridable, and every default works from an
installed copy as well as a source checkout - the UI is meant to be started
with one command on a locked-down machine, not configured first.
"""

import os
from pathlib import Path

#: The installed package directory (…/firewall_analyzer/webui).
PACKAGE_DIR = Path(__file__).resolve().parent

#: The repo root when running from a source checkout; None once installed.
_repo_root = PACKAGE_DIR.parents[2]
REPO_ROOT = _repo_root if (_repo_root / "pyproject.toml").exists() else None

STATIC_DIR = PACKAGE_DIR / "static"


def _env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, default)).expanduser().resolve()


def _default_data_dir() -> Path:
    """Uploads, reports and the database.

    A source checkout keeps them in `var/` beside the code, which is gitignored.
    An installed copy uses a per-user directory so nothing is written next to
    site-packages - that is usually read-only on a managed device.
    """
    if REPO_ROOT:
        return REPO_ROOT / "var"
    return Path.home() / ".firewall-analyzer"


DATA_DIR = _env_path("FWA_DATA_DIR", _default_data_dir())
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = _env_path("FWA_DB_PATH", DATA_DIR / "firewall_analyzer.db")


def _find_appid_db() -> Path:
    """Locate the Applipedia database.

    It is ~6 MB, so it is not shipped inside the wheel. Known locations are
    tried in turn; the last is returned when none exist, and the handler then
    emits its usual "not found" warning - analyses still run, they just lose
    application-risk enrichment.
    """
    candidates = [
        Path.cwd() / "data" / "palo_alto_applipedia.json",
        Path.cwd() / "palo_alto_applipedia.json",
        DATA_DIR / "palo_alto_applipedia.json",
    ]
    if REPO_ROOT:
        candidates.insert(0, REPO_ROOT / "data" / "palo_alto_applipedia.json")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]


APPID_DB = (
    Path(os.environ["FWA_APPID_DB"]).expanduser().resolve()
    if os.environ.get("FWA_APPID_DB")
    else _find_appid_db()
)

#: The full scoring config shipped inside the package. Deliberately NOT the
#: repo-root analysis_config.json, which disables application risk scoring and
#: would silently drop findings from every run.
ANALYSIS_CONFIG = _env_path(
    "FWA_ANALYSIS_CONFIG", PACKAGE_DIR.parent / "config" / "analysis_config.json"
)

#: Uploads larger than this are rejected before anything is written to disk.
MAX_UPLOAD_BYTES = int(os.environ.get("FWA_MAX_UPLOAD_BYTES", 64 * 1024 * 1024))

#: Analysis is CPU-bound and single-threaded; a small pool keeps the API
#: responsive without starving it.
MAX_WORKERS = int(os.environ.get("FWA_MAX_WORKERS", 2))


def ensure_dirs() -> None:
    for directory in (DATA_DIR, UPLOAD_DIR, REPORT_DIR):
        directory.mkdir(parents=True, exist_ok=True)
