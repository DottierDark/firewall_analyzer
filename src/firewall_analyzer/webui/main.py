"""Firewall Analyzer API service entry point.

Serves the JSON API under /api and, when the static bundle is present, the
frontend itself - so `uvicorn app.main:app` is the whole application in
development. In the container split, nginx serves the frontend and proxies
/api here.
"""

import json
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import auth, config, dashboard, jobs, runner, store
from .routers import admin, analyses, auth as auth_router, meta

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("firewall_analyzer.api")

STATIC_DIR = config.STATIC_DIR


@asynccontextmanager
async def lifespan(_app: FastAPI):
    config.ensure_dirs()
    store.init_db()
    logger.info("database ready at %s", config.DB_PATH)
    # Analyses stored under the retired Critical/Poor/Fair/Good label are
    # re-rated once from their own findings. Never blocks startup.
    try:
        dashboard.backfill_posture()
    except Exception:
        logger.warning("could not re-rate earlier analyses", exc_info=True)

    # First run only: create one account per role and surface the generated
    # passwords once, since there is no sign-up flow to fall back on.
    auth.seed_roles()
    created = auth.seed_users()
    if created:
        app.state.seeded_accounts = created
        logger.info("seeded %d role accounts", len(created))
    try:
        runner.warm_up()
    except Exception:
        # A missing Applipedia file must not stop the service; analyses still
        # run, they just lose application risk enrichment.
        logger.warning("Applipedia database unavailable at %s", config.APPID_DB)
    yield
    jobs.shutdown()


app = FastAPI(
    title="Firewall Analyzer API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.include_router(auth_router.router, prefix="/api")
app.include_router(analyses.router, prefix="/api")
app.include_router(meta.router, prefix="/api")
app.include_router(admin.router, prefix="/api")


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error_code": "INTERNAL"},
    )


# ----------------------------------------------------------------- frontend

@app.middleware("http")
async def revalidate_frontend(request: Request, call_next):
    """Make browsers check the frontend for changes on every load.

    With no Cache-Control header a browser caches JS/CSS heuristically - for
    up to a tenth of the file's age - so after an update the page can run a
    mix of new and stale modules until a hard refresh. `no-cache` still lets
    it keep the file; it just revalidates first, and an unchanged file costs
    a 304 with no body.
    """
    response = await call_next(request)
    if request.url.path.startswith(("/js/", "/css/", "/app")):
        response.headers["Cache-Control"] = "no-cache"
    return response


if STATIC_DIR.is_dir():
    app.mount("/css", StaticFiles(directory=STATIC_DIR / "css"), name="css")
    app.mount("/js", StaticFiles(directory=STATIC_DIR / "js"), name="js")
    app.mount("/img", StaticFiles(directory=STATIC_DIR / "img"), name="img")

    @app.get("/", include_in_schema=False)
    def index():
        """Marketing landing page; the app itself lives at /app."""
        landing = STATIC_DIR / "index.html"
        return FileResponse(landing if landing.exists() else STATIC_DIR / "app.html")

    @app.get("/app", include_in_schema=False)
    @app.get("/app.html", include_in_schema=False)
    def app_shell():
        """The signed-in application. Serves the login gate when there is no
        session; app.js decides which of the two views to show."""
        return HTMLResponse(_versioned_shell(), headers={"Cache-Control": "no-cache"})

    def _versioned_shell() -> str:
        """app.html with every script and stylesheet URL tagged by its mtime.

        The frontend is ES modules importing each other by relative path, so a
        browser holding a stale copy of one (say nav.js, cached before the
        revalidation header existed) keeps running it after an update. An
        import map rewrites each module's URL to include its version; a changed
        file therefore has a new URL the browser has never cached, and an
        unchanged one keeps its URL and its cache. No build step involved.
        """
        html = (STATIC_DIR / "app.html").read_text(encoding="utf-8")

        def tagged(rel: str) -> str:
            path = STATIC_DIR / rel.lstrip("/")
            return f"{rel}?v={int(path.stat().st_mtime)}" if path.exists() else rel

        js_root = STATIC_DIR / "js"
        imports = {}
        for path in sorted(js_root.rglob("*.js")):
            rel = "/js/" + path.relative_to(js_root).as_posix()
            imports[rel] = tagged(rel)

        importmap = ('<script type="importmap">'
                     + json.dumps({"imports": imports}).replace("</", "<\\/")
                     + "</script>\n  ")
        html = html.replace('<script type="module" src="/js/app.js"></script>',
                            importmap + f'<script type="module" src="{imports.get("/js/app.js", "/js/app.js")}"></script>')
        for css in ("/css/app.css", "/css/report.css"):
            html = html.replace(f'href="{css}"', f'href="{tagged(css)}"')
        return html

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        icon = STATIC_DIR / "img" / "favicon.svg"
        if icon.exists():
            return FileResponse(icon, media_type="image/svg+xml")
        return JSONResponse(status_code=404, content={"detail": "no favicon"})
