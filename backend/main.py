import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session

from .db import engine, init_db
from .auth import router as auth_router
from .auth.service import bootstrap_admin_if_needed
from .targets.routes import router as targets_router
from .api.chat import router as chat_router
from .api.knowledge import router as knowledge_router
from .api.cwe import router as cwe_router
from .api.llm import router as llm_router
from .api.audit import router as audit_router
from .api.tools_zap import router as tools_zap_router
from .api.reports import router as reports_router
from .api.tools_scan import router as tools_scan_router
from .uploads.routes import router as uploads_router

log = logging.getLogger("pentest-agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with Session(engine) as session:
        created = bootstrap_admin_if_needed(session)
    if created:
        username, password = created
        banner = (
            "\n" + "=" * 70 +
            f"\n  Initial admin account created."
            f"\n  username: {username}"
            f"\n  password: {password}"
            "\n  You will be forced to change this password on first login."
            "\n" + "=" * 70 + "\n"
        )
        print(banner, file=sys.stderr, flush=True)
        log.info("initial admin account created; credentials printed to stderr")
    _bootstrap_engines()
    _bootstrap_knowledge_base()
    _bootstrap_cwe()
    try:
        from .llm import registry as _llm_registry
        with Session(engine) as session:
            _llm_registry.load_user_models(session)
    except Exception as e:  # noqa: BLE001
        log.warning("custom model load skipped: %s", e)
    try:
        from .llm import router as _llm_router
        _llm_router.load_routes_from_db()
    except Exception as e:  # noqa: BLE001
        log.warning("route load skipped: %s", e)
    yield


def _bootstrap_engines() -> None:
    """Register built-in engines AND external tools with the plugin host."""
    from .plugins import register_engine
    from . import plugins as plugin_host_module
    try:
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "sdk" / "python"))
        from engines.whitebox.svf_wrapper import SVFWrapper
        from engines.blackbox import StateAFLEngine
        from engines.network import NetworkAttackEngine
        for cls in (SVFWrapper, StateAFLEngine, NetworkAttackEngine):
            inst = cls()
            try:
                inst.setup({})
            except Exception as e:  # noqa: BLE001
                log.warning("engine %s setup skipped: %s", inst.name, e)
            register_engine(inst)
    except Exception as e:  # noqa: BLE001
        log.warning("built-in engine registration failed: %s", e)

    # External pentest tools (Nmap / Burp / ZAP / Metasploit)
    try:
        from .tools.bootstrap import bootstrap_external_tools
        bootstrap_external_tools(plugin_host_module)
    except Exception as e:  # noqa: BLE001
        log.warning("external tool registration failed: %s", e)


def _bootstrap_knowledge_base() -> None:
    """Ingest references.md on startup if present and not yet indexed."""
    from pathlib import Path
    import os as _os
    import sys as _sys
    try:
        _sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from knowledge_base.ingestion import ingest_references, all_entries
        from knowledge_base import retriever
        kb_file = _os.environ.get("PA_REFERENCES_MD") or str(
            Path(__file__).resolve().parents[1].parent / "references.md"
        )
        p = Path(kb_file)
        if p.exists() and not all_entries():
            count = ingest_references(p)
            retriever.index_all(all_entries())
            log.info("ingested %d knowledge base entries from %s", count, p)
    except Exception as e:  # noqa: BLE001
        log.warning("knowledge base bootstrap skipped: %s", e)


def _bootstrap_cwe() -> None:
    """Parse data/cwe/cwec_latest.xml on startup and build the CWE index.

    Idempotent: skips XML parse when cwe_entries already populated and
    PA_CWE_FORCE_REINGEST != "1". Always rebuilds the in-memory BM25 index.
    Failures are logged at WARNING level and never block startup.
    """
    from pathlib import Path
    import os as _os
    import sys as _sys
    try:
        _sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from knowledge_base.cwe.parser import parse_cwec_xml
        from knowledge_base.cwe.storage import store as cwe_store
        from knowledge_base.cwe import retriever as cwe_retriever
        force = _os.environ.get("PA_CWE_FORCE_REINGEST") == "1"
        xml_path = Path(_os.environ.get("PA_CWE_XML")
                        or Path(__file__).resolve().parents[1] / "data" / "cwe" / "cwec_latest.xml")
        if cwe_store.count() == 0 or force:
            if not xml_path.exists():
                log.warning("CWE XML not found at %s, skipping bootstrap", xml_path)
                return
            entries = parse_cwec_xml(xml_path)
            cwe_store.bulk_insert(entries, force=force)
            log.info("ingested %d CWE entries from %s", len(entries), xml_path)
        cwe_retriever.index_all(cwe_store.all())
        log.info("CWE retriever indexed %d entries", cwe_store.count())
    except Exception as e:  # noqa: BLE001
        log.warning("CWE bootstrap skipped: %s", e)


app = FastAPI(title="Pentest Agent", version="0.1.0", lifespan=lifespan)

# In dev the frontend runs on a different port
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("PA_CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(targets_router)
app.include_router(chat_router)
app.include_router(knowledge_router)
app.include_router(cwe_router)
app.include_router(llm_router)
app.include_router(audit_router)
app.include_router(uploads_router)
app.include_router(tools_zap_router)
app.include_router(reports_router)
app.include_router(tools_scan_router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


# Serve the built frontend (Vite output) so the whole product runs on one
# port. Optional: only mount when the dist directory exists; in dev mode the
# frontend is served by `npm run dev` on a separate port via Vite's proxy.
_FRONTEND_DIST = Path(__file__).resolve().parents[1] / "frontend" / "dist"
if _FRONTEND_DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_FRONTEND_DIST / "assets"),
               name="frontend_assets")

    @app.get("/")
    def _serve_index():
        return FileResponse(_FRONTEND_DIST / "index.html")

    @app.get("/{full_path:path}")
    def _spa_fallback(full_path: str):
        # API/auth/targets/healthz already match earlier routes; this catches
        # all other client-side routes (e.g. /login) and returns the SPA shell.
        candidate = _FRONTEND_DIST / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_FRONTEND_DIST / "index.html")
    log.info("serving frontend from %s", _FRONTEND_DIST)
else:
    log.info("no frontend dist found at %s; running API-only", _FRONTEND_DIST)
