"""LLM routing configuration API: per-task model selection + custom models."""
from __future__ import annotations
import logging
import time
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select
from ..auth.middleware import require_role
from ..auth.models import User, Role
from ..audit import record as audit_record, AuditKind
from ..db import get_session
from ..llm import registry, router as llm_router, Message
from ..llm.budget_tracker import snapshot
from ..llm.credential_store import encrypt
from ..llm.models import CustomModel

router = APIRouter(prefix="/api/llm", tags=["llm"])
log = logging.getLogger(__name__)


class RoutesIn(BaseModel):
    routes: dict[str, str]  # task_kind -> model_name


class CustomModelIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    display: str = Field(..., min_length=1, max_length=128)
    base_url: str = Field(..., min_length=1, max_length=512)
    api_key: str = Field("", max_length=2048)
    context_window: int = 32_768
    capabilities: list[str] = Field(default_factory=lambda: ["coding"])
    provider: str = Field("openai_compat", max_length=64,
                           pattern="^(openai_compat|anthropic_proxy)$")


class CustomModelOut(BaseModel):
    id: int
    name: str
    display: str
    provider: str
    base_url: str
    context_window: int
    capabilities: list[str]


class TestConnectionIn(BaseModel):
    model_config = {"protected_namespaces": ()}  # allow `model_name`

    model_name: str | None = None
    # If provided, test an unsaved config inline (useful before saving)
    base_url: str | None = None
    api_key: str | None = None
    test_model_id: str | None = None  # the model id to actually call
    # Which protocol to speak when testing an inline config
    provider: str = Field("openai_compat",
                           pattern="^(openai_compat|anthropic_proxy)$")


class TestConnectionOut(BaseModel):
    ok: bool
    latency_ms: int
    reply_excerpt: str
    error: str | None = None


@router.get("/models")
def list_models(_admin: User = Depends(require_role(Role.admin))):
    return {"models": [{
        "name": s.name,
        "display": s.display,
        "provider": s.provider,
        "context_window": s.context_window,
        "capabilities": sorted(s.capabilities),
    } for s in registry.all_specs()]}


@router.get("/routes")
def get_routes(_admin: User = Depends(require_role(Role.admin))):
    return {"routes": llm_router.get_primary_routes()}


@router.put("/routes")
def set_routes(data: RoutesIn,
               admin: User = Depends(require_role(Role.admin)),
               session: Session = Depends(get_session)):
    for kind, model in data.routes.items():
        llm_router.set_route(kind, llm_router.compose_chain_for_primary(kind, model))
        llm_router.save_route_to_db(kind, model, user_id=admin.id)
    audit_record(AuditKind.route_update,
                 actor_id=admin.id, actor_username=admin.username,
                 detail={"routes": data.routes}, session=session)
    return {"ok": True, "routes": data.routes}


@router.get("/usage")
def get_usage(_admin: User = Depends(require_role(Role.admin))):
    return {k: {"input_tokens": v.input_tokens,
                "output_tokens": v.output_tokens,
                "calls": v.calls}
            for k, v in snapshot().items()}


@router.post("/custom", response_model=CustomModelOut)
def add_custom_model(data: CustomModelIn,
                     admin: User = Depends(require_role(Role.admin)),
                     session: Session = Depends(get_session)):
    """Register a user-defined model (vLLM/Ollama/internal gateway)."""
    if session.exec(select(CustomModel).where(CustomModel.name == data.name)).first():
        raise HTTPException(status_code=409, detail="model name already exists")
    cm = CustomModel(
        name=data.name,
        display=data.display,
        provider=data.provider,
        base_url=data.base_url,
        api_key_encrypted=encrypt(data.api_key),
        context_window=data.context_window,
        capabilities=",".join(data.capabilities),
        created_by=admin.id,
    )
    session.add(cm)
    session.commit()
    session.refresh(cm)
    # Immediately register in the live registry so it's usable without restart
    registry.load_user_models(session)
    audit_record(AuditKind.model_register,
                 actor_id=admin.id, actor_username=admin.username,
                 object_kind="custom_model", object_id=str(cm.id),
                 detail={"name": cm.name, "provider": cm.provider,
                         "base_url": cm.base_url},
                 session=session)
    return CustomModelOut(id=cm.id, name=cm.name, display=cm.display,
                          provider=cm.provider, base_url=cm.base_url,
                          context_window=cm.context_window,
                          capabilities=data.capabilities)


@router.get("/custom")
def list_custom_models(_admin: User = Depends(require_role(Role.admin)),
                       session: Session = Depends(get_session)):
    rows = session.exec(select(CustomModel).where(CustomModel.is_active == True)).all()
    return [{
        "id": cm.id,
        "name": cm.name,
        "display": cm.display,
        "provider": cm.provider,
        "base_url": cm.base_url,
        "context_window": cm.context_window,
        "capabilities": cm.capabilities.split(","),
    } for cm in rows]


@router.delete("/custom/{model_id}")
def delete_custom_model(model_id: int,
                        _admin: User = Depends(require_role(Role.admin)),
                        session: Session = Depends(get_session)):
    cm = session.get(CustomModel, model_id)
    if not cm:
        raise HTTPException(status_code=404, detail="not found")
    cm.is_active = False
    session.add(cm)
    session.commit()
    return {"ok": True}


@router.post("/test-connection", response_model=TestConnectionOut)
def test_connection(data: TestConnectionIn,
                    _admin: User = Depends(require_role(Role.admin))):
    """Round-trip a tiny prompt to confirm a model is reachable.

    Two modes:
      1. **By name**: pass `model_name` matching a registered ModelSpec.
      2. **Inline**: pass `base_url` + `api_key` + `test_model_id` + `provider`
         to test an unsaved configuration before persisting it. `provider`
         selects the protocol (openai_compat vs anthropic_proxy).
    """
    start = time.monotonic()
    try:
        if data.base_url:
            if data.provider == "anthropic_proxy":
                from ..llm.adapters.anthropic import make_client
                client = make_client(
                    model=data.test_model_id or "claude-3-5-sonnet-20241022",
                    base_url=data.base_url,
                    api_key=data.api_key,
                )
            else:
                from ..llm.adapters.openai_compat import make_client
                client = make_client(
                    model=data.test_model_id or "gpt-3.5-turbo",
                    base_url=data.base_url,
                    api_key=data.api_key,
                )
        elif data.model_name:
            client = llm_router._get_client(data.model_name)
        else:
            raise HTTPException(status_code=400,
                                detail="model_name or base_url required")

        result = client.chat(
            [Message(role="user", content="Reply with the single word 'ok'.")],
            max_tokens=8, temperature=0.0,
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        excerpt = result.text.strip()[:200] or "(empty)"
        return TestConnectionOut(ok=True, latency_ms=latency_ms,
                                  reply_excerpt=excerpt)
    except Exception as e:  # noqa: BLE001
        latency_ms = int((time.monotonic() - start) * 1000)
        log.warning("test-connection failed: %s", e)
        return TestConnectionOut(ok=False, latency_ms=latency_ms,
                                  reply_excerpt="",
                                  error=f"{type(e).__name__}: {e}")
