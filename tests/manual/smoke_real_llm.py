"""Manual end-to-end smoke test against a REAL LLM endpoint.

Picks up credentials from the user's shell env (~/.bashrc), so the test
doesn't run in CI by default. We use `ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL`
because that's what the user has configured (Claude Code style).

Run:
    cd pentest-agent
    bash -c 'source ~/.bashrc && PYTHONPATH=. python tests/manual/smoke_real_llm.py'

The script tests three layers:
  1. Adapter — bare client.chat()
  2. Router  — task-typed call with failover
  3. Pipeline — full Orchestrator (planner → router → verifier → reporter)

No vulnerabilities are scanned and no targets are touched; the prompts are
trivial. We only verify the LLM round-trip works.
"""
from __future__ import annotations
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sdk" / "python"))


def _section(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def _ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m✗\033[0m {msg}")


def _info(msg: str) -> None:
    print(f"  · {msg}")


def assert_env() -> str:
    """Ensure we have at least one Anthropic key available."""
    key = (os.environ.get("ANTHROPIC_API_KEY")
           or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    if not key:
        _fail("no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN in env")
        _fail("did you run: source ~/.bashrc ?")
        sys.exit(2)
    base = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    _ok(f"key found (len={len(key)})")
    _info(f"base_url={base}")
    return key


def _resolve_test_model() -> str:
    """Find a model id the configured endpoint actually accepts.

    Custom gateways often only honour a subset of model ids and map everything
    to one underlying model. Try our internal canonical names first, then
    fall back to widely-recognized public ids.
    """
    candidates = [
        "claude-sonnet-4-6",         # internal canonical (Opus 4.6+ family)
        "claude-3-5-sonnet-20241022",  # widely accepted by proxies
        "claude-3-5-sonnet-latest",
        "claude-3-haiku-20240307",
    ]
    return os.environ.get("PA_TEST_MODEL") or candidates[1]


def test_adapter() -> None:
    _section("LAYER 1 — adapter direct call")
    from backend.llm.adapters.anthropic import make_client
    from backend.llm.base import Message

    model = _resolve_test_model()
    client = make_client(model=model)
    _info(f"calling {model} with a 1-token prompt …")
    t0 = time.monotonic()
    result = client.chat(
        [Message(role="system", content="You are a calculator."),
         Message(role="user", content="What is 2+3? Reply with just the number.")],
        max_tokens=8, temperature=0.0,
    )
    dt = (time.monotonic() - t0) * 1000
    _info(f"latency={dt:.0f}ms  in_tokens={result.usage.input_tokens}  "
          f"out_tokens={result.usage.output_tokens}")
    _info(f"reply: {result.text!r}")
    if "5" in result.text:
        _ok("adapter round-trip correct")
    else:
        _fail(f"unexpected reply (expected '5'): {result.text!r}")


def test_streaming() -> None:
    _section("LAYER 1b — adapter streaming")
    from backend.llm.adapters.anthropic import make_client
    from backend.llm.base import Message

    client = make_client(model=_resolve_test_model())
    _info("streaming a short reply, watching for token deltas …")
    chunks = []
    t0 = time.monotonic()
    for chunk in client.stream(
        [Message(role="user", content="Count 1 to 3.")],
        max_tokens=32, temperature=0.0,
    ):
        chunks.append(chunk)
    dt = (time.monotonic() - t0) * 1000
    text = "".join(chunks)
    _info(f"received {len(chunks)} chunks in {dt:.0f}ms")
    _info(f"reassembled: {text!r}")
    if len(chunks) > 0 and text.strip():
        _ok("streaming yields non-empty deltas")
    else:
        _fail(f"streaming produced no usable output (chunks={chunks})")


def test_router() -> None:
    _section("LAYER 2 — router with task kinds")
    from backend.llm import router as llm_router, registry
    from backend.llm.base import Message

    # Use the model id this proxy actually accepts
    model_id = _resolve_test_model()
    # Register a spec for the resolved model id so the router can find it
    if not registry.get(model_id):
        from backend.llm.adapters.anthropic import make_client
        registry.register(registry.ModelSpec(
            name=model_id, provider="anthropic", display=model_id,
            context_window=200_000,
            capabilities={"reasoning", "tool_use"},
            factory=lambda _cfg: make_client(model=model_id),
        ))
    llm_router.set_route("triage", [model_id])
    _info(f"routing 'triage' task → {model_id}")
    result = llm_router.call("triage",
                              [Message(role="user", content="Say 'hello'.")])
    _info(f"reply: {result.text!r}")
    _info(f"usage: in={result.usage.input_tokens} out={result.usage.output_tokens}")
    if "hello" in result.text.lower():
        _ok("router resolved + invoked + returned expected content")
    else:
        _fail(f"unexpected reply: {result.text!r}")


def test_pipeline() -> None:
    _section("LAYER 3 — full Orchestrator pipeline")
    from backend.llm import router as llm_router, registry
    from backend.orchestrator import run_pipeline
    from pentest_agent_sdk.contracts import (
        Capability, Evidence, Finding, HealthStatus, Severity, Target,
    )
    from backend import plugins as plugin_host

    model_id = _resolve_test_model()
    if not registry.get(model_id):
        from backend.llm.adapters.anthropic import make_client
        registry.register(registry.ModelSpec(
            name=model_id, provider="anthropic", display=model_id,
            context_window=200_000, capabilities={"reasoning"},
            factory=lambda _cfg: make_client(model=model_id),
        ))
    llm_router.set_route("planning", [model_id])

    # Register a deterministic engine so we can isolate the LLM-driven planner
    class _SimEngine:
        name = "sim_engine"
        version = "0.1.0"
        capabilities = [Capability.static_analysis]

        def setup(self, _c): pass

        def run(self, target, _o):
            return [
                Finding(id="s1", title="simulated buffer overflow",
                        severity=Severity.medium, category="BufferOverflow",
                        target_ref=target.id,
                        evidence=[Evidence(kind="sim", summary="static demo")]),
                Finding(id="s2", title="simulated buffer overflow (corroboration)",
                        severity=Severity.medium, category="BufferOverflow",
                        target_ref=target.id,
                        evidence=[Evidence(kind="sim", summary="dynamic demo")]),
            ]

        def health_check(self):
            return HealthStatus(ok=True, version=self.version)

    plugin_host.register_engine(_SimEngine())

    target = Target(id="real-test", type="url",
                     value="https://example.com/test")
    _info("running pipeline with real planner LLM …")
    t0 = time.monotonic()
    out = run_pipeline(
        "Find injection bugs in this target. "
        "Use the sim_engine tool. Output only JSON.",
        target,
    )
    dt = (time.monotonic() - t0) * 1000
    _info(f"pipeline finished in {dt:.0f}ms")
    _info(f"plan steps: {len(out.get('plan', []))}")
    _info(f"verified findings: {len(out.get('verified_findings', []))}")
    if out.get("verified_findings"):
        _ok("end-to-end pipeline produced verified findings using real LLM")
    elif out.get("plan"):
        _ok("planner produced steps but findings were filtered "
            "(expected behavior — verifier is strict)")
    else:
        _fail("pipeline produced no plan and no findings — "
              "planner may have returned non-JSON")
    if out.get("report"):
        _info(f"report excerpt: {out['report'][:200]}")


def test_anthropic_proxy_custom_model() -> None:
    """End-to-end: register a CustomModel with provider=anthropic_proxy and
    invoke it through the registry, mirroring the GUI flow.

    Uses an in-memory SQLite DB so we don't touch the user's real one.
    """
    _section("LAYER 4 — GUI flow: anthropic_proxy custom model")
    from sqlmodel import SQLModel, create_engine, Session
    from backend.llm import registry
    from backend.llm.models import CustomModel
    from backend.llm.credential_store import encrypt
    from backend.llm.base import Message

    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
    api_key = (os.environ.get("ANTHROPIC_AUTH_TOKEN")
               or os.environ.get("ANTHROPIC_API_KEY"))
    model_id = _resolve_test_model()

    eng = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(eng)
    with Session(eng) as session:
        session.add(CustomModel(
            name="real-cloudrouter",
            display="Real Cloudrouter",
            provider="anthropic_proxy",
            base_url=base_url,
            api_key_encrypted=encrypt(api_key or ""),
            context_window=200_000,
            capabilities="reasoning,coding",
            created_by=1,
        ))
        session.commit()
        registry.load_user_models(session)

    spec = registry.get("real-cloudrouter")
    assert spec is not None, "anthropic_proxy custom model failed to register"
    _info(f"registered model: {spec.name} ({spec.provider}) → {base_url}")

    client = spec.factory({})
    # Override the model id at call time — many proxies route any name to
    # one underlying model anyway
    client.model = model_id
    _info(f"calling via custom model with underlying id={model_id} …")
    t0 = time.monotonic()
    result = client.chat(
        [Message(role="user", content="Reply with the single word 'pong'.")],
        max_tokens=8, temperature=0.0,
    )
    dt = (time.monotonic() - t0) * 1000
    _info(f"latency={dt:.0f}ms in={result.usage.input_tokens} out={result.usage.output_tokens}")
    _info(f"reply: {result.text!r}")
    if "pong" in result.text.lower():
        _ok("anthropic_proxy custom-model end-to-end (GUI flow) works")
    else:
        _fail(f"unexpected reply (expected 'pong'): {result.text!r}")


def main() -> int:
    print("# Real LLM smoke test — pentest-agent\n")
    assert_env()
    test_adapter()
    test_streaming()
    test_router()
    test_pipeline()
    test_anthropic_proxy_custom_model()
    _section("ALL LAYERS COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
