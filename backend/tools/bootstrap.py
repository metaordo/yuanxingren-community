"""Bootstrap external pentest tools into the plugin host as ToolPlugins.

Wraps each ExternalPentestTool adapter with the SDK's ToolPlugin protocol so
the orchestrator can invoke them by name. Each invocation:

  1. Resolves the target by ID from the DB
  2. Enforces the user's declared authorization scope (allow_hosts / allow_cidrs)
  3. Applies the per-tool rate limiter
  4. Records an audit event before and after
  5. Returns the raw tool output (normalization to Finding[] is the engine's job)

External tools that aren't installed or whose credentials aren't configured
fail health_check() — they're registered but invocation surfaces a clear error
rather than crashing the orchestrator.
"""
from __future__ import annotations
import logging
import os
from typing import Callable
from pentest_agent_sdk.contracts import HealthStatus

from .external_pentest.adapters.nmap import NmapAdapter
from .external_pentest.adapters.burp import BurpAdapter
from .external_pentest.adapters.zap import ZAPAdapter
from .external_pentest.adapters.metasploit import MetasploitAdapter
from .external_pentest.policies.rate_limiter import RateLimiter
from .external_pentest.policies.target_allowlist import check as scope_check
from ..targets.parser import parse as parse_target

log = logging.getLogger(__name__)

# Global rate limiter shared across tool invocations on the same host.
# 10 req/s per host with burst of 20 keeps load reasonable on real targets.
_rate_limiter = RateLimiter(rate=10.0, burst=20)


class _ToolWrapper:
    """Wraps an ExternalPentestTool with the orchestrator-facing ToolPlugin API."""

    def __init__(self, adapter, *,
                 description: str, input_schema: dict,
                 target_resolver: Callable[[dict], object] | None = None):
        self.name = adapter.name
        self.version = "0.1.0"
        self.description = description
        self.input_schema = input_schema
        self._adapter = adapter
        self._target_resolver = target_resolver
        self._configured = False

    def configure(self, config: dict) -> None:
        try:
            self._adapter.setup(config)
            self._configured = True
        except Exception as e:  # noqa: BLE001
            log.warning("tool %s setup failed: %s (will surface on invoke)",
                         self.name, e)

    def invoke(self, args: dict) -> dict:
        target = self._resolve_target(args)
        self._enforce_scope(target, args)
        if target and getattr(target, "value", None):
            _rate_limiter.acquire(target.value)
        if not self._configured:
            # Lazy setup if config was supplied via args
            self.configure(args.get("config", {}))
        return self._adapter.run(target, args.get("options", {}))

    def health_check(self) -> HealthStatus:
        try:
            ok = self._adapter.health_check()
            return HealthStatus(ok=bool(ok), version=self.version,
                                 message="" if ok else "tool not available")
        except Exception as e:  # noqa: BLE001
            return HealthStatus(ok=False, version=self.version, message=str(e))

    # ---- helpers ----

    def _resolve_target(self, args: dict):
        """Resolve target either by id (looking up the DB) or by raw value."""
        if self._target_resolver is not None:
            return self._target_resolver(args)
        target = args.get("target")
        if isinstance(target, dict):
            return _DictTarget(**target)
        return target

    def _enforce_scope(self, target, args: dict) -> None:
        """Verify the target is within the caller's declared scope.

        Caller must pass auth_scope={'hosts': [...], 'cidrs': [...]} explicitly.
        Empty scope = deny.
        """
        if target is None or not getattr(target, "value", None):
            return
        scope = args.get("auth_scope", {})
        hosts = scope.get("hosts", [])
        cidrs = scope.get("cidrs", [])
        try:
            parsed = parse_target(target.value)
        except Exception as e:  # noqa: BLE001
            raise PermissionError(f"target value not parseable: {e}")
        scope_check(parsed, hosts, cidrs)


class _DictTarget:
    """Plain target struct when caller passes a dict instead of a Target object."""
    def __init__(self, id: str = "ad-hoc", type: str = "url",
                  value: str = "", **kwargs):
        self.id = id
        self.type = type
        self.value = value
        for k, v in kwargs.items():
            setattr(self, k, v)


def bootstrap_external_tools(plugin_host) -> None:
    """Register all external pentest tool adapters as ToolPlugins.

    Each tool is registered even if its prerequisite (binary or remote service)
    isn't available; the orchestrator finds them and health_check reveals the
    missing prerequisite at invocation time, not at startup time.
    """
    wrappers = [
        _ToolWrapper(
            NmapAdapter(),
            description="Network port scanning and service detection via nmap.",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "object"},
                    "options": {"type": "object",
                                "properties": {"ports": {"type": "string"},
                                                "service_detect": {"type": "boolean"},
                                                "os_detect": {"type": "boolean"}}},
                    "auth_scope": {"type": "object"},
                },
                "required": ["target", "auth_scope"],
            },
        ),
        _ToolWrapper(
            BurpAdapter(),
            description="Web application vulnerability scanning via Burp Suite Pro REST API.",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "object"},
                    "options": {"type": "object",
                                "properties": {"scan_type": {"type": "string"}}},
                    "auth_scope": {"type": "object"},
                    "config": {"type": "object",
                               "description": "Burp REST API base_url + api_key"},
                },
                "required": ["target", "auth_scope"],
            },
        ),
        _ToolWrapper(
            ZAPAdapter(),
            description="OWASP ZAP active web scanner (open-source Burp alternative).",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "object"},
                    "options": {"type": "object"},
                    "auth_scope": {"type": "object"},
                    "config": {"type": "object"},
                },
                "required": ["target", "auth_scope"],
            },
        ),
        _ToolWrapper(
            MetasploitAdapter(),
            description="Metasploit exploit framework (default DRY-RUN for exploit/auxiliary).",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "object"},
                    "options": {"type": "object",
                                "properties": {"operation": {"type": "string"},
                                                "module": {"type": "string"},
                                                "query": {"type": "string"},
                                                "dry_run": {"type": "boolean"}}},
                    "auth_scope": {"type": "object"},
                    "config": {"type": "object"},
                },
                "required": ["target", "auth_scope"],
            },
        ),
    ]
    for w in wrappers:
        plugin_host.register_tool(w)
        log.info("registered external tool: %s", w.name)
    _autoconfigure_from_env(wrappers)


# ---------------------------------------------------------------------------
# Environment-driven autoconfiguration
# ---------------------------------------------------------------------------

# Maps wrapper.name -> (env_base_url, env_api_key) pairs. If the env vars are
# present at startup, the wrapper is configured immediately so health_check()
# reflects real backend status without waiting for the first invoke.
_ENV_CONFIG = {
    "zap":  ("PA_ZAP_BASE_URL",  "PA_ZAP_API_KEY"),
    "burp": ("PA_BURP_BASE_URL", "PA_BURP_API_KEY"),
}


def _autoconfigure_from_env(wrappers: list[_ToolWrapper]) -> None:
    for w in wrappers:
        env_pair = _ENV_CONFIG.get(w.name)
        if not env_pair:
            continue
        base_env, key_env = env_pair
        base = os.environ.get(base_env)
        key = os.environ.get(key_env, "")
        if not base:
            continue
        try:
            w.configure({"base_url": base, "api_key": key})
            log.info("autoconfigured tool %s from %s", w.name, base_env)
        except Exception as e:  # noqa: BLE001
            log.warning("autoconfigure %s failed: %s", w.name, e)
