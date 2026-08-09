"""Plugin registry: discover, load, and isolate plugins."""
from __future__ import annotations
import importlib
import importlib.util
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_engines: dict[str, Any] = {}
_tools: dict[str, Any] = {}


def register_engine(plugin: Any) -> None:
    _engines[plugin.name] = plugin
    log.info("registered engine plugin: %s v%s", plugin.name, plugin.version)


def register_tool(plugin: Any) -> None:
    _tools[plugin.name] = plugin
    log.info("registered tool plugin: %s v%s", plugin.name, plugin.version)


def get_engine(name: str) -> Any | None:
    return _engines.get(name)


def get_tool(name: str) -> Any | None:
    return _tools.get(name)


def all_engines() -> list[Any]:
    return list(_engines.values())


def all_tools() -> list[Any]:
    return list(_tools.values())


def discover_plugins(plugins_dir: Path) -> None:
    """Scan plugins/ directory for plugin.toml manifests and load entry modules.

    Each plugin lives in its own subdirectory containing:
      - plugin.toml (manifest with name/version/entry_module)
      - the entry module (e.g. main.py) defining register(host) -> None
    """
    if not plugins_dir.exists():
        return
    for child in plugins_dir.iterdir():
        manifest = child / "plugin.toml"
        if not manifest.is_file():
            continue
        try:
            _load_plugin(child)
        except Exception as e:  # noqa: BLE001
            log.error("failed to load plugin at %s: %s", child, e)


def _load_plugin(plugin_dir: Path) -> None:
    """Load a single plugin. Manifest format:
        [plugin]
        name = "my-plugin"
        version = "0.1.0"
        entry = "main:register"
    """
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        import tomli as tomllib  # type: ignore
    manifest = (plugin_dir / "plugin.toml").read_bytes()
    data = tomllib.loads(manifest.decode("utf-8"))
    info = data.get("plugin", {})
    entry = info.get("entry", "main:register")
    module_name, _, fn_name = entry.partition(":")
    entry_path = plugin_dir / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(
        f"pentest_plugin_{plugin_dir.name}", entry_path
    )
    if not spec or not spec.loader:
        raise RuntimeError(f"could not load module spec for {entry_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    register_fn = getattr(module, fn_name or "register")
    # Host API passed to the plugin
    host = type("Host", (), {
        "register_engine": staticmethod(register_engine),
        "register_tool": staticmethod(register_tool),
    })()
    register_fn(host)
