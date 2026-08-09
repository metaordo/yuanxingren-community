"""Supervisor: picks which worker roles to spawn for a given file_index.

Two-layer decision:
  1. LLM proposes a role list given a project summary and the user objective.
  2. Hard rules filter the LLM's output: dep-analyst requires a manifest,
     iot-firmware-auditor requires binary scope, xss/sqli/authn-tester
     require web-app signals, etc.

The hard layer is the safety net — if the LLM hallucinates a role name
or picks one whose preconditions are not met, the dispatcher silently
drops it (with a "rejected_invalid" reason recorded).

A second-round supervisor pick (after verifier) reviews the verified
findings and may spawn an extra round of workers to chase a specific
lead (e.g., crypto-analyst suggests an auth issue → spawn auth-analyst
on the relevant files). Only one extra round is allowed (`spawn_round < 2`).
"""
from __future__ import annotations
import json
import logging
import re
from pathlib import Path

from ..llm import Message
from .roles import known_role_names, role_descriptions

log = logging.getLogger(__name__)


# ---- file_index construction ---------------------------------------------

# Per-language source extensions, used by both file-index summary and
# default-scope selection when the supervisor names a role but supplies
# no explicit scope.
_C_FAMILY = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
_GENERIC_SOURCE = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".py", ".js",
                    ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".php",
                    ".rs", ".cs", ".kt", ".swift"}
_WEB_BACKEND_HINTS = (
    "express", "django", "flask", "fastapi", "spring", "laravel", "rails",
    "gin-gonic", "echo", "actix", "nestjs", "koa",
)
_WEB_TEMPLATE_EXTS = {".jsx", ".tsx", ".vue", ".html", ".ejs", ".hbs", ".jinja",
                       ".erb", ".twig", ".blade.php"}
_CONFIG_EXTS = {".env", ".yaml", ".yml", ".toml", ".json", ".ini",
                 ".conf", ".config", ".properties", ".cfg", ".xml"}
_CI_FILENAMES = {
    "jenkinsfile", ".travis.yml", ".gitlab-ci.yml", "circle.yml",
}
_ANDROID_MANIFEST = "androidmanifest.xml"


def build_file_index(root: Path) -> dict:
    """Walk the project root and produce a summary used by the supervisor.

    Returns a flat dict (JSON-serializable) describing the project shape.
    The supervisor reads this dict to decide which agents fit.
    """
    by_ext: dict[str, int] = {}
    files: list[str] = []
    total_bytes = 0
    has_makefile = False
    has_dockerfile = False
    has_requirements = False
    has_go_mod = False
    has_package_json = False
    has_cargo_toml = False
    has_pom_xml = False
    has_gradle = False
    has_crypto_header = False
    has_web_template = False
    has_binary = False
    has_protocol_code = False
    has_config_files = False
    has_ci_pipeline = False
    has_android_manifest = False
    has_kernel_code = False
    # ---- new content-level signals ----
    has_threading_code = False    # pthread/goroutine/async/mutex/std::thread
    has_heap_ops = False          # malloc/free/new/delete/realloc patterns
    has_payment_code = False      # payment/order/price/cart/checkout keywords
    has_auth_code = False         # login/token/jwt/session/password/credential
    has_api_routes = False        # REST route decorators or explicit route strings
    has_heap_struct_ops = False   # struct pointer chains that feed memory ops
    has_icmp_handler = False      # ICMP error handlers / icmp_unreach / redirect
    web_framework_hits: set[str] = set()
    package_blobs: list[str] = []

    # keywords that strongly suggest protocol parser / network code
    _PROTOCOL_KEYWORDS = (
        b"recv(", b"send(", b"parse_", b"decode_", b"encode_",
        b"ntohl", b"ntohs", b"htonl", b"htons",
        b"struct pkt", b"struct msg", b"struct frame", b"struct header",
        b"tlv", b"PDU", b"pdu", b"marshal", b"unmarshal",
        b"protobuf", b"msgpack", b"capnp",
    )

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        # Skip .git directory but allow other dotfiles (.github, .env, etc.)
        if "/.git/" in f"/{rel}" or rel == ".git":
            continue
        try:
            sz = p.stat().st_size
        except OSError:
            continue
        if sz > 2_000_000:
            continue
        ext = p.suffix.lower()
        by_ext[ext] = by_ext.get(ext, 0) + 1
        total_bytes += sz
        files.append(rel)
        name_lower = p.name.lower()

        if name_lower in ("makefile", "gnumakefile"):
            has_makefile = True
        if name_lower == "dockerfile":
            has_dockerfile = True
        if name_lower in ("requirements.txt", "setup.py", "pyproject.toml",
                           "pipfile"):
            has_requirements = True
        if name_lower == "go.mod":
            has_go_mod = True
        if name_lower == "package.json":
            has_package_json = True
        if name_lower == "cargo.toml":
            has_cargo_toml = True
        if name_lower == "pom.xml":
            has_pom_xml = True
        if name_lower in ("build.gradle", "build.gradle.kts"):
            has_gradle = True
        if name_lower in ("crypto.h", "aes.h", "evp.h", "sha.h"):
            has_crypto_header = True
        if ext in _WEB_TEMPLATE_EXTS:
            has_web_template = True

        # snapshot package files to grep for web framework names later
        if name_lower in ("package.json", "requirements.txt",
                           "go.mod", "cargo.toml", "pom.xml"):
            try:
                package_blobs.append(p.read_text(errors="replace")[:8000])
            except OSError:
                pass

        # quick magic-byte test for ELF/PE binaries
        if ext in {"", ".bin", ".elf", ".exe", ".dll", ".so"}:
            try:
                head = p.open("rb").read(4)
                if head.startswith(b"\x7fELF") or head.startswith(b"MZ"):
                    has_binary = True
            except OSError:
                pass

        # protocol code detection: scan C/C++ source files for protocol keywords
        if not has_protocol_code and ext in _C_FAMILY:
            try:
                snippet = p.open("rb").read(32768)  # first 32KB
                if any(kw in snippet for kw in _PROTOCOL_KEYWORDS):
                    has_protocol_code = True
            except OSError:
                pass
        # also treat .proto files as protocol code
        if ext == ".proto":
            has_protocol_code = True

        # config/secrets files
        if ext in _CONFIG_EXTS:
            has_config_files = True

        # CI/CD pipeline detection
        if (name_lower in _CI_FILENAMES
                or (".github/workflows" in rel and ext in (".yml", ".yaml"))):
            has_ci_pipeline = True

        # Android manifest
        if name_lower == _ANDROID_MANIFEST:
            has_android_manifest = True

        # Kernel/driver code: files importing kernel headers or named *_drv/*_dev
        if not has_kernel_code and ext in (".c", ".h"):
            try:
                snippet = p.open("rb").read(4096)
                _KERNEL_HINTS = (
                    b"#include <linux/", b"#include <asm/",
                    b"MODULE_LICENSE", b"module_init(",
                    b"copy_from_user", b"copy_to_user",
                    b"commit_creds", b"prepare_kernel_cred",
                    b"IOCTL", b"ioctl",
                )
                if any(kw in snippet for kw in _KERNEL_HINTS):
                    has_kernel_code = True
            except OSError:
                pass

        # Threading / concurrency signals (C/C++, Go, Python, Java, Rust, JS)
        if not has_threading_code and ext in _GENERIC_SOURCE | _C_FAMILY:
            try:
                snippet = p.open("rb").read(16384)
                _THREAD_HINTS = (
                    b"pthread_", b"std::thread", b"std::mutex", b"std::atomic",
                    b"goroutine", b"go func(", b"sync.Mutex", b"sync.RWMutex",
                    b"asyncio", b"async def", b"await ", b"Promise",
                    b"Thread(", b"ExecutorService", b"CompletableFuture",
                    b"Arc<Mutex", b"RwLock<", b"Mutex::new(",
                    b"setInterval", b"setTimeout", b"worker_threads",
                )
                if any(kw in snippet for kw in _THREAD_HINTS):
                    has_threading_code = True
            except OSError:
                pass

        # Heap allocation patterns (C/C++ focus, also Rust unsafe)
        if not has_heap_ops and ext in _C_FAMILY:
            try:
                snippet = p.open("rb").read(16384)
                _HEAP_HINTS = (
                    b"malloc(", b"calloc(", b"realloc(", b"free(",
                    b"new ", b"delete ", b"delete[]",
                    b"kmalloc(", b"kfree(",
                )
                if any(kw in snippet for kw in _HEAP_HINTS):
                    has_heap_ops = True
            except OSError:
                pass

        # Payment / business logic signals
        if not has_payment_code and ext in _GENERIC_SOURCE:
            try:
                snippet = p.open("rb").read(8192).lower()
                _PAYMENT_HINTS = (
                    b"payment", b"checkout", b"order", b"cart",
                    b"price", b"discount", b"coupon", b"invoice",
                    b"transaction", b"refund", b"billing", b"stripe",
                    b"paypal", b"alipay", b"wechatpay",
                )
                if any(kw in snippet for kw in _PAYMENT_HINTS):
                    has_payment_code = True
            except OSError:
                pass

        # Auth / credential signals (distinct from crypto — focuses on session/token logic)
        if not has_auth_code and ext in _GENERIC_SOURCE:
            try:
                snippet = p.open("rb").read(8192).lower()
                _AUTH_HINTS = (
                    b"login", b"logout", b"password", b"credential",
                    b"jwt", b"token", b"session", b"cookie",
                    b"oauth", b"bearer", b"authenticate", b"authorize",
                )
                if any(kw in snippet for kw in _AUTH_HINTS):
                    has_auth_code = True
            except OSError:
                pass

        # REST/GraphQL API route signals
        if not has_api_routes and ext in _GENERIC_SOURCE:
            try:
                snippet = p.open("rb").read(8192)
                _API_HINTS = (
                    b"@app.route", b"@router.", b"app.get(", b"app.post(",
                    b"app.put(", b"app.delete(", b"app.patch(",
                    b"router.get(", b"router.post(",
                    b"@GetMapping", b"@PostMapping", b"@RequestMapping",
                    b"graphql", b"GraphQL", b"schema = build_schema",
                )
                if any(kw in snippet for kw in _API_HINTS):
                    has_api_routes = True
            except OSError:
                pass





    # framework keyword detection across package files + source samples
    blob_join = "\n".join(package_blobs).lower()
    for fw in _WEB_BACKEND_HINTS:
        if fw in blob_join:
            web_framework_hits.add(fw)

    return {
        "files": files,
        "by_ext": by_ext,
        "total_bytes": total_bytes,
        "total_files": len(files),
        "has_makefile": has_makefile,
        "has_dockerfile": has_dockerfile,
        "has_requirements": has_requirements,
        "has_go_mod": has_go_mod,
        "has_package_json": has_package_json,
        "has_cargo_toml": has_cargo_toml,
        "has_pom_xml": has_pom_xml,
        "has_gradle": has_gradle,
        "has_crypto_header": has_crypto_header,
        "has_web_template": has_web_template,
        "has_binary": has_binary,
        "has_protocol_code": has_protocol_code,
        "has_config_files": has_config_files,
        "has_ci_pipeline": has_ci_pipeline,
        "has_android_manifest": has_android_manifest,
        "has_kernel_code": has_kernel_code,
        "has_threading_code": has_threading_code,
        "has_heap_ops": has_heap_ops,
        "has_payment_code": has_payment_code,
        "has_auth_code": has_auth_code,
        "has_api_routes": has_api_routes,
        "has_icmp_handler": has_icmp_handler,
        "web_framework_hits": sorted(web_framework_hits),
    }


# ---- LLM supervisor (round 0) --------------------------------------------

_SUPERVISOR_SYSTEM = """\
You are the **Supervisor** of a multi-agent code audit. You pick which
specialist agents to spawn given a project summary and the user's goal.

Available roles (use these EXACT names):
{role_table}

Decide rules:
- Pick **at least 5 agents**. Cover the project broadly.
- **code-auditor is MANDATORY** whenever source files exist — always include it.
- **dataflow-analyst is MANDATORY** when C/C++ files exist (.c/.cpp/.h) — always include it.
- **protocol-analyst is MANDATORY** when has_protocol_code=true or .proto files exist — always include it.
- dep-analyst requires a manifest file (requirements.txt, go.mod, package.json, etc).
- iot-firmware-auditor requires has_binary=true.
- web-recon/xss-analyst/sqli-analyst/authn-tester require web_framework_hits
  or has_web_template, OR clear evidence of web routing code in user prompt.
- crypto-analyst: pick when has_crypto_header=true, OR web framework present, OR C/C++ files exist.
- state-machine-extractor: pick when C/C++ files exist and project looks like firmware/protocol code.
- auth-analyst: pick ONLY when has_auth_code=true (login/token/session/password patterns found).
- heap-spray-analyst: pick ONLY when has_heap_ops=true AND C/C++ files exist.
- concurrency-analyst: pick ONLY when has_threading_code=true (pthread/goroutine/async/mutex found).
- config-secrets-scanner: pick when has_config_files=true OR has_dockerfile=true — always useful.
- supply-chain-analyst: pick when has_ci_pipeline=true OR has_dockerfile=true OR has_package_json=true.
- business-logic-analyst: pick ONLY when has_payment_code=true OR (has_api_routes=true AND web framework present).
- api-security-analyst: pick when has_api_routes=true OR web_framework_hits non-empty.
- android-analyst: pick when has_android_manifest=true OR .java/.kt files with android imports.
- kernel-driver-analyst: pick when has_kernel_code=true.
- Do NOT pick verifier-reviewer or reporter-writer (they run in a dedicated
  post-processing phase, not as code-reading workers).

Output a strict JSON object:
{{
  "picked": [{{"role": "<name>", "scope_globs": ["**/*.c","..."], "hints": "..."}}],
  "rejected": [{{"role": "<name>", "why_skipped": "..."}}],
  "rationale": "<1-2 sentences>"
}}

`scope_globs` is a list of glob patterns relative to project root. Use [] to
let the system pick default scope based on the role's preferred extensions.
Output ONLY the JSON. Start with `{{`. No prose, no code fences.
"""


def _format_role_table() -> str:
    descs = role_descriptions()
    lines = []
    for role, desc in descs.items():
        if role in ("reporter-writer",):
            continue  # internal-only roles
        lines.append(f"  - {role}: {desc}")
    return "\n".join(lines)


def _file_index_summary_for_llm(file_index: dict) -> dict:
    """Compact, LLM-friendly slice of file_index — avoid the giant file list."""
    files = file_index.get("files", [])
    sample = files[:12]
    return {
        "total_files": file_index.get("total_files", len(files)),
        "by_ext": file_index.get("by_ext", {}),
        "total_bytes": file_index.get("total_bytes", 0),
        "sample_files": sample,
        "has_makefile": file_index.get("has_makefile", False),
        "has_dockerfile": file_index.get("has_dockerfile", False),
        "has_requirements": file_index.get("has_requirements", False),
        "has_go_mod": file_index.get("has_go_mod", False),
        "has_package_json": file_index.get("has_package_json", False),
        "has_cargo_toml": file_index.get("has_cargo_toml", False),
        "has_pom_xml": file_index.get("has_pom_xml", False),
        "has_gradle": file_index.get("has_gradle", False),
        "has_crypto_header": file_index.get("has_crypto_header", False),
        "has_web_template": file_index.get("has_web_template", False),
        "has_binary": file_index.get("has_binary", False),
        "has_protocol_code": file_index.get("has_protocol_code", False),
        "has_config_files": file_index.get("has_config_files", False),
        "has_ci_pipeline": file_index.get("has_ci_pipeline", False),
        "has_android_manifest": file_index.get("has_android_manifest", False),
        "has_kernel_code": file_index.get("has_kernel_code", False),
        "has_threading_code": file_index.get("has_threading_code", False),
        "has_heap_ops": file_index.get("has_heap_ops", False),
        "has_payment_code": file_index.get("has_payment_code", False),
        "has_auth_code": file_index.get("has_auth_code", False),
        "has_api_routes": file_index.get("has_api_routes", False),
        "has_icmp_handler": file_index.get("has_icmp_handler", False),
        "web_framework_hits": file_index.get("web_framework_hits", []),
    }


def supervisor_pick(file_index: dict, user_prompt: str,
                     *, use_llm: bool = True) -> dict:
    """Decide which workers to spawn for round 0.

    Returns:
      {"round":0, "picked":[{role,scope_files,hints}],
       "rejected":[{role,why_skipped}], "rationale": str}
    """
    fi_summary = {
        "total_files": file_index.get("total_files"),
        "by_ext": file_index.get("by_ext"),
        "web_hits": file_index.get("web_framework_hits"),
        "has_binary": file_index.get("has_binary"),
    }
    log.info("supervisor_pick start: use_llm=%s file_index=%s", use_llm, fi_summary)

    if use_llm:
        try:
            llm_decision = _llm_pick(file_index, user_prompt)
            log.info("supervisor LLM returned: picked=%s rejected=%d",
                     [p.get("role") for p in (llm_decision.get("picked") or [])],
                     len(llm_decision.get("rejected") or []))
        except Exception as e:  # noqa: BLE001
            log.warning("supervisor LLM failed, falling back to rules: %s", e)
            llm_decision = None
    else:
        llm_decision = None

    if llm_decision is None:
        result = _rule_based_pick(file_index)
        log.info("supervisor rule-based picked=%s",
                 [p.get("role") for p in result.get("picked") or []])
        return result

    filtered = _apply_hard_filter(llm_decision, file_index)
    # Second-level safety net: LLM occasionally returns an empty picked list
    # for small projects even when there are usable sources. Fall back to the
    # rule-based picker so the user always sees at least one worker spawn.
    if not filtered["picked"]:
        log.warning("supervisor LLM produced empty picked; using rule-based fallback")
        rb = _rule_based_pick(file_index)
        if rb["picked"]:
            rb["rejected"] = (filtered.get("rejected") or []) + (rb.get("rejected") or [])
            rb["rationale"] = (
                f"LLM returned no picks; rule-based fallback applied. "
                f"LLM rationale: {filtered.get('rationale', '')}"
            )[:1000]
            log.info("supervisor rule-based fallback picked=%s",
                     [p.get("role") for p in rb["picked"]])
            return rb

    # Enforce mandatory roles and minimum agent count (≥5)
    filtered = _enforce_mandatory_and_minimum(filtered, file_index)

    log.info("supervisor final picked=%s",
             [p.get("role") for p in filtered.get("picked") or []])
    return filtered


def _llm_pick(file_index: dict, user_prompt: str) -> dict:
    """Ask the LLM to choose a worker subset."""
    from ..llm.router import call as llm_call
    role_table = _format_role_table()
    summary = _file_index_summary_for_llm(file_index)
    system = _SUPERVISOR_SYSTEM.format(role_table=role_table)
    user_msg = (
        f"Project summary:\n{json.dumps(summary, ensure_ascii=False, indent=2)}\n\n"
        f"User objective: {user_prompt}\n\n"
        "Respond with the JSON plan only."
    )
    res = llm_call("planning",
                    [Message(role="system", content=system),
                     Message(role="user", content=user_msg)],
                    max_tokens=1024)
    text = (res.text or "").strip()
    decision = _parse_supervisor_json(text)
    # Thinking models (e.g. DeepSeek v4-pro) expose their chain-of-thought
    # via raw["reasoning_content"]. Surface it by prepending to rationale so
    # the SupervisorPanel renders it without any WS/UI changes.
    reasoning = (res.raw or {}).get("reasoning_content")
    if reasoning:
        original = decision.get("rationale", "") or ""
        decision["rationale"] = (
            f"🧠 LLM 推理过程:\n{reasoning}\n\n---\n\n{original}"
        )
    return decision


def _parse_supervisor_json(text: str) -> dict:
    """Tolerant JSON object extraction (strip fences, balance braces)."""
    if not text:
        return {"picked": [], "rejected": [], "rationale": "(empty LLM output)"}
    fence = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object found in supervisor output")
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced braces in supervisor output")


# ---- Hard-rule filter ----------------------------------------------------

def _apply_hard_filter(decision: dict, file_index: dict) -> dict:
    """Apply preconditions and resolve scope_globs → concrete file paths."""
    files = file_index.get("files", [])
    known = known_role_names()
    picked: list[dict] = []
    rejected: list[dict] = list(decision.get("rejected") or [])

    for entry in decision.get("picked") or []:
        role = entry.get("role")
        if role not in known:
            rejected.append({"role": role or "?",
                              "why_skipped": "unknown role name"})
            continue
        if role in ("reporter-writer",):
            rejected.append({"role": role,
                              "why_skipped": "internal-only role"})
            continue

        why_skip = _precondition_fail(role, file_index)
        if why_skip:
            rejected.append({"role": role, "why_skipped": why_skip})
            continue

        # Resolve scope: explicit globs, or fall back to role's preferred exts
        globs = entry.get("scope_globs") or []
        scope_files = _resolve_scope(globs, role, files)
        if not scope_files:
            rejected.append({"role": role,
                              "why_skipped": "no files matched scope"})
            continue
        picked.append({
            "role": role,
            "scope_files": scope_files,   # no file count cap
            # LLM may return hints as a plain string; normalise to dict.
            "hints": entry.get("hints") if isinstance(entry.get("hints"), dict) else {},
        })

    rationale = decision.get("rationale") or "(no rationale)"
    return {"round": 0, "picked": picked, "rejected": rejected,
            "rationale": rationale}


def _precondition_fail(role: str, fi: dict) -> str | None:
    """Return the skip reason if a role's hard precondition is not met."""
    if role == "dep-analyst":
        if not (fi.get("has_requirements") or fi.get("has_go_mod")
                 or fi.get("has_package_json") or fi.get("has_cargo_toml")
                 or fi.get("has_pom_xml") or fi.get("has_gradle")):
            return "no dependency manifest found"
    if role == "iot-firmware-auditor":
        if not fi.get("has_binary"):
            return "no binary file in scope"
    if role in ("web-recon", "xss-analyst", "sqli-analyst", "authn-tester",
                 "api-security-analyst"):
        if not (fi.get("web_framework_hits") or fi.get("has_web_template")
                 or fi.get("has_api_routes")):
            return "no web framework / template / API route signals"
    if role == "business-logic-analyst":
        if not (fi.get("has_payment_code") or fi.get("web_framework_hits")
                 or fi.get("has_api_routes")):
            return "no payment/order/checkout keywords or web framework signals"
    if role == "crypto-analyst":
        if not fi.get("has_crypto_header"):
            # also allow if web framework is present (TLS configs etc)
            if not fi.get("web_framework_hits"):
                # also allow if C/C++ sources exist (may use crypto inline)
                c_count = sum(fi.get("by_ext", {}).get(ext, 0) for ext in _C_FAMILY)
                if c_count == 0:
                    return "no crypto headers, web framework, or C/C++ sources"
    if role in ("protocol-analyst", "state-machine-extractor"):
        c_count = sum(fi.get("by_ext", {}).get(ext, 0) for ext in _C_FAMILY)
        has_proto = fi.get("has_protocol_code", False) or bool(
            fi.get("by_ext", {}).get(".proto", 0)
        )
        if role == "state-machine-extractor" and c_count == 0:
            return "no C/C++ source files"
        if role == "protocol-analyst" and c_count == 0 and not has_proto:
            return "no C/C++ or .proto files"
    if role in ("heap-spray-analyst", "kernel-driver-analyst"):
        c_count = sum(fi.get("by_ext", {}).get(ext, 0) for ext in _C_FAMILY)
        if c_count == 0:
            return "no C/C++ source files"
    if role == "heap-spray-analyst":
        if not fi.get("has_heap_ops"):
            return "no malloc/free/new/delete patterns detected"
    if role == "kernel-driver-analyst":
        if not fi.get("has_kernel_code"):
            return "no kernel/driver code signals detected"
    if role == "concurrency-analyst":
        if not fi.get("has_threading_code"):
            return "no threading/async/mutex patterns detected"
    if role == "config-secrets-scanner":
        if not (fi.get("has_config_files") or fi.get("has_dockerfile")):
            return "no config or Dockerfile found"
    if role == "supply-chain-analyst":
        if not (fi.get("has_ci_pipeline") or fi.get("has_dockerfile")
                 or fi.get("has_package_json") or fi.get("has_makefile")):
            return "no CI/CD pipeline, Dockerfile, or build scripts"
    if role == "android-analyst":
        has_android = fi.get("has_android_manifest", False)
        kt_count = fi.get("by_ext", {}).get(".kt", 0)
        java_count = fi.get("by_ext", {}).get(".java", 0)
        if not (has_android or kt_count > 0 or java_count > 0):
            return "no Android manifest or Java/Kotlin source files"
    if role == "auth-analyst":
        if not fi.get("has_auth_code"):
            return "no login/token/session/password patterns detected"
    return None


from fnmatch import fnmatch as _fnmatch

_MIN_ROUND0_AGENTS = 5

# Roles that are always forced in when their signal is present,
# regardless of what the LLM suggested.
# Format: (role, condition_fn(file_index) -> bool)
_MANDATORY_ROLES: list[tuple[str, object]] = [
    ("code-auditor",
     lambda fi: bool(fi.get("total_files", 0))),  # always, if any source exists
    ("dataflow-analyst",
     lambda fi: bool(sum(fi.get("by_ext", {}).get(ext, 0) for ext in _C_FAMILY))),
    ("protocol-analyst",
     lambda fi: fi.get("has_protocol_code", False)
                or bool(fi.get("by_ext", {}).get(".proto", 0))),
]

# Candidate roles to add when count < _MIN_ROUND0_AGENTS, in priority order.
# Each entry: (role, condition_fn)
_FILLER_ROLES: list[tuple[str, object]] = [
    ("auth-analyst",       lambda fi: fi.get("has_auth_code", False)),
    ("config-secrets-scanner", lambda fi: bool(
        fi.get("has_config_files") or fi.get("has_dockerfile"))),
    ("crypto-analyst",     lambda fi: bool(
        fi.get("has_crypto_header") or fi.get("web_framework_hits")
        or sum(fi.get("by_ext", {}).get(ext, 0) for ext in _C_FAMILY))),
    ("dep-analyst",        lambda fi: bool(
        fi.get("has_requirements") or fi.get("has_go_mod")
        or fi.get("has_package_json") or fi.get("has_cargo_toml")
        or fi.get("has_pom_xml") or fi.get("has_gradle"))),
    ("heap-spray-analyst", lambda fi: bool(
        fi.get("has_heap_ops") and
        sum(fi.get("by_ext", {}).get(ext, 0) for ext in _C_FAMILY))),
    ("concurrency-analyst", lambda fi: fi.get("has_threading_code", False)),
    ("supply-chain-analyst", lambda fi: bool(
        fi.get("has_ci_pipeline") or fi.get("has_dockerfile")
        or fi.get("has_package_json") or fi.get("has_makefile"))),
    ("web-recon",          lambda fi: bool(
        fi.get("web_framework_hits") or fi.get("has_web_template")
        or fi.get("has_api_routes"))),
    ("api-security-analyst", lambda fi: bool(
        fi.get("web_framework_hits") or fi.get("has_web_template")
        or fi.get("has_api_routes"))),
    ("business-logic-analyst", lambda fi: bool(
        fi.get("has_payment_code") or fi.get("web_framework_hits")
        or fi.get("has_api_routes"))),
    ("xss-analyst",        lambda fi: bool(
        fi.get("web_framework_hits") or fi.get("has_web_template"))),
    ("sqli-analyst",       lambda fi: bool(
        fi.get("web_framework_hits") or fi.get("has_web_template"))),
    ("authn-tester",       lambda fi: bool(
        fi.get("web_framework_hits") or fi.get("has_web_template")
        or fi.get("has_api_routes"))),
    ("android-analyst",    lambda fi: bool(
        fi.get("has_android_manifest")
        or fi.get("by_ext", {}).get(".kt", 0)
        or fi.get("by_ext", {}).get(".java", 0))),
    ("state-machine-extractor", lambda fi: bool(
        sum(fi.get("by_ext", {}).get(ext, 0) for ext in _C_FAMILY))),
    ("kernel-driver-analyst", lambda fi: fi.get("has_kernel_code", False)),
]


def _enforce_mandatory_and_minimum(filtered: dict, file_index: dict) -> dict:
    """After LLM + hard-filter, enforce:
    1. Mandatory roles (code-auditor, dataflow-analyst if C exists,
       protocol-analyst if protocol code exists) are always included.
    2. Total picked count >= _MIN_ROUND0_AGENTS (fill with eligible extras).
    """
    from .roles import get_worker
    all_files = file_index.get("files", [])
    picked = list(filtered.get("picked") or [])
    picked_roles = {p["role"] for p in picked}

    def _add_role(role: str, reason: str) -> None:
        worker = get_worker(role)
        if worker is None:
            return
        scope = _resolve_scope([], role, all_files)
        if not scope:
            return
        picked.append({
            "role": role,
            "scope_files": scope,
            "hints": {"forced": reason},
        })
        picked_roles.add(role)
        log.info("supervisor forced %s: %s", role, reason)

    # Step 1: enforce mandatory roles
    for role, cond_fn in _MANDATORY_ROLES:
        if role not in picked_roles and cond_fn(file_index):
            _add_role(role, "mandatory")

    # Step 2: fill up to minimum agent count
    if len(picked) < _MIN_ROUND0_AGENTS:
        for role, cond_fn in _FILLER_ROLES:
            if len(picked) >= _MIN_ROUND0_AGENTS:
                break
            if role not in picked_roles and cond_fn(file_index):
                _add_role(role, f"filler (min={_MIN_ROUND0_AGENTS})")

    filtered["picked"] = picked
    return filtered


def _resolve_scope(globs: list[str], role: str, all_files: list[str]) -> list[str]:
    """Map LLM-supplied globs (or empty) to a concrete file list."""
    if globs:
        out: list[str] = []
        for f in all_files:
            if any(_fnmatch(f, g) for g in globs):
                out.append(f)
        if out:
            return out
        # fall through to default extension matching if globs matched nothing

    # role-default: take files matching the role's preferred extensions
    from .roles import ROLES
    spec = next((s for s in ROLES if s.role == role), None)
    exts = tuple(spec.file_extensions) if spec and spec.file_extensions else ()
    if not exts:
        # role has no preference (e.g. dep-analyst, web-recon) — give everything
        return all_files
    return [f for f in all_files if f.lower().endswith(exts)]


# ---- Rule-based fallback (used when LLM unavailable) ---------------------

def _rule_based_pick(file_index: dict) -> dict:
    """Conservative rule-based picker — same logic as M2.

    Used if the LLM supervisor errors out. Picks only the safest subset:
    code-auditor + dataflow-analyst when C files exist.
    """
    files = file_index.get("files", [])
    picked: list[dict] = []
    rejected: list[dict] = []
    known = known_role_names()

    generic = [f for f in files if f.lower().endswith(tuple(_GENERIC_SOURCE))]
    c_files = [f for f in files if f.lower().endswith(tuple(_C_FAMILY))]

    if "code-auditor" in known and generic:
        picked.append({"role": "code-auditor", "scope_files": generic,
                        "hints": {"fallback": "rule-based"}})
    if "dataflow-analyst" in known and c_files:
        picked.append({"role": "dataflow-analyst", "scope_files": c_files,
                        "hints": {"fallback": "rule-based"}})
    if not picked:
        rejected.append({"role": "*", "why_skipped": "no analyzable sources"})

    return {"round": 0, "picked": picked, "rejected": rejected,
            "rationale": "rule-based fallback (LLM supervisor unavailable)"}


# ---- Second-round supervisor (after verifier) ----------------------------

_SECOND_ROUND_SYSTEM = """\
You are the **Supervisor** mid-audit. The first round of agents has run
and the verifier has produced a list of confirmed findings. Decide if a
*second, targeted* round of workers can deepen these findings.

Only pick agents that are clearly justified by an existing finding.
Examples:
- An auth finding mentioning JWT → spawn auth-analyst on the same file.
- A crypto issue mentioning ECB on user data → spawn protocol-analyst.
- Output `{"picked": [], ...}` if no targeted follow-up makes sense.

Output a strict JSON object identical to round 0's schema:
{{"picked":[{{"role":..., "scope_globs":[...], "hints":"..."}}],
   "rejected":[{{"role":..., "why_skipped":"..."}}],
   "rationale":"..."}}
Start with `{{`. No prose, no code fences.
"""


def supervisor_second_round(file_index: dict, verified_findings: list[dict],
                              first_round_roles: list[str]) -> dict:
    """LLM decides whether to spawn a second targeted round.

    Returns the same shape as supervisor_pick(), with `round=1`.
    Returns `picked=[]` if there's nothing useful to do, which the caller
    interprets as "skip second round".
    """
    if not verified_findings:
        return {"round": 1, "picked": [], "rejected": [],
                "rationale": "no findings from first round; skipping"}
    try:
        from ..llm.router import call as llm_call
        role_table = _format_role_table()
        system = _SECOND_ROUND_SYSTEM
        # Compact findings: keep just title/severity/category/file/line
        fmin = [{"title": f.get("title"),
                  "severity": f.get("severity"),
                  "category": f.get("category"),
                  "file": f.get("file"),
                  "line": f.get("line")} for f in verified_findings[:20]]
        user_msg = (
            f"Available roles:\n{role_table}\n\n"
            f"Already-run roles: {first_round_roles}\n\n"
            f"Verified findings so far:\n{json.dumps(fmin, ensure_ascii=False, indent=2)}\n\n"
            "Project summary:\n"
            f"{json.dumps(_file_index_summary_for_llm(file_index), ensure_ascii=False, indent=2)}\n\n"
            "Respond with the JSON plan only."
        )
        res = llm_call("planning",
                        [Message(role="system", content=system),
                         Message(role="user", content=user_msg)],
                        max_tokens=768)
        decision = _parse_supervisor_json((res.text or "").strip())
        reasoning = (res.raw or {}).get("reasoning_content")
        if reasoning:
            original = decision.get("rationale", "") or ""
            decision["rationale"] = (
                f"🧠 LLM 推理过程 (Round 1):\n{reasoning}\n\n---\n\n{original}"
            )
    except Exception as e:  # noqa: BLE001
        log.warning("second-round supervisor LLM failed: %s", e)
        return {"round": 1, "picked": [], "rejected": [],
                "rationale": f"second-round LLM error: {e}"}

    out = _apply_hard_filter(decision, file_index)
    out["round"] = 1
    return out
