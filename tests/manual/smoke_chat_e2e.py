#!/usr/bin/env python3
"""End-to-end smoke test for the chat API + model routing.

Designed to run AGAINST a live VPS deployment (not local). Logs into the API
with admin credentials read from the environment, then exercises:
  - GET  /api/llm/models         — assert only claude-code-* shown
  - GET  /api/llm/routes         — assert every default route is claude-code-*
  - POST /api/uploads            — upload a tiny C source file
  - POST /api/chat (direct)      — quick greeting; assert non-empty real reply
  - POST /api/chat (direct + upload) — code audit; assert structured response
  - POST /api/chat (engine)      — minimal protocol target; assert non-empty
  - WS   /api/chat/stream        — measure first-token latency for direct mode

Usage:
  PA_BASE_URL=https://pentest-agent.online \
  PA_USERNAME=admin PA_PASSWORD=... \
  python tests/manual/smoke_chat_e2e.py
"""
from __future__ import annotations
import json
import os
import sys
import time
import asyncio
from urllib.parse import urlparse

import httpx
import websockets


_BASE_URL = os.environ.get("PA_BASE_URL")
if not _BASE_URL:
    sys.exit("PA_BASE_URL env var is required — refusing to use a hardcoded default")
BASE_URL = _BASE_URL.rstrip("/")
USERNAME = os.environ.get("PA_USERNAME", "admin")
PASSWORD = os.environ.get("PA_PASSWORD")
if not PASSWORD:
    sys.exit("PA_PASSWORD env var required")

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"

results: list[tuple[bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    mark = PASS if ok else FAIL
    print(f"{mark} {name}" + (f"  ({detail})" if detail else ""))
    results.append((ok, name))
    return ok


def login(client: httpx.Client) -> None:
    r = client.post(f"{BASE_URL}/auth/login",
                    json={"username": USERNAME, "password": PASSWORD})
    if r.status_code != 200:
        sys.exit(f"login failed: {r.status_code} {r.text}")
    # cookie is set automatically on the client


def test_models_endpoint(client: httpx.Client) -> None:
    r = client.get(f"{BASE_URL}/api/llm/models")
    data = r.json()
    names = [m["name"] for m in data.get("models", [])]
    check("GET /api/llm/models returns 200", r.status_code == 200)
    check("models list non-empty", len(names) > 0, f"{len(names)} models")
    check("all models are claude-code-*",
          all(n.startswith("claude-code-") for n in names),
          ", ".join(names))


def test_routes_endpoint(client: httpx.Client) -> None:
    r = client.get(f"{BASE_URL}/api/llm/routes")
    data = r.json()
    routes = data.get("routes", {})
    check("GET /api/llm/routes returns 200", r.status_code == 200)
    check("planning route is claude-code-*",
          routes.get("planning", "").startswith("claude-code-"),
          routes.get("planning"))
    check("codegen route is claude-code-*",
          routes.get("codegen", "").startswith("claude-code-"),
          routes.get("codegen"))
    check("triage route is claude-code-*",
          routes.get("triage", "").startswith("claude-code-"),
          routes.get("triage"))


def upload_sample(client: httpx.Client) -> int | None:
    sample = b"""#include <string.h>
#include <stdio.h>
int main(int argc, char **argv) {
    char buf[16];
    if (argc > 1) strcpy(buf, argv[1]);
    printf("input: %s\\n", buf);
    return 0;
}
"""
    files = {"files": ("vuln.c", sample, "text/x-c")}
    r = client.post(f"{BASE_URL}/api/uploads", files=files)
    if r.status_code != 200:
        check("upload sample.c", False, f"{r.status_code} {r.text[:120]}")
        return None
    uploads = r.json().get("uploads", [])
    if not uploads:
        check("upload sample.c", False, "no uploads in response")
        return None
    uid = uploads[0]["id"]
    check("upload sample.c", True, f"id={uid}")
    return uid


def test_direct_greeting(client: httpx.Client) -> None:
    t0 = time.time()
    r = client.post(f"{BASE_URL}/api/chat",
                    json={"message": "你好你是谁？用一句话回答",
                          "mode": "direct"},
                    timeout=120.0)
    dt = time.time() - t0
    if r.status_code != 200:
        check("direct greeting", False,
              f"HTTP {r.status_code} {r.text[:200]} ({dt:.1f}s)")
        return
    reply = r.json().get("reply", "")
    check("direct greeting latency < 90s", dt < 90, f"{dt:.1f}s")
    check("direct greeting reply is real (>=10 chars, not '分析完成。')",
          len(reply) >= 10 and reply.strip() != "分析完成。",
          f"len={len(reply)}, head={reply[:80]!r}")


def test_direct_concept(client: httpx.Client) -> None:
    t0 = time.time()
    r = client.post(f"{BASE_URL}/api/chat",
                    json={"message": "讲讲什么是 SSRF 攻击",
                          "mode": "direct"},
                    timeout=120.0)
    dt = time.time() - t0
    if r.status_code != 200:
        check("direct concept (SSRF)", False, f"HTTP {r.status_code} ({dt:.1f}s)")
        return
    reply = r.json().get("reply", "")
    check("SSRF concept reply contains 'SSRF' or '服务器'",
          "SSRF" in reply or "服务器" in reply,
          f"head={reply[:120]!r}")


def test_direct_with_upload(client: httpx.Client, upload_id: int) -> None:
    t0 = time.time()
    r = client.post(f"{BASE_URL}/api/chat",
                    json={"message": "请审计这段 C 代码，找出潜在的安全问题",
                          "mode": "direct",
                          "upload_ids": [upload_id]},
                    timeout=180.0)
    dt = time.time() - t0
    if r.status_code != 200:
        check("direct + upload code audit", False,
              f"HTTP {r.status_code} ({dt:.1f}s)")
        return
    reply = r.json().get("reply", "")
    has_overflow_concept = any(k in reply for k in
        ("缓冲区", "溢出", "strcpy", "buffer", "栈溢出", "越界"))
    check("code audit reply mentions buffer-overflow concept",
          has_overflow_concept,
          f"head={reply[:160]!r}")


def test_engine_minimal(client: httpx.Client) -> None:
    # Engine mode requires a real target. Create one (and an auth scope) first.
    sc = client.put(f"{BASE_URL}/targets/auth-scope",
                    json={"hosts": ["example.test"], "cidrs": [], "note": "e2e"})
    if sc.status_code != 200:
        check("engine mode setup auth-scope", False,
              f"HTTP {sc.status_code} {sc.text[:120]}")
        return
    tr = client.post(f"{BASE_URL}/targets",
                     json={"value": "example.test", "authorized": True})
    if tr.status_code != 200:
        check("engine mode create target", False,
              f"HTTP {tr.status_code} {tr.text[:120]}")
        return
    tid = tr.json()["id"]

    t0 = time.time()
    try:
        r = client.post(f"{BASE_URL}/api/chat",
                        json={"message": "做个最小规划",
                              "mode": "engine",
                              "target_id": tid},
                        timeout=180.0)
        dt = time.time() - t0
        if r.status_code != 200:
            check("engine mode minimal request", False,
                  f"HTTP {r.status_code} {r.text[:120]} ({dt:.1f}s)")
            return
        reply = r.json().get("reply", "")
        check("engine mode returns non-placeholder reply",
              reply.strip() not in ("", "分析完成。"),
              f"latency={dt:.1f}s, len={len(reply)}, head={reply[:120]!r}")
    except httpx.ReadTimeout:
        check("engine mode minimal request", False, "timeout > 180s")


async def test_ws_first_token(cookie: str) -> None:
    parsed = urlparse(BASE_URL)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    ws_url = f"{scheme}://{parsed.netloc}/api/chat/stream"
    headers = [("Cookie", f"pa_token={cookie}")]
    t0 = time.time()
    try:
        async with websockets.connect(ws_url, additional_headers=headers,
                                       open_timeout=30) as ws:
            await ws.send(json.dumps({
                "message": "用三句话介绍 Pentest Agent",
                "mode": "direct",
            }))
            first_token_at: float | None = None
            done = False
            async for raw in ws:
                evt = json.loads(raw)
                if evt.get("event") == "token" and first_token_at is None:
                    first_token_at = time.time() - t0
                if evt.get("event") in ("done", "error"):
                    done = True
                    break
            if first_token_at is None:
                check("WS first-token", False, "no token received")
            else:
                check("WS first-token latency < 15s",
                      first_token_at < 15, f"{first_token_at:.1f}s")
            check("WS reached terminal event", done, "")
    except Exception as e:  # noqa: BLE001
        check("WS first-token", False, f"{type(e).__name__}: {e}")


def main() -> int:
    print(f"=== smoke_chat_e2e against {BASE_URL} ===\n")
    with httpx.Client(verify=True, follow_redirects=True) as client:
        login(client)
        cookie = client.cookies.get("pa_token")
        if not cookie:
            sys.exit("login succeeded but no pa_token cookie set")

        print("[Section] model registry / routing")
        test_models_endpoint(client)
        test_routes_endpoint(client)
        print()

        print("[Section] uploads")
        upload_id = upload_sample(client)
        print()

        print("[Section] direct mode")
        test_direct_greeting(client)
        test_direct_concept(client)
        if upload_id is not None:
            test_direct_with_upload(client, upload_id)
        print()

        print("[Section] engine mode")
        test_engine_minimal(client)
        print()

        print("[Section] WebSocket streaming")
        asyncio.run(test_ws_first_token(cookie))
        print()

    passed = sum(1 for ok, _ in results if ok)
    total = len(results)
    print(f"=== {passed}/{total} passed ===")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
