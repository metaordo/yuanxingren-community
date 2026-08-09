"""Chat API: ties the frontend to the Orchestrator pipeline.

POST /api/chat          — synchronous run (returns full result at once)
WS   /api/chat/stream   — streaming variant (emits tokens + step events)
"""
from __future__ import annotations
import asyncio
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..auth.middleware import get_current_user
from ..auth import jwt_handler
from ..auth.models import User
from ..db import engine, get_session
from ..targets.models import Target as TargetModel
from ..targets.scope_manager import AuthScope
from ..uploads.models import UploadedFile
from ..uploads.preprocess import render_uploads_block
from ..orchestrator import run_pipeline
from ..llm import Message
from ..llm.router import _get_client, _task_routes  # streaming uses primary route
from pentest_agent_sdk.contracts import Target as TargetDTO

router = APIRouter(prefix="/api/chat", tags=["chat"])
log = logging.getLogger(__name__)


AGENT_SYSTEM_PROMPT = """你是新一代 AI 渗透测试智能体 (Pentest Agent)，具备以下能力：
- 自主规划并协调 SVF 白盒分析、StateAFL 协议模糊测试、Off-Path 网络攻击三大引擎
- 融合 403 条协议栈文献知识库，可进行漏洞研判、PoC 合成与 0-Day 发现
- 熟悉 OWASP Top 10、CWE 分类、CVE 情报、内核与网络协议安全

请先判断用户意图并据此回复：

【意图 A：闲聊 / 身份问询 / 使用指引】
- 涵盖「你好」「你是谁」「你叫什么」「介绍一下自己」「你能做什么」「怎么用」等
- 如果用户在问「你是谁 / 你的身份 / 介绍自己」这一类问题，**必须**用以下这段固定中文文本回答（一字不差，可以在末尾追加 1 句邀请协作的话，但不要改写、不要翻译、不要分节）：
  「我是一个 AI 渗透测试智能体，专门协助进行安全测试和漏洞研究工作。我可以协调白盒静态分析、协议模糊测试与网络攻击三大引擎，并融合 403 条协议栈文献知识库，帮助你完成漏洞挖掘、代码审计与 PoC 合成。」
- 若用户只是问候（如「你好」「在吗」），用 1-2 句中文回应即可，无需重复完整身份介绍
- 若用户在问「能做什么 / 怎么用」，用 2-4 句中文给出常用能力示例，不要输出结构化分节

【意图 B：安全咨询 / 概念解释】
- 比如「什么是 SSRF」「讲讲 TCP ISN 预测」
- 用自然段落解释核心概念，必要时给一个简短示例
- 避免机械分节，控制在 150-300 字

【意图 C：漏洞挖掘 / 渗透测试请求】
- 比如「检测 SQL 注入」「审计这段代码」「探测 ISN 可预测性」
- 使用以下 Markdown 结构化输出（不要输出 JSON，不要用代码围栏包裹整个回复）：

## 意图识别
一句话概括用户的测试目标。

## 分析思路
2-4 条要点，说明你打算怎么做 / 会调用哪些能力。

## 初步发现
逐条列出可能的风险点，每条带 **[严重级别]** 前缀（严重 / 高危 / 中危 / 低危 / 提示）。
若暂无可验证发现，如实说明「需要进一步探测」。

## 建议动作
给出 2-3 条后续可执行动作（例如配置目标、切换引擎模式、运行 PoC 沙箱等）。

## 风险提示
一句话合规提醒，强调仅在授权范围内测试。

通用约束：
- 全程使用中文
- 不输出原始 JSON / YAML 大块数据，不要把整段回复用 ``` 包起来
- 严重级别只用：严重 / 高危 / 中危 / 低危 / 提示
- 不编造不存在的 CVE 编号，不确定时写「疑似」或「待验证」
- 用户上传的文件**完整内容**已直接放在用户消息里（在「## 用户上传的文件」段落下），请直接基于这些内容分析；**不要**说"先读取文件"、"无法访问文件"、"无法找到文件"、"请提供源代码"之类的话
- 「当前目标」中如果是形如 `uploads/<id>/<id>/<filename>` 的路径，那就是用户从「目标配置 → 上传文件」上传的目标；该文件的完整内容已经在下方「## 用户上传的文件」段落里给你了，不要再尝试从磁盘读取或要求重新上传
"""


class ChatIn(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    target_id: int | None = None
    mode: str = Field("engine", pattern="^(engine|direct|multi_agent)$")
    upload_ids: list[int] = Field(default_factory=list)


class ChatOut(BaseModel):
    reply: str
    plan: list[dict] = []
    findings: list[dict] = []


def _load_uploads(data: ChatIn, user: User, session: Session) -> list[UploadedFile]:
    if not data.upload_ids:
        return []
    rows = session.exec(
        select(UploadedFile).where(
            UploadedFile.owner_id == user.id,
            UploadedFile.id.in_(data.upload_ids),
        )
    ).all()
    if len(rows) != len(set(data.upload_ids)):
        raise HTTPException(status_code=404, detail="one or more uploads not found")
    return rows


def _resolve_target(data: ChatIn, user: User, session: Session) -> TargetDTO:
    if data.target_id is not None:
        t = session.get(TargetModel, data.target_id)
        if not t or t.owner_id != user.id:
            raise HTTPException(status_code=404, detail="target not found")
        if not t.authorized:
            raise HTTPException(status_code=403, detail="target lacks authorization")
        return TargetDTO(id=str(t.id), type=t.type.value, value=t.value,
                         scope=t.scope, auth=t.auth)
    if data.mode != "direct":
        raise HTTPException(status_code=400,
                            detail="target_id required unless mode=direct")
    return TargetDTO(id="direct", type="protocol", value="inline")


def _target_upload(data: ChatIn, user: User, session: Session) -> UploadedFile | None:
    """If the active target was created from an uploaded file, return that file.

    Looks up the Target row by id and reads `metadata_["upload_id"]` (set by
    create_target_from_upload). The file's preprocessed summary already
    contains the full content for source code, so the LLM can analyze it
    without needing filesystem access.
    """
    if data.target_id is None:
        return None
    t = session.get(TargetModel, data.target_id)
    if not t or t.owner_id != user.id:
        return None
    meta = t.metadata_ or {}
    upload_id = meta.get("upload_id")
    if not isinstance(upload_id, int):
        return None
    uf = session.get(UploadedFile, upload_id)
    if uf and uf.owner_id == user.id:
        return uf
    return None


def _merge_uploads(primary: list[UploadedFile],
                   secondary: UploadedFile | None) -> list[UploadedFile]:
    """Combine attachment uploads with the target-backed upload, de-duping by id."""
    if secondary is None:
        return primary
    seen = {u.id for u in primary}
    if secondary.id in seen:
        return primary
    return [secondary, *primary]


def _message_with_uploads(message: str, uploads: list[UploadedFile]) -> str:
    if not uploads:
        return message
    return f"{message}{render_uploads_block(uploads)}"


# Canonical identity reply — short-circuited for identity questions so the
# answer is byte-for-byte consistent across runs, models, and prompt drift.
IDENTITY_REPLY = (
    "我是一个 AI 渗透测试智能体，专门协助进行安全测试和漏洞研究工作。"
    "我可以协调白盒静态分析、协议模糊测试与网络攻击三大引擎，"
    "并融合 403 条协议栈文献知识库，帮助你完成漏洞挖掘、代码审计与 PoC 合成。"
    "\n\n你可以直接描述测试目标或粘贴代码片段，我会按意图给出对应的分析结果。"
)

# Canonical workflow walkthrough — explains the 5-stage Agent pipeline shown
# in the left-side panel, plus the quickstart steps a user typically follows.
WORKFLOW_REPLY = (
    "## 一次完整渗透测试的执行流程\n\n"
    "左侧「Agent 工作流」面板展示了我处理每一次任务的 5 个阶段，"
    "它们由我自动协调，你只需配置目标并提出需求：\n\n"
    "**1. 目标（Target）** — 接收并校验你要测试的对象（URL / IP / 域名 / 二进制 / pcap / 协议端点）。"
    "授权范围会在后端强制校验，目标必须落在你已配置的 host / CIDR 范围内。\n\n"
    "**2. 规划器（Planner）** — LLM 根据目标类型和你的指令拆解任务，决定调用哪些引擎、按什么顺序、用什么参数。\n\n"
    "**3. 路由器（Router）** — 把规划出的任务派发到对应的执行单元：\n"
    "   - 「深度引擎」模式：SVF 白盒静态分析 / StateAFL 协议模糊测试 / Off-Path 网络攻击 / 外部工具（Nmap、Burp、ZAP、Metasploit）\n"
    "   - 「LLM 直接审计」模式：纯 LLM 推理 + 知识库检索（适合代码审计、概念问答、快速研判）\n\n"
    "**4. 验证器（Verifier）** — 对各引擎产出的候选发现做交叉验证，关联 403 条协议栈文献知识库去重、定级。\n\n"
    "**5. 报告器（Reporter）** — 生成结构化报告（意图识别 / 分析思路 / 初步发现 / 建议动作 / 风险提示），"
    "并把已验证的安全发现实时推送到对话与证据图视图。\n\n"
    "## 快速上手\n\n"
    "1. **配置授权范围** —— 设置 → 授权范围，添加允许测试的 host 或 CIDR\n"
    "2. **设置目标** —— 设置 → 目标配置，输入 URL / IP / 二进制等\n"
    "3. **选择分析模式** —— 左侧面板底部，「深度引擎」或「LLM 直审」可随时切换\n"
    "4. **提出测试需求** —— 在对话框描述要做什么，比如「检测目标的 SQL 注入」「审计这段代码」「探测 ISN 可预测性」\n"
    "5. **查看结果** —— 对话区显示结构化报告，证据图视图可看到目标→发现→证据的关系图\n\n"
    "如果只是想了解某个安全概念或快速审计一段代码，直接在对话框提问/粘贴即可，不必先配置目标。"
)

# Phrases that indicate the user is asking who/what the assistant is.
# Matching is substring-based and case-insensitive on the trimmed message.
_IDENTITY_PATTERNS = (
    "你是谁", "你是什么", "你叫什么", "你是哪", "你的身份",
    "介绍一下你自己", "介绍下你自己", "介绍你自己",
    "自我介绍", "介绍一下自己", "介绍下自己",
    "你能做什么", "你会什么", "你是干什么的",
    "你最擅长", "你擅长", "你的能力", "你的特长",
    "你的功能", "你的作用", "你有哪些能力", "你能帮我做什么",
    "what are you", "who are you", "introduce yourself",
    "what can you do", "your capabilities",
)

# Phrases that indicate the user wants the end-to-end workflow walkthrough.
_WORKFLOW_PATTERNS = (
    "完整的渗透测试", "完整渗透测试", "完整测试流程",
    "怎么做渗透测试", "如何做渗透测试", "怎么用你做",
    "怎么用你完成", "如何使用你做", "怎么使用",
    "工作流程", "agent 工作流", "工作流",
    "完整流程", "整体流程", "执行流程",
    "how do i use you", "how to do a pentest",
    "full pentest workflow", "end-to-end pentest",
)


def _is_identity_question(message: str) -> bool:
    if not message:
        return False
    text = message.strip().lower()
    if len(text) > 80:
        return False
    return any(p in text for p in _IDENTITY_PATTERNS)


def _is_workflow_question(message: str) -> bool:
    if not message:
        return False
    text = message.strip().lower()
    if len(text) > 80:
        return False
    return any(p in text for p in _WORKFLOW_PATTERNS)


@router.post("", response_model=ChatOut)
def chat(data: ChatIn,
         user: User = Depends(get_current_user),
         session: Session = Depends(get_session)):
    target = _resolve_target(data, user, session)
    uploads = _load_uploads(data, user, session)
    uploads = _merge_uploads(uploads, _target_upload(data, user, session))

    # Short-circuit identity / workflow questions for byte-for-byte consistent answers.
    if not uploads and _is_identity_question(data.message):
        return ChatOut(reply=IDENTITY_REPLY, plan=[], findings=[])
    if not uploads and _is_workflow_question(data.message):
        return ChatOut(reply=WORKFLOW_REPLY, plan=[], findings=[])

    if data.mode == "direct":
        return _direct_llm_audit(data.message, target, uploads)

    if data.mode == "multi_agent":
        return _multi_agent_sync(data.message, target, user)

    try:
        result = run_pipeline(_message_with_uploads(data.message, uploads), target,
                              auth_scope=_load_auth_scope(user, session))
    except Exception as e:  # noqa: BLE001
        log.exception("orchestrator failed")
        raise HTTPException(status_code=500, detail=f"pipeline error: {e}")
    return ChatOut(reply=result.get("report") or "分析完成。",
                   plan=result.get("plan", []),
                   findings=result.get("verified_findings", []))


def _multi_agent_sync(prompt: str, target: TargetDTO, user: User) -> ChatOut:
    """Synchronous multi-agent path. The streaming variant goes through WS.

    Strict precondition: target must be of type 'source'. The workflow then
    reads the AgentTask + AgentRun rows it creates and returns the final
    report + verified findings.
    """
    if target.type != "source":
        raise HTTPException(status_code=400,
                            detail="multi_agent mode requires a source target")
    from ..agents.workflow import run_workflow
    try:
        result = run_workflow(user_prompt=prompt, target=target, owner_id=user.id)
    except Exception as e:  # noqa: BLE001
        log.exception("multi-agent workflow failed")
        raise HTTPException(status_code=500, detail=f"multi-agent error: {e}")
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])
    return ChatOut(reply=result.get("report") or "分析完成。",
                   plan=[],
                   findings=result.get("findings", []))


def _load_auth_scope(user: User, session: Session) -> dict:
    scope = session.exec(select(AuthScope).where(AuthScope.owner_id == user.id)).first()
    if not scope:
        return {"hosts": [], "cidrs": []}
    return {"hosts": list(scope.hosts), "cidrs": list(scope.cidrs)}


def _format_direct_reply(text: str) -> str:
    cleaned = text.strip()
    if not cleaned:
        return "分析完成。"
    return cleaned


def _direct_llm_audit(prompt: str, target: TargetDTO, uploads: list[UploadedFile]) -> ChatOut:
    """LLM Direct Audit: bypass engine pipeline, let LLM reason directly."""
    from ..llm.router import call as llm_call
    system = AGENT_SYSTEM_PROMPT
    user_msg = f"当前目标: {target.value}\n\n{prompt}{render_uploads_block(uploads)}"
    messages = [
        Message(role="system", content=system),
        Message(role="user", content=user_msg),
    ]
    try:
        result = llm_call("planning", messages, max_tokens=4096)
    except Exception as e:
        log.exception("direct LLM audit failed")
        raise HTTPException(status_code=500, detail=f"LLM error: {e}")
    return ChatOut(reply=_format_direct_reply(result.text), plan=[], findings=[])


# ---------------------------------------------------------------------------
# WebSocket streaming endpoint
# ---------------------------------------------------------------------------

def _ws_authenticate(ws: WebSocket) -> User | None:
    """Authenticate the WS connection via the same JWT cookie used elsewhere."""
    cookie = ws.cookies.get("pa_token")
    if not cookie:
        return None
    try:
        payload = jwt_handler.verify(cookie)
    except Exception:
        return None
    user_id = int(payload.get("sub", 0))
    with Session(engine) as session:
        u = session.get(User, user_id)
        if u and u.is_active:
            return u
    return None


async def _emit(ws: WebSocket, event: str, **data) -> None:
    payload = {"event": event, **data}
    await ws.send_text(json.dumps(payload, ensure_ascii=False, default=str))


async def _multi_agent_stream(ws: WebSocket, prompt: str,
                                target: TargetDTO, user: User) -> None:
    """Pump events from the multi-agent workflow into the WebSocket."""
    from ..agents.workflow import astream_workflow
    try:
        async for evt in astream_workflow(user_prompt=prompt,
                                            target=target,
                                            owner_id=user.id):
            await ws.send_text(json.dumps(evt, ensure_ascii=False, default=str))
    except Exception as e:  # noqa: BLE001
        log.exception("multi-agent stream crashed")
        try:
            await _emit(ws, "workflow_error", detail=f"stream error: {e}")
        except Exception:  # noqa: BLE001
            pass
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass


@router.websocket("/stream")
async def chat_stream(ws: WebSocket):
    """Stream the analysis pipeline.

    Protocol (client → server): single JSON {message, target_id, mode}.
    Protocol (server → client): JSON events
      {event: "step", node: "planner|router|verifier|reporter"}
      {event: "token", chunk: "..."}
      {event: "finding", finding: {...}}
      {event: "done", reply: "...", findings: [...]}
      {event: "error", detail: "..."}
    """
    await ws.accept()
    user = _ws_authenticate(ws)
    if not user:
        await _emit(ws, "error", detail="not authenticated")
        await ws.close(code=1008)
        return

    try:
        raw = await ws.receive_text()
        data = ChatIn(**json.loads(raw))
    except Exception as e:  # noqa: BLE001
        await _emit(ws, "error", detail=f"bad request: {e}")
        await ws.close()
        return

    with Session(engine) as session:
        try:
            target = _resolve_target(data, user, session)
            uploads = _load_uploads(data, user, session)
            uploads = _merge_uploads(uploads, _target_upload(data, user, session))
            ws_auth_scope = _load_auth_scope(user, session)
        except HTTPException as he:
            await _emit(ws, "error", detail=he.detail)
            await ws.close()
            return

    # Short-circuit identity / workflow questions: emit canonical reply
    # token-by-chunk so the UI sees normal streaming, then close. No LLM call.
    if not uploads and (
        _is_identity_question(data.message) or _is_workflow_question(data.message)
    ):
        canned = (IDENTITY_REPLY if _is_identity_question(data.message)
                  else WORKFLOW_REPLY)
        await _emit(ws, "step", node="thinking")
        chunk_size = 24
        for i in range(0, len(canned), chunk_size):
            await _emit(ws, "token", chunk=canned[i:i + chunk_size])
        await _emit(ws, "done", reply=canned, plan=[], findings=[])
        try:
            await ws.close()
        except WebSocketDisconnect:
            pass
        return

    # Multi-agent mode: skip the LLM-token streaming branch entirely and
    # instead pump workflow events directly from the workflow generator.
    if data.mode == "multi_agent":
        if target.type != "source":
            await _emit(ws, "error",
                        detail="multi_agent mode requires a source target")
            await ws.close()
            return
        await _multi_agent_stream(ws, data.message, target, user)
        return

    upload_block = render_uploads_block(uploads)

    # Stream the LLM response via the failover chain.
    # In direct mode we only show a single "thinking" step (no fake pipeline);
    # in engine mode we still emit step events for the orchestrator phases below.
    if data.mode == "direct":
        await _emit(ws, "step", node="thinking")
        system = AGENT_SYSTEM_PROMPT
        prompt_text = f"当前目标: {target.value}\n\n{data.message}{upload_block}"
    else:
        await _emit(ws, "step", node="planner")
        system = ("You are a pentest planner. Briefly describe your plan in "
                  "1-2 sentences, then output the JSON plan.")
        prompt_text = f"Target: {target}\nObjective: {data.message}{upload_block}"

    messages = [Message(role="system", content=system),
                Message(role="user", content=prompt_text)]

    streamed_text = ""
    stream_error: str | None = None
    try:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        max_tokens = 4096 if data.mode == "direct" else 512

        def producer():
            try:
                last_err: Exception | None = None
                candidates = _task_routes.get("planning") or _task_routes["default"]
                for model_name in candidates:
                    try:
                        client = _get_client(model_name)
                        for chunk in client.stream(messages, max_tokens=max_tokens):
                            loop.call_soon_threadsafe(queue.put_nowait, ("token", chunk))
                        last_err = None
                        break
                    except Exception as e:  # noqa: BLE001
                        last_err = e
                        log.warning("stream candidate %s failed: %s", model_name, e)
                        continue
                if last_err is not None:
                    loop.call_soon_threadsafe(queue.put_nowait, ("error", str(last_err)))
            except Exception as e:  # noqa: BLE001
                loop.call_soon_threadsafe(queue.put_nowait, ("error", str(e)))
            loop.call_soon_threadsafe(queue.put_nowait, ("end", None))

        await loop.run_in_executor(None, producer)
        while True:
            kind, payload = await queue.get()
            if kind == "end":
                break
            if kind == "token":
                streamed_text += payload
                await _emit(ws, "token", chunk=payload)
            elif kind == "error":
                stream_error = payload
                break
    except Exception as e:  # noqa: BLE001
        stream_error = str(e)

    if data.mode == "direct":
        if streamed_text.strip():
            await _emit(ws, "done",
                        reply=streamed_text,
                        plan=[], findings=[])
        else:
            await _emit(ws, "error",
                        detail=f"LLM 调用失败：{stream_error or '上游模型不可用'}")
        try:
            await ws.close()
        except WebSocketDisconnect:
            pass
        return

    # Phase 2 (engine mode): run the full synchronous pipeline (router → verifier → reporter)
    await _emit(ws, "step", node="router")
    try:
        result = await asyncio.to_thread(run_pipeline,
                                          _message_with_uploads(data.message, uploads),
                                          target,
                                          auth_scope=ws_auth_scope)
    except Exception as e:  # noqa: BLE001
        log.exception("orchestrator failed in stream")
        await _emit(ws, "error", detail=f"pipeline error: {e}")
        await ws.close()
        return

    await _emit(ws, "step", node="verifier")
    for f in result.get("verified_findings", []):
        await _emit(ws, "finding", finding=f)

    await _emit(ws, "step", node="reporter")
    await _emit(ws, "done",
                reply=result.get("report") or "分析完成。",
                plan=result.get("plan", []),
                findings=result.get("verified_findings", []))
    try:
        await ws.close()
    except WebSocketDisconnect:
        pass
