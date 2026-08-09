# AI 渗透测试智能体 — 详细设计方案

> 源自 `penetrate.pptx` + 用户迭代需求，基于 `/root/.claude/plans/ppt-jiggly-cloud.md` 落地。
> 当前阶段: M1 骨架完成，后续进入三引擎集成。

---

## 1. 项目起源与定位

### 1.1 PPT 原始主张 (penetrate.pptx, 4 页)
- AI 时代攻击窗口从"天级"降至"分钟级"，传统渗透测试跟不上
- 三位一体架构: 路径捕获 × 深度语义解析 × 漏洞验证利用
- 三项底层技术:
  1. 高精度指针分析与数据流追踪 (白盒)
  2. 状态机差分与 Fuzzing 插桩 (黑盒)
  3. 网络建模与 Off-Path 套接字篡改
- 能力指标: 200+ 漏洞模式、95% 误报压缩 (放宽到 15% 首轮)、20+ 0-Day

### 1.2 用户迭代需求 (本会话中明确)
1. **三技术并行攻坚** (非单点深耕)
2. **工程 + 战略兼顾** — 既给代码实现，也给战略改进建议
3. **配色参考** `参考界面.png` (#e53834 主色, #f7f8fa 背景, #121419 文字, #4b5563 次要文字)
4. **内置协议栈知识库** — `references.md` 的 403 条 TCP/IP/DNS/BGP/TLS/5G/IoT 文献
5. **知识库角色澄清** — "专家参考书"，不是"漏洞白名单"；漏洞发现由底层引擎独立完成
6. **0-Day 发现专项** — 新颖性评分 + 自动 PoC 合成 + 沙箱验证 + 责任披露
7. **LLM 直接审计模式** — 无源码场景快速 code review
8. **插件化扩展** — EnginePlugin/ToolPlugin 标准契约
9. **外部渗透工具集成** — Burp/Metasploit/Nmap/ZAP/sqlmap/Nikto/testssl/tshark
10. **前端模型选配** — Claude/GPT/Gemini/国产/本地 vLLM/Ollama
11. **误报率放宽** — 从 95% 压缩放宽到 ≤15% (首轮)
12. **黑盒目标输入** — IP/URL/域名/CIDR/二进制/pcap/协议端点 七种类型
13. **简化部署** — 不依赖 Docker，主推 systemd 原生安装
14. **前端认证** — 用户名+密码登录，bcrypt + JWT + RBAC

---

## 2. 整体架构

### 2.1 核心原则
**LLM 做编排，不做判定。** 三项底层引擎作为 Tools，LLM 负责规划调用顺序、合成输入、对结果做 triage。误报压缩靠**多引擎交叉验证**，不靠 LLM 主观判断。

### 2.2 分层架构

```
┌─────────────────────────────────────────────────────────┐
│  Web GUI (React + Tailwind)                              │
│  Login → Dashboard → Chat / TargetInput /                │
│  ModelPicker / ToolMarket / KnowledgePanel               │
└──────────────────────────┬──────────────────────────────┘
                           │ WebSocket + REST (FastAPI)
┌──────────────────────────▼──────────────────────────────┐
│  Orchestrator (LangGraph 状态机)                          │
│  Planner → Tool Router → Verifier → Reporter (loop)      │
│  Memory: 对话 + 产物库 + 证据图 + 协议栈知识库 (RAG)        │
└──┬─────────┬───────────┬────────────┬──────────┬────────┘
   │         │           │            │          │
┌──▼──────┐┌─▼─────────┐┌▼───────────┐┌▼────────┐┌▼──────────┐
│ 静态分析 ││ 协议 Fuzz  ││ 网络建模    ││ LLM 直审 ││ 插件引擎   │
│ (白盒)   ││ & 状态机差分││ Off-Path   ││ (三子模式)││ (扩展槽)   │
│ SVF +   ││ AFL++ +   ││ Scapy +    ││          ││ gRPC 隔离 │
│ CodeQL  ││ StateAFL  ││ eBPF       ││          ││           │
└─────────┘└───────────┘└────────────┘└──────────┘└───────────┘
   │         │           │            │          │
   └─────────▼───────────┴────────────┴──────────┘
        证据图 (Neo4j) + PoC 产物库 (MinIO/FS) +
        协议栈知识库 (Chroma/Qdrant)
```

### 2.3 数据流

```
用户 prompt
  ↓
前端发 WebSocket → 后端 API
  ↓
Orchestrator.Planner (LLM 规划任务)
  ↓
Tool Router 调用具体引擎 (内置 or 插件 or 外部工具)
  ↓
结果汇入 Verifier (交叉验证 + LLM 分诊 + 知识库关联)
  ↓
Unknown Detector 判断是否为 0-Day 候选
  ↓
Reporter 生成结构化报告 + PoC
  ↓
前端流式展示 + 证据图可视化
```

---

## 3. 目录结构 (已实现)

```
pentest-agent/
├── README.md                  # 产品说明
├── DESIGN.md                  # 本文件 (详细设计)
├── CLAUDE.md                  # Claude Code 协作指南
│
├── backend/                   # FastAPI 后端
│   ├── main.py                # 应用入口 + lifespan 初始化
│   ├── db.py                  # SQLite + SQLModel
│   ├── requirements.txt
│   ├── auth/                  # ✅ 已实现
│   │   ├── models.py          # User + Role 枚举
│   │   ├── password.py        # bcrypt + 密码策略
│   │   ├── jwt_handler.py     # JWT 签发/校验
│   │   ├── service.py         # 登录/注册业务 + 失败锁定 + 初始密码生成
│   │   ├── middleware.py      # FastAPI 依赖注入
│   │   └── routes.py          # /auth/login, /auth/logout, /auth/me, ...
│   ├── targets/               # ✅ 已实现
│   │   ├── models.py          # Target + TargetType + AuthScope
│   │   ├── parser.py          # 解析 IP/URL/域名/CIDR/...
│   │   ├── validator.py       # 授权范围校验
│   │   ├── scope_manager.py   # 授权范围 CRUD
│   │   └── routes.py          # /targets, /targets/auth-scope
│   ├── llm/                   # ✅ 已实现
│   │   ├── base.py            # LLMClient Protocol + Message/Usage/ChatResult
│   │   ├── registry.py        # 模型注册表 (Claude/GPT/...)
│   │   ├── router.py          # 任务 → 模型路由 + 故障转移
│   │   ├── budget_tracker.py  # Token 统计
│   │   ├── credential_store.py# [待实现] 凭证加密
│   │   ├── failover.py        # [待实现] 主备切换逻辑
│   │   └── adapters/
│   │       ├── anthropic.py   # ✅ Claude 适配器
│   │       └── openai.py      # ✅ OpenAI 适配器
│   ├── tools/                 # LLM 可调用工具
│   │   ├── external_pentest/  # ✅ 外部工具适配层
│   │   │   ├── base.py        # ExternalPentestTool 抽象
│   │   │   └── adapters/
│   │   │       └── nmap.py    # ✅ Nmap 适配器
│   │   ├── static_analysis.py # [待实现]
│   │   ├── fuzzing.py         # [待实现]
│   │   ├── network_attack.py  # [待实现]
│   │   └── knowledge_base.py  # [待实现]
│   ├── orchestrator/          # [待实现] LangGraph 编排
│   │   ├── planner.py
│   │   ├── router.py
│   │   ├── verifier.py
│   │   ├── reporter.py
│   │   └── direct_audit.py    # LLM 直审模式
│   ├── plugins/               # ✅ 插件注册中心
│   │   ├── registry.py        # 发现/加载/调用
│   │   └── contracts/         # (使用 sdk/ 的契约)
│   ├── api/                   # [待实现] 额外 REST 端点
│   └── memory/                # [待实现] 对话/产物存储
│
├── frontend/                  # React + Vite + Tailwind
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js     # 品牌色: #e53834/#f7f8fa/#121419/#4b5563
│   ├── index.html
│   └── src/
│       ├── main.tsx           # 路由 + AuthProvider
│       ├── index.css
│       ├── pages/
│       │   ├── Login.tsx      # ✅ 登录页
│       │   └── Dashboard.tsx  # ✅ 主面板
│       ├── components/        # [待实现]
│       │   ├── ChatPanel.tsx
│       │   ├── AttackGraph.tsx
│       │   ├── StatusBoard.tsx
│       │   ├── ModelPicker.tsx
│       │   ├── ModeSelector.tsx
│       │   ├── KnowledgePanel.tsx
│       │   ├── ToolMarket.tsx
│       │   ├── TargetInput.tsx
│       │   └── AuthScope.tsx
│       └── api/
│           └── auth.tsx       # ✅ AuthContext + useAuth
│
├── engines/                   # 分析引擎 (M2 起实现)
│   ├── whitebox/              # 模块 A: SVF + CodeQL
│   │   ├── svf_wrapper/
│   │   ├── codeql_runner/
│   │   └── taint_tracker/
│   ├── blackbox/              # 模块 B: StateAFL + 状态机差分
│   │   ├── state_extractor/
│   │   ├── state_diff/
│   │   └── harness_synth/
│   ├── network/               # 模块 C: Off-Path
│   │   ├── model_builder/
│   │   ├── offpath/
│   │   └── exploit_gen/
│   ├── llm_direct/            # 模块 D: LLM 直审
│   │   ├── code_auditor.py
│   │   ├── protocol_auditor.py
│   │   └── config_auditor.py
│   └── unknown_detector/      # 模块 E: 0-Day 发现
│       ├── novelty_scorer.py
│       ├── poc_synthesizer.py
│       ├── sandbox_runner.py  # Firecracker
│       └── disclosure.py
│
├── knowledge_base/            # ✅ 协议栈漏洞知识库
│   ├── ingestion/
│   │   └── references_parser.py  # ✅ 解析 references.md 403 条目
│   ├── schema/
│   │   └── entry.py           # ✅ KnowledgeEntry + EntryType
│   ├── vectorstore/           # [待实现] Chroma/Qdrant 客户端
│   ├── retriever.py           # [待实现] BM25 + 向量混合检索
│   └── data/
│       └── references.md      # 源文件 (403 条文献)
│
├── sdk/                       # ✅ 插件开发 SDK
│   └── python/
│       └── pentest_agent_sdk/
│           ├── __init__.py
│           └── contracts.py   # ✅ EnginePlugin/ToolPlugin + Finding/Evidence
│
├── plugins/                   # 第三方插件 (用户扩展)
│   └── README.md              # [待实现] 插件开发指南
│
├── infra/
│   ├── install.sh             # ✅ 单机原生部署 (systemd)
│   ├── systemd/               # 由 install.sh 运行时生成
│   ├── config.yaml.example    # [待实现]
│   ├── docker-compose.yml     # [待实现] 可选 Docker
│   └── k8s/                   # [待实现] 可选 K8s
│
└── tests/                     # [待实现] 端到端 + 单元测试
```

---

## 4. 核心模块详细设计

### 4.1 用户认证 (backend/auth/) — ✅ 已实现

**数据模型** (`models.py`):
- `User`: id, username, password_hash, role, is_active, must_change_password, failed_attempts, locked_until, last_login
- `Role`: admin | operator | viewer

**核心流程**:
1. 首次启动后端检测无用户 → 生成随机 16 位强密码 → 控制台打印 → 创建 admin (`must_change_password=True`)
2. 登录: 校验密码 → 失败 5 次锁定 15 分钟 → 成功颁发 JWT 存入 HttpOnly Cookie (8h TTL)
3. 所有受保护 API 通过 `get_current_user` 依赖注入校验
4. RBAC: `require_role(Role.admin)` 作为依赖

**安全点**:
- bcrypt cost=12 加盐哈希
- 密码策略: 最少 8 位 + 大小写字母 + 数字 + 特殊字符
- JWT HS256，默认密钥从 `PA_JWT_SECRET` 环境变量读取 (install.sh 自动生成)
- Cookie 配置: HttpOnly + SameSite=Strict
- 登录失败错误不透露用户名是否存在

### 4.2 黑盒目标管理 (backend/targets/) — ✅ 已实现

**数据模型** (`models.py`):
- `Target`: id, type, value, owner_id, authorized, scope (JSON), auth (JSON), metadata
- `TargetType`: url | ip | domain | binary | pcap | protocol
- `AuthScope`: owner_id, hosts (glob 模式), cidrs

**解析器** (`parser.py`):
- 自动识别输入类型: URL (http/https 开头) / IP 或 CIDR / 自定义协议 (`tcp://...`) / host:port / 域名
- 支持 `type_hint` 强制类型 (用于二进制/pcap 文件上传)

**校验器** (`validator.py`):
- URL → 提取 hostname → 匹配 `allow_hosts` (支持 `*.example.com` 通配)
- IP/CIDR → 用 `ipaddress.subnet_of` 匹配 `allow_cidrs`
- 协议端点 → hostname 是 IP 则查 CIDRs, 否则查 hosts
- 空白名单 = 拒绝所有

**API 路由** (`routes.py`):
- `POST /targets` — 创建目标 (必须勾选 authorized=true)
- `PUT /targets/auth-scope` — 更新授权范围
- `GET /targets/auth-scope` — 查询授权范围

### 4.3 LLM 适配层 (backend/llm/) — ✅ 已实现

**统一 Protocol** (`base.py`):
```python
class LLMClient(Protocol):
    def chat(messages, *, max_tokens, temperature, tools) -> ChatResult
    def stream(messages, *, max_tokens, temperature) -> Iterator[str]
```

**模型注册表** (`registry.py`):
- `ModelSpec`: name, provider, context_window, capabilities, default_for, factory
- 预注册: claude-opus-4-7 / claude-sonnet-4-6 / claude-haiku-4-5-20251001 / gpt-4o
- 能力标签: reasoning / coding / tool_use / long_context / multimodal

**任务路由** (`router.py`):
- `_task_routes`: planning → [opus, gpt-4o], codegen → [sonnet, gpt-4o], triage → [haiku]
- `call(kind, messages, **kwargs)`: 依次尝试候选，失败自动 failover
- Token 使用记录到 `budget_tracker`

**适配器** (`adapters/`):
- `anthropic.py`: Claude SDK，system/user/assistant 消息分离
- `openai.py`: 兼容 endpoint (可指向 Azure/私有部署)
- 待实现: `google.py` (Gemini), `domestic.py` (文心/通义/豆包/Kimi), `local_vllm.py`, `local_ollama.py`

### 4.4 知识库 (knowledge_base/) — ✅ 部分实现

**数据模型** (`schema/entry.py`):
```python
@dataclass
class KnowledgeEntry:
    id: str                # "ref_021"
    title: str
    type: EntryType        # RFC/Paper/CVE/Report/Blog/Book/Tool
    category: str          # TCP/IP/DNS/BGP/TLS/WiFi/5G/...
    year: int | None
    url: str | None
    summary: str
    attack_surface: list[str]
    mitigations: list[str]
    cves: list[str]
    embedding: list[float]
```

**摄取** (`ingestion/references_parser.py`):
- 按章节 `## ` 分段 → 推断 category
- 逐条 `[N]` 解析 → 提取 year/URL/title/type
- 输出 KnowledgeEntry 流

**角色界定** (重要!):
- **不是"漏洞白名单"**，是**"专家参考书"**
- 漏洞发现由底层引擎独立完成，不依赖知识库
- 知识库只在 4 处起作用:
  1. 给 LLM 提供领域上下文
  2. 辅助引擎结果的解释与归类
  3. 直审模式的依据召回
  4. 报告中的引用追溯
- **未匹配知识库 ≠ 误报**，反而可能是 0-Day

**待实现**:
- `vectorstore/` — Chroma/Qdrant 嵌入式客户端
- `retriever.py` — BM25 + 向量混合检索 + 元数据过滤
- `ingestion/cve_fetcher.py` — NVD/Exploit-DB 增量拉取
- `ingestion/rfc_fetcher.py` — IETF datatracker 监听

### 4.5 插件系统 (backend/plugins/ + sdk/) — ✅ 已实现

**契约** (`sdk/python/pentest_agent_sdk/contracts.py`):
- `EnginePlugin` Protocol: name, version, capabilities, setup/run/health_check
- `ToolPlugin` Protocol: name, version, description, input_schema, invoke/health_check
- `Finding` schema: id, title, severity, category, target_ref, evidence, references, cwe, cve
- `Capability` 枚举: static_analysis / fuzzing / web_scan / port_scan / tls_audit / exploit / ...

**注册中心** (`backend/plugins/registry.py`):
- `discover_plugins(plugins_dir)`: 扫描 `plugin.toml` 清单 → 动态加载
- `register_engine` / `register_tool`: 注册到内存表
- 加载失败不影响主系统

**插件目录结构示例**:
```
plugins/my_plugin/
├── plugin.toml         # name="my-plugin", version="0.1.0", entry="main:register"
└── main.py             # 定义 register(host) -> None
```

**待实现**:
- 子进程隔离 (gRPC 或 subprocess)
- 权限声明与审批流程
- 官方插件市场 (HTTP 仓库 + signature 校验)

### 4.6 外部工具适配 (backend/tools/external_pentest/) — ✅ 部分实现

**抽象基类** (`base.py`):
- `ExternalPentestTool`: setup/run/health_check
- `ToolCapability`: name + description

**已实现适配器**:
- `nmap.py`: 子进程调用 + XML 解析，支持 port_scan/service_detect/os_fingerprint

**待实现适配器**:
- `burp.py` — Burp Suite REST API (Pro 版)
- `metasploit.py` — MSF RPC
- `zap.py` — OWASP ZAP REST API
- `sqlmap.py`
- `nikto.py`
- `testssl.py` / `sslyze.py`
- `tshark.py`

**统一 Finding 归一化** (待实现 `output_normalizer.py`):
- Nmap XML → Finding
- Burp XML → Finding
- MSF JSON → Finding

**安全门控** (待实现 `policies/`):
- `target_allowlist.py` — 强制授权白名单校验
- `rate_limiter.py` — 防止暴打目标
- `auth_manager.py` — API key 加密存储

---

## 5. 部署方案 (infra/) — ✅ 已实现

### 5.1 install.sh 主推方案

**流程**:
1. 检测 OS (Linux/macOS) + Python 3.11+ + Node.js 20+
2. 创建系统用户 `pentest-agent` (非 root)
3. 创建目录: `/opt/pentest-agent` (程序) / `/var/lib/pentest-agent` (数据) / `/etc/pentest-agent` (配置) / `/var/log/pentest-agent` (日志)
4. 安装 Python 依赖 (venv) + 构建前端
5. 生成 JWT 密钥 `openssl rand -hex 32` 写入 `/etc/pentest-agent/config.yaml`
6. 安装 systemd 服务 `pentest-agent.service` → enable + start
7. 首次启动打印 admin 初始密码

### 5.2 单二进制包 (待实现)
- PyInstaller / shiv 打包后端
- Vite build 前端 → 嵌入后端 `/static/`
- 产物 `pentest-agent-linux-x64` (约 200MB)

### 5.3 Docker 可选 (待实现)
- `infra/docker-compose.yml` — 面向已有容器平台的企业

### 5.4 依赖最小化策略
- 数据库: SQLite (默认) → PostgreSQL (生产可切)
- 向量库: Chroma 嵌入式 → Qdrant (生产可切)
- 对象存储: 本地文件系统 → MinIO
- 消息队列: asyncio 进程内 → Redis

---

## 6. 待实现清单 (M2+)

### 6.1 M2 (T+2mo) 优先级
- [ ] **Orchestrator 骨架** — LangGraph 状态机: Planner → Router → Verifier → Reporter
- [ ] **LLM 直审模式** — `engines/llm_direct/` 三子模式 + 前端 ModeSelector
- [ ] **知识库向量检索** — Chroma 集成 + BM25 混合检索 + Tool 封装
- [ ] **更多前端组件** — ChatPanel/AttackGraph/ModelPicker/ToolMarket/TargetInput/KnowledgePanel
- [ ] **首发 2 个插件** — Semgrep + Nuclei
- [ ] **Unknown Detector 骨架** — 新颖性评分
- [ ] **Burp + Nmap 外部工具** — Burp Suite REST 适配
- [ ] **国产模型适配器** — 文心/通义/豆包 + 本地 vLLM/Ollama

### 6.2 M3 (T+3mo) 核心引擎
- [ ] **SVF Wrapper** (`engines/whitebox/svf_wrapper/`) — C/C++ 指针分析与污点追踪
- [ ] **CodeQL Runner** (`engines/whitebox/codeql_runner/`) — Java/Python/Go/JS 多语言
- [ ] **StateAFL 集成** (`engines/blackbox/`) — 协议 Fuzz + 状态机差分
- [ ] **Off-Path 模块** (`engines/network/offpath/`) — TCP 序列号预测 + eBPF 观测
- [ ] **PoC 自动合成** + **Firecracker 沙箱验证**
- [ ] **端到端闭环 Demo** — Juliet Test Suite + top-10 CVE 复现

### 6.3 M6 (T+6mo) 生产化
- [ ] 误报率 ≤15% (首轮)
- [ ] 首个 0-Day 独立发现 + 责任披露
- [ ] 插件市场 4+ 官方插件
- [ ] 多模型路由 + 预算管控 + 故障转移生产级稳定
- [ ] 首个试点客户签约

---

## 7. 关键技术决策记录

### 7.1 为什么不用 Docker 作为主部署方式?
**用户明确要求**: "部署和安全方式简单，不必依赖docker环境"。
走 systemd 原生 → 更贴近企业传统运维习惯，也避免 Docker in Linux 的权限复杂性。Docker 保留为可选。

### 7.2 为什么 SQLite 而不是 PostgreSQL?
MVP 追求零依赖。SQLite 在单机 + 小规模场景下性能足够 (支持千级并发读)。设计上通过 SQLModel 抽象，切 PostgreSQL 只需改 engine URL。

### 7.3 为什么 Chroma 嵌入式而不是 Qdrant?
部署简化。Chroma 可作为 Python 进程内库，无独立服务。生产场景再切 Qdrant。

### 7.4 为什么 LLM 不做漏洞判定?
- LLM 幻觉不可控
- "95% 误报压缩"只能靠引擎交叉验证
- LLM 负责编排/合成/triage 是成熟可控的范式

### 7.5 为什么协议栈知识库不是"漏洞白名单"?
用户主动澄清: RAG 不应限制产品挖掘规定漏洞。
设计上:
- 底层引擎 (SVF/StateAFL/Off-Path) 独立工作，不依赖知识库
- 未匹配知识库的发现 = "未知模式"，反而是 0-Day 候选
- 知识库只用于**辅助解释、召回上下文、报告引用**

### 7.6 误报率目标从 95% 压缩放宽到 ≤15%
**用户确认放宽**。工程可实现性 > 营销口径。
分级输出策略:
- 高可信: ≥2 引擎验证 + PoC 触发
- 中可信: 单引擎 + LLM 确认
- 低可信: 入"待确认队列"不默认展示

### 7.7 认证为什么不用 OAuth2/OIDC?
M1 简化: 用户明确要求 "USER+PWD 认证"。
OIDC/LDAP 放入 v2+ 扩展能力。

---

## 8. 已知风险与兜底

| 风险 | 兜底 |
|---|---|
| SVF 对超大项目内存爆炸 | 分模块分析 + 摘要抽象 |
| LLM 幻觉生成无效 PoC | Verifier 节点强制实际执行验证 |
| 状态机差分找不到对照实现 | 回退到单实现 + 协议规范对比 |
| eBPF 内核版本不兼容 | 提供 Kprobe 兜底 |
| 大模型 API 中断 | 本地 Qwen3/DeepSeek V4 备用 |
| 插件崩溃影响主系统 | 子进程隔离 (gRPC) |
| 目标授权误扫生产 | 强制白名单校验 + 审计日志 + 速率限制 |

---

## 9. 验证方法

### 9.1 端到端验证 (从 M1 逐步扩充)
1. ✅ **一条命令安装**: `bash infra/install.sh`
2. ✅ **认证**: 浏览器访问 → 自动跳转登录页 → admin 初始密码 → 强制改密
3. [M2] **知识库**: GUI 搜索 "TCP sequence number prediction" → 召回 RFC 793 + Morris 1985
4. ✅ **目标输入**: POST /targets + 授权范围校验
5. [M2] **LLM 直审**: 粘贴 nginx TLS 配置 → 输出加固建议
6. [M3] **引擎模式**: 上传 Juliet → prompt 找漏洞 → 证据图展示污点路径
7. [M2] **插件**: 安装 Semgrep 插件 → 跑同一项目 → 交叉验证
8. [M3] **0-Day 发现**: 埋入已知 0-Day → 新颖性高 + PoC 合成 + 沙箱验证
9. [M2] **外部工具**: GUI ToolMarket 安装 Burp → 授权目标 → LLM 调用 Burp
10. ✅ **模型选配** (接口已在): 配置 Claude + DeepSeek → 关闭 Claude key → failover
11. ✅ **RBAC**: viewer 登录 → 不能发起任务
12. [M3+] **基准**: 召回率 ≥80%, 误报率 ≤15%

### 9.2 单元验证
- SVF wrapper: Juliet Test Suite
- 状态机差分: OpenSSL vs BoringSSL TLS 差异
- Off-Path: TCP 序列号预测复现
- Orchestrator: mock LLM 下状态转移
- 知识库检索: MRR@10, Recall@5
- 插件加载: 加载/卸载/崩溃隔离

### 9.3 性能目标
- 10 万行 C 代码扫描 ≤ 30 min
- LLM token 成本 ≤ $5/次
- 内存峰值 ≤ 16 GB
- 知识库检索 P95 < 200ms
- 最小硬件: 4 核 / 8 GB / 50 GB

---

## 10. 参考资料索引

本地文件:
- `/home/claude/Attack/penetrate.pptx` — 产品方案 PPT (4 页)
- `/home/claude/Attack/references.md` — 403 条协议栈安全文献
- `/home/claude/Attack/高精度指针分析与数据流追踪.pdf` — SVF 引擎技术基础
- `/home/claude/Attack/状态机差分.pdf` — 状态机差分 Fuzz 技术基础
- `/home/claude/Attack/参考界面.png` — 前端配色参考
- `/root/.claude/plans/ppt-jiggly-cloud.md` — 完整实施计划 (含战略改进建议)
