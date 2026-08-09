# 元星刃 Community · AI 漏洞挖掘平台

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![Node](https://img.shields.io/badge/node-20+-green.svg)](https://nodejs.org)

元星刃 Community（社区版）是由元序星核研发的智能化漏洞挖掘平台开源版本。**Supervisor 编排框架** 自动分析项目特征，动态调度 8 个专项分析引擎对源代码进行多维度安全审计，三层去重 + LLM 置信裁判输出高价值漏洞发现。

## ✨ 为什么选择元星刃

传统的 SAST 工具基于规则匹配，误报率高、覆盖维度单一。元星刃将 LLM 的语义理解能力与 Agent 专业化结合：

- 🧠 **Supervisor 智能调度** — 不是人工选择扫描器，而是 Supervisor 分析项目信号（文件类型、代码模式、配置特征），自动决策哪些引擎出战，每个引擎聚焦一个安全领域
- 🔗 **三层去重** — 跨文件位置、漏洞类型、语义相似度去重，大幅降低误报
- 🎯 **二次深挖** — 首轮发现后自动 spawn 第二轮专项分析，深入验证
- 🔍 **渗透测试** — 集成 ZAP + Nmap，支持 URL/IP/域名主动扫描，实时进度 + 漏洞关联
- 📚 **CWE 知识库** — 内置通用漏洞模式索引，辅助引擎定位风险代码

### 社区版 vs 完整版

| 功能 | 社区版 | 完整版 |
|------|:----:|:----:|
| Supervisor 编排框架 | ✅ | ✅ |
| 专项分析引擎 | **8 个** | **26 个** |
| 三层去重 + 置信裁判 | ✅ | ✅ |
| 渗透测试 (ZAP + Nmap) | ✅ | ✅ |
| AI 对话分析 | ✅ | ✅ |
| CWE 知识库 | ✅ | ✅ |
| 授权范围管理 | ✅ | ✅ |
| RBAC 用户管理 | ❌ | ✅ |
| 合规溯源 (ScanOSS) | ❌ | ✅ |
| 审计日志 & 计费 | ❌ | ✅ |
| 0-Day 闭环 (PoC + 沙箱) | ❌ | ✅ |

## 🚀 快速开始

### 前置条件

- Python 3.12+
- Node.js 20+
- OWASP ZAP（可选，Web 扫描）
- Nmap（可选，网络扫描）

### 1. 克隆代码

```bash
git clone https://github.com/metaordo/yuanxingren-community.git
cd yuanxingren-community
```

### 2. 配置环境

```bash
cp .env.example .env
# 编辑 .env，填入 DeepSeek API Key（必填）
# 生成 JWT 密钥：bash scripts/generate-secret.sh
```

### 3. 启动后端

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### 4. 启动前端

```bash
cd frontend
npm install
npm run dev
```

访问 `http://localhost:5173`，使用控制台打印的初始 admin 密码登录。

## 🤖 专项分析引擎

社区版内置 8 个分析引擎 + 2 个元引擎，由 Supervisor 根据项目特征自动调度：

| 引擎 | 分析领域 | 触发信号 |
|------|---------|---------|
| 代码审计引擎 | 通用代码缺陷、CWE 模式匹配、危险函数调用 | `.c/.h/.py/.java` 等源码文件 |
| 数据流分析引擎 | 污点追踪、变量流向、source-sink 路径 | 源码 + 用户输入入口 |
| Web 侦察引擎 | Web 入口点发现、目录结构、框架指纹 | `.html/.js/.tsx/.php` |
| Web 安全引擎 #1 | XSS 跨站脚本（存储/反射/DOM） | Web 模板 + 用户输入渲染 |
| Web 安全引擎 #2 | SQL 注入（联合查询/盲注/二次注入） | 数据库操作 + 外部参数 |
| 认证分析引擎 | 认证逻辑缺陷、会话管理、权限绕过 | JWT/OAuth/登录/注册代码 |
| 依赖分析引擎 | 第三方库版本风险、CVE 关联 | `package.json/requirements.txt/pom.xml` |
| 配置扫描引擎 | 密钥硬编码、配置缺陷、不安全默认值 | `.env/.conf/.yaml/config.*` |

### 元引擎

| 引擎 | 作用 |
|------|------|
| 质量复核引擎 (Verifier-Reviewer) | 对所有引擎产出进行置信度评估，判 `keep/lower/dismiss` |
| 报告汇总引擎 (Reporter-Writer) | 聚合最终结果，生成结构化报告 |

### 调度流程

```
用户提交源码项目
       ↓
Supervisor 扫描文件信号（ext/keyword/config）
       ↓
LLM 决策：选择 N 个相关引擎 + 文件分配
       ↓
引擎并行执行 → 产出 findings JSON
       ↓
Verifier-Reviewer 复核（keep/lower/dismiss）
       ↓
三层去重（位置/类型/语义）
       ↓
二次 spawn 深挖（有信号时）
       ↓
Reporter-Writer 汇总 → 最终报告
```

## 🏗️ 技术架构

```
┌─────────────────────────────────────────────┐
│  前端 React SPA                             │
│  对话 / 渗透测试 / 漏洞挖掘 / 知识库 / 设置    │
└──────────────────┬──────────────────────────┘
                   │ WebSocket + REST
┌──────────────────▼──────────────────────────┐
│  FastAPI 后端                                │
│  Auth (JWT) · Targets · Uploads · LLM Router│
└──┬───────────┬────────────┬─────────────────┘
   │           │            │
┌──▼──┐  ┌────▼─────┐  ┌──▼──────────────┐
│LLM   │  │Agent 编排 │  │External Tools   │
│OpenAI│  │Supervisor │  │ZAP · Nmap · …   │
│Compat│  │8+2 Agent  │  │                 │
└─────┘  └───────────┘  └─────────────────┘
```

| 层 | 技术 |
|---|---|
| 前端 | React 18 + Vite + Tailwind CSS |
| 后端 | FastAPI + SQLModel + SQLite |
| 认证 | JWT + bcrypt + HttpOnly Cookie |
| LLM | OpenAI 兼容协议（DeepSeek/通义/GLM/本地 vLLM/Ollama） |
| 部署 | systemd / Docker Compose |

## 🎬 使用场景

| 场景 | 怎么用 |
|------|--------|
| **代码审计** | 上传开源项目源码 → 漏洞挖掘，自动发现 SQL 注入/XSS/硬编码密钥等 |
| **渗透测试** | 创建 URL/IP 目标 → 渗透测试 Tab 发起主动扫描 → 导出 PDF 报告 |
| **学习研究** | 上传 CVE 相关项目 → AI 对话模式自由提问，探索漏洞原理 |
| **CI/CD 集成** | REST API + API Key，可在流水线中自动触发安全审计 |
| **开源合规** | 社区版不含此功能，完整版提供 ScanOSS 溯源审计 |

## 🔧 LLM 配置

编辑 `.env`：

```bash
OPENAI_API_KEY=sk-your-deepseek-key
OPENAI_BASE_URL=https://api.deepseek.com/v1
```

### 支持的模型

| 厂商 | base_url |
|------|----------|
| **DeepSeek** | `https://api.deepseek.com/v1` |
| **通义千问** | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| **智谱 GLM** | `https://open.bigmodel.cn/api/paas/v4` |
| **Moonshot Kimi** | `https://api.moonshot.cn/v1` |
| **本地 vLLM** | `http://localhost:8000/v1` |
| **本地 Ollama** | `http://localhost:11434/v1` |

在 GUI 的 **设置 → 模型管理** 面板中可以添加自定义模型和配置路由。

## 🎯 授权范围管理

防止误扫非授权目标的安全护栏：
- **Host 匹配** — `*.example.com` 通配
- **CIDR 匹配** — `10.0.0.0/24` 网段
- 外部工具调用前强制校验
- 每位用户独立授权范围

## 📁 目录结构

```
yuanxingren-community/
├── backend/              # FastAPI 后端
│   ├── agents/           # Supervisor + 8 Agent 定义
│   ├── api/              # REST + WebSocket 端点
│   ├── auth/             # JWT 认证
│   ├── llm/              # LLM 适配层（OpenAI 兼容）
│   ├── targets/          # 目标管理 + 授权校验
│   └── tools/            # ZAP / Nmap 适配器
├── frontend/             # React SPA
│   └── src/
│       ├── pages/        # Login / Dashboard
│       └── components/   # UI 组件库
├── engines/              # 分析引擎（SVF / StateAFL / 网络攻击）
├── knowledge_base/       # CWE 漏洞知识库
├── tests/                # 228 单测
├── scripts/              # 辅助脚本
├── docker-compose.yml    # 一键部署
├── .env.example          # 环境变量模板
└── CONTRIBUTING.md       # 贡献指南
```

## 📦 Docker 部署

```bash
# 启动（含 ZAP daemon）
docker compose up -d

# 首次登录
# 查看容器日志获取初始 admin 密码
docker compose logs app | grep "password"
```

## 📸 功能截图

元星刃 Community 提供完整的 Web GUI，以下是主要功能模块：

| Tab | 功能描述 |
|-----|---------|
| **对话** | 交互式 AI 安全分析，上传源码后自然语言提问，LLM 结合知识库实时推理 |
| **渗透测试** | 对 URL/IP/域名发起主动扫描，ZAP 爬虫 + Nmap 端口发现，站点爬取进度 + 漏洞扫描进度双轨展示 |
| **漏洞挖掘** | 核心功能：上传源码项目 → Supervisor 自动调度引擎 → WebSocket 实时展示每个 Agent 运行状态 → 报告 |
| **知识库** | 内置 CWE 漏洞模式索引，支持 BM25 语义检索 |
| **设置** | 目标管理 / 授权范围 / 模型管理 / 目标创建 |

### 漏洞挖掘工作流

1. **创建目标** — 在「设置 → 目标配置」上传源码项目（`.zip` / `.tar.gz`）
2. **配置授权范围** — 在「设置 → 授权范围」声明授权测试的主机/CIDR（渗透测试用）
3. **启动分析** — 在「漏洞挖掘」Tab 选择目标，点击开始
4. **观察进度** — WebSocket 实时推送每个引擎状态（pending → running → done），Supervisor 决策面板展示引擎选取理由
5. **查看报告** — 最终报告聚合所有引擎发现，三层去重 + 置信评分

## 🙋 常见问题

**Q: 社区版可以用于生产环境吗？**  
A: 可以。MIT 许可证允许商业使用。8 个引擎覆盖最常见的漏洞类型，适合中小项目的日常安全审计。

**Q: 为什么我的扫描结果很少？**  
A: 检查几点：(1) 源码项目类型是否匹配引擎触发信号；(2) LLM API 是否正常（查看后端日志）；(3) 项目规模太小可能不触发所有引擎。

**Q: 如何添加自定义分析引擎？**  
A: 参见 [CONTRIBUTING.md](CONTRIBUTING.md)，核心步骤：定义 `system_prompt` → 注册 `AgentSpec` → 添加信号检测 → 调度规则。

**Q: ZAP/Nmap 扫描需要额外配置吗？**  
A: ZAP 需要本地运行 ZAP daemon（`docker compose` 已集成），Nmap 需要安装 `nmap` 二进制。

**Q: 支持哪些 LLM？**  
A: 所有兼容 OpenAI Chat Completions API 的模型，包括 DeepSeek、通义千问、GLM、Kimi，以及本地部署的 vLLM/Ollama。

## 🔐 隐私与安全

- **零数据外泄** — 代码分析在本地完成，源码不会发送到元星刃服务器
- **LLM API 直连** — 仅将代码片段发给用户配置的 LLM API，不经过第三方网关
- **无遥测** — 社区版不包含任何数据收集或回传机制
- **授权门控** — 渗透测试目标强制校验授权范围，防止误扫

## 🧪 测试

```bash
# 运行全部 228 单测
python3 -m pytest tests/unit/ -v

# 运行特定模块
python3 -m pytest tests/unit/test_nmap_adapter.py -v
python3 -m pytest tests/unit/test_cve_index.py -v
```

## 🤝 贡献

欢迎贡献新的分析引擎、检测规则或 bug 修复。

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feat/my-agent`)
3. 在 `backend/agents/roles.py` 注册新 Agent → 在 `supervisor.py` 添加调度规则
4. 提交 PR

详见 [CONTRIBUTING.md](CONTRIBUTING.md)

## 📄 许可证

[MIT License](LICENSE)

## 🔗 完整版

元星刃完整版提供 **26 个专项分析引擎**，覆盖：

协议分析 · 侧信道检测 · 路由安全 (BGP/OSPF/IS-IS) · 内核驱动 · 固件审计 · 内存安全 · 加密审计 · Android 安全 · API 安全 · 业务逻辑漏洞 · 供应链深度审计 · 0-Day 闭环

+ 企业功能：RBAC · 合规溯源 (ScanOSS) · 审计日志 · Token 计费 · 0-Day PoC 验证

访问 **https://pentest-agent.online** 了解更多。

---

<p align="center">Made with ❤️ by the 元星刃 Team</p>
