# 贡献指南

欢迎贡献新的分析引擎！

## 添加新 Agent

1. 在 `backend/agents/roles.py` 的 `ROLES` 列表中添加 `AgentSpec`
2. 定义 `system_prompt`，描述该引擎的分析领域和目标
3. 在 `backend/agents/supervisor.py` 中添加信号检测逻辑
4. 在 `_SUPERVISOR_SYSTEM` prompt 中注册调度规则
5. 提交 PR

## Agent 规范

- 每个 agent 输出 JSON 格式：`[{"finding": "...", "evidence": "...", "rationale": "..."}]`
- 必须包含 `allowed_tools` 定义
- 需添加对应的 precondition 和 filler 规则
